"""`orion scan <repo>` end to end: build the graph, discover leads, verify them, report.

    orion scan ./NodeGoat                  # build the graph, then discover + verify + report
    orion scan --scan-id <id>               # skip the build, run against an existing scan graph
    orion scan ./NodeGoat --watch           # follow live progress while the scan runs
    orion scan ./NodeGoat --json out.json   # also write the verdicts as JSON
    orion scan ./NodeGoat --quiet           # suppress per-event prints (still logs to file)
    orion scan ./NodeGoat --engine lm --model <path>   # in-process Orion-LM discovery, no claude

Discovery and verification are two SEPARATE `claude -p` sessions (see the design doc) fanned out
and joined here; this module owns only the wiring -- build -> index -> discover -> verify ->
report -- and the run's progress log.

`--engine lm` (default: `claude`) swaps discovery for the in-process Orion-LM engine
(`orion/lm/engine.py`, MLX-LM; never `claude_cli`) and SKIPS the verifier: every lead is reported
as INCONCLUSIVE "unverified (engine=lm)". The lm sink profile (`profiles.with_lm_sinks`) is applied
at BUILD time so the graph carries the extra CandidateFlows; with `--scan-id` the existing graph is
used as-is. Nothing on the claude path changes.

graph_build / embed / discover / verify pull in the Neo4j driver, the local embedding model, and
the `claude` CLI subprocess wrapper. Those are imported LAZILY inside `_run_scan`, not at module
scope, so `orion --help` and `import orion.cli` stay cheap and don't fail merely because one of
those modules is mid-edit elsewhere.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import sys
import threading
import time
from pathlib import Path


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _event(phase: str, event: str, *, shape=None, lead=None, turn=None, detail: str = "") -> dict:
    """Build one ProgressEvent dict (see contracts.ProgressEvent for the key contract)."""
    return {
        "ts": _now(),
        "phase": phase,
        "shape": shape,
        "lead": lead,
        "turn": turn,
        "event": event,
        "detail": detail,
    }


def _run_dir(scan_id: str) -> str:
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = Path(".orion") / "runs" / scan_id / ts
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def _load_lm_model(path: str):
    """Load the Orion-LM model wrapper for `path` (MLX-LM, llama-cpp fallback). A seam: tests replace
    it, and the MLX import stays inside the lm branch -- `orion.lm.model`'s top level is stdlib-only."""
    from .lm import model as lm_model
    return lm_model.load(path)


def _run_scan(args: argparse.Namespace) -> int:
    # Cheap arg validation BEFORE the heavy lazy imports below, so a typo'd path fails instantly
    # instead of after loading the embedding model / Neo4j driver.
    if not args.scan_id and not args.repo:
        print("orion scan: provide a repo path or --scan-id", file=sys.stderr)
        return 2
    # A missing repo path must fail here with a clear message -- otherwise it reaches joern-parse,
    # which dies with a Java AssertionError stack trace ("Input path does not exist") that reads like
    # an Orion crash. This also catches the aftermath of a failed `git clone` (empty/absent dir).
    if args.repo and not Path(args.repo).is_dir():
        print(f"orion scan: repo path not found or not a directory: {args.repo}", file=sys.stderr)
        return 2
    lm_engine = getattr(args, "engine", "claude") == "lm"
    # There is no default model path: `--engine lm` without `--model` is a usage error, not a crash
    # deep inside the pipeline after the graph has been built.
    if lm_engine and not args.lm_model:
        print("orion scan: --engine lm needs --model <path to the Orion-LM model>", file=sys.stderr)
        return 2
    # The repo path is the engine's `read_code` sandbox. Without it the only fallback would be the
    # CWD -- Orion's own checkout (CLAUDE.md, eval/, answer keys) -- which must never be what the
    # model reads. So unlike the claude path, --scan-id alone is not enough here.
    if lm_engine and not args.repo:
        print("orion scan: --engine lm needs the repo path for read_code even with --scan-id", file=sys.stderr)
        return 2

    # Deferred on purpose -- see module docstring.
    from . import config, discover, embed, graph_build, graphdb, report, verify
    from .monitor import run_logger, tail

    # The lm sink profile must be in the graph, so it is chosen BEFORE the build and handed to
    # graph_build.build(profile=). select_profile ignores the language today (it only keys on
    # package.json/express), so passing none here mirrors the discovery-profile pick below; build
    # resolves the Joern frontend itself and would select the same base profile.
    lm_profile = None
    if lm_engine and args.repo:
        from .graph import profiles
        lm_profile = profiles.with_lm_sinks(profiles.select_profile(args.repo))

    needs_build = not args.scan_id
    # The lm profile changes the CandidateFlows, so its graph gets its own scan_id (scan_id_for adds
    # the profile name); the claude path calls scan_id_for exactly as before.
    scan_id_kwargs = {"profile": lm_profile} if lm_profile is not None else {}
    scan_id = args.scan_id or graph_build.scan_id_for(args.repo, **scan_id_kwargs)
    run_dir = _run_dir(scan_id)

    # In --watch mode the foreground `tail` is the one rendering progress (reading the same
    # JSONL), so the background pipeline's own logger stays quiet to avoid printing every event
    # twice. Otherwise the logger prints directly unless the caller asked for --quiet.
    on_event = run_logger(run_dir, quiet=True if args.watch else args.quiet)

    print(f"scan_id: {scan_id}")
    print(f"run log: {run_dir}/progress.jsonl")

    def _index_semantic(batch=None) -> None:
        # Best-effort semantic index. When `batch` is given it runs CONCURRENTLY with persist (item
        # 4, via build's on_batch hook) reading spans from the in-memory batch; otherwise it reads
        # the already-persisted graph (the --scan-id path). Embedding is never fatal to a scan.
        concurrent = batch is not None
        on_event(_event("build", "start", detail="indexing semantic embeddings"
                        + (" (concurrent with persist)" if concurrent else "")))
        try:
            embed.index(args.repo, scan_id, batch=batch)
            on_event(_event("build", "done", detail="semantic index complete"))
        except Exception as exc:  # noqa: BLE001 -- embedding is best-effort, never fatal
            on_event(_event(
                "build", "error",
                detail=f"semantic index failed, continuing graph-only: {exc}",
            ))

    if needs_build:
        on_event(_event("build", "start", detail=f"building graph for {args.repo}"))
        # Overlap the semantic index with persist: build runs _index_semantic(batch) concurrently
        # with the persist write (item 4), so the two independent costs no longer serialize.
        # The claude path passes no `profile` (build auto-selects, exactly as before); the lm path
        # pins the extended-sink profile so pathfind emits the extra CandidateFlows.
        build_kwargs = {"profile": lm_profile} if lm_profile is not None else {}
        if lm_profile is not None:
            on_event(_event("build", "start", detail=f"lm sink profile {lm_profile.name} applied to the build"))
        graph_build.build(args.repo, args.language, on_event,
                          stream=args.stream, queue_size=args.queue_size,
                          on_batch=_index_semantic, **build_kwargs)
        on_event(_event("build", "done", detail="graph build complete"))
    else:
        on_event(_event("build", "done", detail=f"using existing scan_id {scan_id}"))
        if args.repo:
            _index_semantic()   # --scan-id path: read spans from the already-persisted graph
        if lm_engine:
            on_event(_event("discover", "warn",
                            detail=f"--scan-id: existing graph {scan_id} used as-is (built without the lm "
                                   "sink profile; rebuild with `orion scan <repo> --engine lm` to add its flows)"))

    # Best-effort: ensure the GLOBAL exploit-reference corpus is indexed (once) so the verifier's
    # exploit_search tool works. Builds ONLY if the metadata file is present locally -- never
    # downloads mid-scan, never fatal. Run `orion index-exploits` to fetch + build it explicitly.
    try:
        if embed.ensure_exploit_index():
            on_event(_event("build", "done", detail="exploit-reference corpus ready"))
        else:
            on_event(_event("build", "done",
                            detail="exploit corpus not indexed (run `orion index-exploits` to enable)"))
    except Exception as exc:  # noqa: BLE001 -- corpus is advisory; never break a scan over it
        on_event(_event("build", "error", detail=f"exploit corpus index skipped: {exc}"))

    # fp-check (the verifier's source-reading step) sandboxes to this path via --add-dir; fall
    # back to "." when only --scan-id was given and no repo checkout is known.
    repo_for_verify = args.repo or "."

    # Per-stack prompt vocabulary when we know the repo; None keeps the agnostic default prompt.
    profile = None
    if args.repo:
        from .graph import profiles
        profile = profiles.select_profile(args.repo)
    if lm_profile is not None:
        profile = lm_profile   # the same object the graph was built with

    # Opt-in runtime enrichment (--runtime): EXECUTE the target and fold observed coverage back into
    # the graph before discovery reads it. Best-effort by contract -- a failure is an event, never an
    # abort, and it only ADDS props/edges (never touches NODE_KEY labels), so the static graph and its
    # FLOWS_TO parity are untouched. Needs a repo checkout to boot/build; skipped on --scan-id only.
    if getattr(args, "runtime", False):
        if args.repo:
            from . import runtime
            runtime.enrich(scan_id, args.repo, profile, on_event, budget=args.runtime_budget)
        else:
            on_event(_event("runtime", "warn",
                            detail="--runtime needs a repo checkout to execute; skipped on --scan-id"))

    def _pipeline():
        # Size the per-shape discovery timeout to the graph: a bigger graph is a bigger search space
        # and needs longer sweeps (see config.discover_timeout). Sizing is best-effort -- if the
        # count query fails we fall back to the reality-based floor, never abort the scan.
        node_count = 0
        try:
            db = graphdb.GraphDB()
            try:
                node_count = db.node_count(scan_id)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001 -- best-effort sizing; the floor is a safe default
            on_event(_event("discover", "warn",
                            detail=f"graph node count unavailable, using base discovery timeout: {exc}"))
        if lm_engine:
            return _pipeline_lm(node_count)
        d_timeout = config.discover_timeout(node_count)
        on_event(_event("discover", "start",
                        detail=f"discovery fleet starting ({node_count} nodes, per-shape timeout {d_timeout}s)"))
        leads = discover.discover(scan_id, on_event, profile, timeout=d_timeout)
        on_event(_event("discover", "done", detail=f"{len(leads)} candidate leads"))

        on_event(_event("verify", "start", detail=f"verifying {len(leads)} leads"))
        verdicts = verify.verify_all(scan_id, leads, repo_for_verify, on_event)
        on_event(_event("verify", "done", detail=f"{len(verdicts)} verdicts"))
        return verdicts

    def _pipeline_lm(node_count: int):
        # The in-process Orion-LM engine: one local model, no `claude -p`, no verifier. The model is
        # loaded HERE -- after the build -- so Joern and the model are never resident together
        # (16 GB machine). MLX is imported lazily by _load_lm_model; `orion.lm.engine` itself is
        # stdlib + graphdb only.
        from .contracts import Verdict
        from .lm import engine as lm_engine_mod

        on_event(_event("discover", "start",
                        detail=f"Orion-LM discovery starting ({node_count} nodes, engine=lm, "
                               f"loading model {args.lm_model})"))
        model = _load_lm_model(args.lm_model)
        # args.repo, never the "." fallback: it is the read_code sandbox (guarded in pre-flight).
        leads = lm_engine_mod.discover_lm(scan_id, args.repo, on_event, profile=profile, model=model)
        on_event(_event("discover", "done", detail=f"{len(leads)} candidate leads"))

        # No independent verifier on this engine (yet): say so loudly and report every lead as
        # INCONCLUSIVE rather than inventing a CONFIRM. `report._ORDER` ranks INCONCLUSIVE, so the
        # report and --json work unchanged.
        on_event(_event("verify", "done", detail="skipped (engine=lm)"))
        return [Verdict(lead, "INCONCLUSIVE", "unverified (engine=lm)") for lead in leads]

    if args.watch:
        stop = threading.Event()
        result: dict = {}

        def _worker() -> None:
            try:
                result["verdicts"] = _pipeline()
            except Exception as exc:  # noqa: BLE001 -- surface, don't swallow
                result["error"] = exc
            finally:
                stop.set()

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        try:
            tail(run_dir, stop)
        except KeyboardInterrupt:
            stop.set()
        thread.join()
        if "error" in result:
            raise result["error"]
        verdicts = result.get("verdicts", [])
    else:
        verdicts = _pipeline()

    on_event(_event("report", "start", detail=f"rendering {len(verdicts)} verdicts"))
    text = report.render(verdicts)
    on_event(_event("report", "done", detail="report rendered"))

    print("\n" + "=" * 70)
    print(text)

    if args.json:
        payload = [dataclasses.asdict(v) for v in verdicts]
        Path(args.json).write_text(json.dumps(payload, indent=2, default=str))
        print(f"\nwrote {len(payload)} verdicts to {args.json}")

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="orion")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a repo (or an existing scan graph) for candidate leads")
    scan.add_argument("repo", nargs="?", help="path to the repo to build a graph for")
    scan.add_argument("--scan-id", dest="scan_id", help="use an existing scan graph instead of building one")
    scan.add_argument("--watch", action="store_true", help="follow live progress while the scan runs")
    scan.add_argument("--json", dest="json", metavar="OUT", help="also write verdicts as JSON to OUT")
    scan.add_argument("--quiet", action="store_true", help="suppress per-event progress prints (still logs to file)")
    scan.add_argument("--language", dest="language", metavar="FRONTEND",
                      help="Joern frontend id (jssrc/pythonsrc/golang/javasrc); overrides repo auto-detection")
    scan.add_argument("--stream", dest="stream", action="store_true",
                      help="use the streaming per-function build (avoids the 85x export blob)")
    scan.add_argument("--no-stream", dest="stream", action="store_false")
    scan.set_defaults(stream=True)
    scan.add_argument("--queue-size", dest="queue_size", type=int, default=64,
                      help="functions held in flight by the streaming build (default 64)")
    scan.add_argument("--runtime", action="store_true",
                      help="EXECUTES the target: after the static build, boot/build and drive it to "
                           "enrich the graph with observed coverage (executed/hit_count + OBSERVED_CALL). "
                           "Off by default; runs on the host.")
    scan.add_argument("--runtime-budget", dest="runtime_budget", type=int, default=200,
                      help="max inputs the runtime fuzz loop drives (default 200)")
    scan.add_argument("--engine", choices=["claude", "lm"], default="claude",
                      help="discovery engine: `claude` (default; `claude -p` fleet + verifier) or `lm` "
                           "(in-process Orion-LM model via --model; verifier skipped, leads reported "
                           "INCONCLUSIVE)")
    scan.add_argument("--model", dest="lm_model", metavar="PATH",
                      help="path to the Orion-LM model (engine=lm)")

    idx = sub.add_parser("index-exploits",
                         help="build/refresh the global Metasploit exploit-reference corpus (one-time)")
    idx.add_argument("--refresh", action="store_true",
                     help="re-download the Metasploit metadata index before building")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "scan":
        return _run_scan(args)
    if args.cmd == "index-exploits":
        return _run_index_exploits(args)
    return 0


def _run_index_exploits(args: argparse.Namespace) -> int:
    """Fetch (if missing/--refresh) and index the global exploit-reference corpus."""
    from . import embed, exploit_corpus

    path = exploit_corpus.DEFAULT_METADATA_PATH
    if args.refresh or not Path(path).exists():
        print(f"fetching Metasploit metadata index -> {path}")
        exploit_corpus.fetch_metadata(path)
    print("indexing exploit-reference corpus (embedding a few thousand modules, one-time)...")
    n = embed.index_exploits(path)
    print(f"indexed {n} exploit-reference documents into the '{embed.EXPLOIT_LABEL}' corpus")
    return 0


if __name__ == "__main__":
    sys.exit(main())
