import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from . import db, owasp, queue, repo
from .resources import PhaseSampler

# The five study arms (design 2026-10-18 §5.4). orion-lm* run in-process (eval/arms/lm.py);
# plain-* are the frontier competitors (Claude Code / Codex CLI).
ARMS = ["orion-lm", "orion-lm-base", "plain-sonnet5", "plain-opus5", "plain-gpt"]
# In-process arm -> the main() flag naming its local model path (that path is its model_tag).
LM_MODEL_FLAGS = {"orion-lm": "--lm-model", "orion-lm-base": "--lm-base-model"}

# Exact model ids, verified against the installed CLIs on 2026-10-18 (claude 2.1.302,
# codex-cli 0.155.1): `claude --model <id>` runs and reports the same id in its init/usage
# events; `codex exec -m <id>` runs. Frozen at pre-registration (orion-lm-prereg-v1).
# orion-lm* have no fixed tag: main() maps them to the --lm-model / --lm-base-model path.
MODEL_TAGS = {
    "plain-sonnet5": "claude-sonnet-5",
    "plain-opus5": "claude-opus-5",
    "plain-gpt": "gpt-5.6-sol",
}

# Reasoning effort per frontier arm, passed as a real CLI flag (claude --effort / codex
# -c model_reasoning_effort) and recorded in runs.effort. Pre-registration decision #7.
EFFORT = {
    "plain-sonnet5": "xhigh",
    "plain-opus5": "xhigh",
    "plain-gpt": "xhigh",
}


# Usage-limit signatures. UNCAPTURED: these are the documented CLI messages ("Claude AI usage limit
# reached", "5-hour limit reached", Codex "You've hit your usage limit", HTTP 429), not text
# copied from a real event -- eval/tests/fixtures/limit_{claude,codex}.json carry "captured": false.
# Replace them with the first real limit event seen in Phase 0 and tighten the match to it.
_HTTP_429 = r"(?:http|status|code)\W{0,3}429|\b429\b.{0,3}too many requests"
# raw (non-JSON) lines: only specific CLI phrasings; "limit reached" needs usage/rate/plan on the
# same line so "context limit reached" / "max turns limit reached" stay real failures
_RAW_RE = re.compile(r"usage limit|rate[- ]limit(?:ed| exceeded| reached| hit)|hit your limit|"
                     r"(?:usage|rate|plan)\b.*limit reached|limit reached.*\b(?:usage|rate|plan)\b|"
                     + _HTTP_429, re.I)
# error/result-shaped structured fields (error subtypes like error_rate_limit): bare "rate limit" ok
_EVENT_RE = re.compile(_RAW_RE.pattern + r"|rate limit", re.I)
_EVENT_FIELDS = ("subtype", "error", "message", "result", "reason")
_SOURCES = ("claude", "codex")


def _line_signals_limit(line: str) -> bool:
    try:
        ev = json.loads(line)
    except ValueError:
        return bool(_RAW_RE.search(line))  # raw CLI stderr / plain text
    if not isinstance(ev, dict):
        return False
    # structured events: only error/result-shaped ones, so the model's own prose about
    # rate limiting (assistant/tool events) is never mistaken for a CLI limit
    if not (ev.get("is_error") or ev.get("type") in ("result", "error") or "error" in ev
            or str(ev.get("type", "")).endswith("failed")):
        return False
    text = " ".join(v if isinstance(v, str) else json.dumps(v)
                    for v in (ev.get(k) for k in _EVENT_FIELDS) if v)
    return bool(_EVENT_RE.search(text.replace("_", " ")))


def classify_match(status: str, lines: list, *, source: str):
    """(final_status, matched_line_or_None). Only the Claude/Codex CLIs have a subscription usage
    limit: any other source (local-model arms) returns the status unchanged."""
    if status == "ok" or source not in _SOURCES:
        return status, None
    for l in lines:
        if _line_signals_limit(l):
            return "aborted", l
    return status, None


def classify_exit(status: str, lines: list, *, source: str) -> str:
    """'aborted' when a non-ok claude/codex run's output carries a usage/rate-limit signature (the
    model did not fail; the subscription ran out), otherwise the original status."""
    return classify_match(status, lines, source=source)[0]


def _source_for(arm: str) -> str:
    return {"plain-gpt": "codex", "plain-sonnet5": "claude", "plain-opus5": "claude"}.get(arm, "lm")


def git_head(path: str = ".") -> str:
    try:
        return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""


def run_one(conn, *, arm, repo_meta, run_no, model_tags, base_env,
            orion_commit, cli_versions, launcher, efforts=EFFORT) -> str:
    model_tag = model_tags.get(arm, arm)
    effort = efforts.get(arm, "")
    attempt_no = db.next_attempt(conn, arm=arm, repo=repo_meta["id"],
                                 commit_sha=repo_meta["commit_sha"],
                                 case_id=repo_meta.get("case_id", ""), run_no=run_no)
    rid = db.start_run(conn, arm=arm, repo=repo_meta["id"], tier=repo_meta.get("tier", ""),
                       run_no=run_no, model_tag=model_tag, cli_versions=cli_versions,
                       orion_commit=orion_commit,
                       commit_kind=repo_meta.get("commit_kind", ""),
                       commit_sha=repo_meta["commit_sha"],
                       case_id=repo_meta.get("case_id", ""),
                       attempt_no=attempt_no, effort=effort)
    repo_meta = dict(repo_meta, run_no=run_no, attempt_no=attempt_no)
    lines = []

    def on_line(line):
        lines.append(line)
        db.log_event(conn, rid, stage="run", level="info", message=line[:2000])

    sampler = {"s": None}  # attached once the arm's process exists (pid handoff)

    def on_start(proc):
        if sampler["s"] is not None:
            sampler["s"].__exit__(None, None, None)
        sampler["s"] = PhaseSampler(proc.pid).__enter__()

    t0 = time.monotonic()
    try:
        res = launcher(arm, repo_meta, model_tag, on_line, effort=effort, on_start=on_start)
    except KeyboardInterrupt:  # operator interrupt is not the model's miss
        _log_resource(conn, rid, sampler["s"], t0)
        db.log_event(conn, rid, stage="run", level="warn", message="interrupted by operator")
        db.finish_run(conn, rid, "aborted")
        raise
    except Exception as e:
        _log_resource(conn, rid, sampler["s"], t0)
        db.log_event(conn, rid, stage="run", level="error", message=str(e)[:2000])
        db.finish_run(conn, rid, "error")
        return "error"
    # the run must never be left 'running': a failure while recording what the arm returned
    # becomes an error event + status "error", not a dangling row
    try:
        _log_resource(conn, rid, sampler["s"], t0)
        for block in res.usage:
            db.log_agent_call(conn, rid, session_id=None, stage="run",
                              input_tokens=block.get("uncached_in"), output_tokens=block.get("out"),
                              cache_read=block.get("cache_read"), cache_write=block.get("cache_write"),
                              turns_used=None, turn_limit=None, peak_context=None,
                              exit_reason=None, error_head=None)
        for step in res.steps or []:
            db.log_step(conn, rid, **step)
        if res.findings_path is None:
            db.log_event(conn, rid, stage="run", level="warn",
                         message="no valid findings file; scored as a miss")
    except Exception as e:
        db.log_event(conn, rid, stage="run", level="error",
                     message=f"recording run result failed: {e!r}"[:2000])
        db.finish_run(conn, rid, "error")
        return "error"
    final, matched = classify_match(res.status, lines, source=_source_for(arm))
    if final != res.status:
        db.log_event(conn, rid, stage="run", level="warn",
                     message=f"usage limit hit ({res.status} -> {final}); not scored, will resume;"
                             f" matched: {matched[:500]}")
    db.finish_run(conn, rid, final)
    return final


def _log_resource(conn, rid, sampler, t0):
    """One resources row for the run phase. Peak RSS comes only from a sampler that was
    attached to a live process; otherwise it is recorded as missing (None), never 0.
    wall_seconds has two sources: with a sampler it is the arm's process lifetime as seen by
    the sampler (spawn -> launcher return, so it includes the findings copy and the tree
    rmtree); without one (no process was ever spawned) it is run_one's own clock around the
    launcher call."""
    if sampler is not None:
        sampler.__exit__(None, None, None)
        wall, rss = sampler.wall_seconds, sampler.peak_rss_mb
    else:
        wall, rss = time.monotonic() - t0, None
    db.log_resource(conn, rid, phase="run", wall_seconds=wall, peak_rss_mb=rss,
                    graph_nodes=None, graph_edges=None, loc=None)


def _default_plain(**kw):
    from .arms.plain import plain_arm  # runs Claude Code / Codex with TASK_PROMPT
    return plain_arm(**kw)


def _default_lm(**kw):
    from .arms.lm import orion_lm_arm  # in-process: graph build -> model load -> discover_lm
    return orion_lm_arm(**kw)


def run_dir_for(arm, repo_meta, root=os.path.join("eval", "runs")):
    run_seg = str(repo_meta.get("run_no", 1))
    if repo_meta.get("attempt_no", 1) > 1:
        run_seg += f".a{repo_meta['attempt_no']}"
    return os.path.join(root, arm, repo_meta["id"], repo_meta["commit_sha"],
                        repo_meta.get("case_id") or "_", run_seg)


def _leak_guard(tree):
    d = os.path.dirname(tree)
    while True:
        for marker in ("CLAUDE.md", ".git"):
            if os.path.exists(os.path.join(d, marker)):
                raise RuntimeError(f"tree {tree} sits under {d}, which contains {marker}; "
                                   "agents would read it (answer leak). Use --tree-root outside any repo.")
        parent = os.path.dirname(d)
        if parent == d:
            return
        d = parent


def build_launcher(*, base_env, shim_dir, graph_cache, _plain=_default_plain, _lm=_default_lm,
                   _export=repo.export_tree, _strip=owasp.strip_answers, tree_root=None):
    """The launcher run_one calls: export the commit to a fresh tree (no .git), run the arm, delete the
    tree. An OWASP item (repo_meta["case"] set, Task F2) has its answer files stripped right after the
    export, for every arm, and its case passed to the arm (plain: CASE_PROMPT; orion-lm: the case's
    flows); a manifest item has case None."""
    tree_root = tree_root or os.path.join(tempfile.gettempdir(), "orion-eval-trees")

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        sha = repo_meta["commit_sha"]
        run_dir = os.path.abspath(run_dir_for(arm, repo_meta))
        tree = os.path.abspath(os.path.join(run_dir_for(arm, repo_meta, tree_root), "tree"))
        _leak_guard(tree)
        usage_log = os.path.join(run_dir, "usage.jsonl")
        json_out = os.path.join(run_dir, "findings.json")
        try:
            os.makedirs(run_dir, exist_ok=True)
            _export(repo_meta["mirror_dir"], sha, tree)
            case = repo_meta.get("case")
            if case is not None:   # OWASP ships its answers next to the code
                removed = _strip(tree)
                on_line(f"owasp: stripped {len(removed)} answer file(s) from the tree: "
                        + ", ".join(removed[:20]) + (" ..." if len(removed) > 20 else ""))
            common = dict(arm=arm, repo_dir=tree, model_tag=model_tag, effort=effort,
                          json_out=json_out, usage_log=usage_log, base_env=base_env,
                          on_line=on_line, on_start=on_start, case=case)
            if arm in LM_MODEL_FLAGS:
                # in-process orion-lm arms: model_tag is the local model path
                res = _lm(graph_cache=graph_cache, run_no=repo_meta.get("run_no", 1),
                          case_id=repo_meta.get("case_id", ""), repo_id=repo_meta["id"],
                          commit_sha=sha, **common)
            elif arm.startswith("orion-"):
                # nothing may silently run the removed `orion scan` subprocess path
                raise ValueError(f"no in-process arm for {arm!r} (known: {sorted(LM_MODEL_FLAGS)})")
            else:
                # the arm copies its findings.json out of the tree before it is deleted
                res = _plain(shim_dir=shim_dir, **common)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        return res
    return launcher


def main(argv=None, sleep=time.sleep):
    from . import manifest, preflight
    from .shim_setup import shim_dir as _shim_dir
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", action="append", choices=ARMS)
    ap.add_argument("--manifest", default="eval/dataset/manifest.json",
                    help="manifest v2 (vulnerable + patched commit per row); '' runs no manifest rows")
    ap.add_argument("--owasp", metavar="PATH",
                    help="OWASP sample (eval/dataset/owasp_sample.json): add one single-commit item per "
                         "case, under repo id owasp-java / owasp-python, tier 'owasp'")
    ap.add_argument("--owasp-runs", type=int, default=1,
                    help="runs per arm per OWASP case (spec 5.4: R = 1); --runs is for manifest rows")
    ap.add_argument("--db", default="eval/runs.db")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--tree-root", default=os.path.join(tempfile.gettempdir(), "orion-eval-trees"))
    ap.add_argument("--mirror-root", default="eval/mirrors/")
    ap.add_argument("--resume-wait", type=int, default=900,
                    help="seconds to sleep after a usage-limit abort before re-planning")
    ap.add_argument("--lm-model", metavar="PATH",
                    help="local model path for the orion-lm arm (recorded as runs.model_tag)")
    ap.add_argument("--lm-base-model", metavar="PATH",
                    help="local model path for the orion-lm-base arm (recorded as runs.model_tag)")
    args = ap.parse_args(argv)
    arms = args.arm or ARMS
    # A selected orion-lm* arm needs an existing model path. Refuse here, before any run row or
    # mirror exists: a misconfiguration must never become a terminal, scored 'error' run.
    model_tags = dict(MODEL_TAGS)
    given = {"orion-lm": args.lm_model, "orion-lm-base": args.lm_base_model}
    for arm, flag in LM_MODEL_FLAGS.items():
        if arm not in arms:
            continue
        path = given[arm]
        if not path or not os.path.exists(path):
            why = "not given" if not path else f"{path!r} does not exist"
            print(f"arm {arm} needs {flag} PATH (the local model): {why}", flush=True)
            return 2
        model_tags[arm] = os.path.abspath(path)
    data = manifest.load(args.manifest) if args.manifest else {"repos": []}
    errors = manifest.validate(data, split_repos=manifest.split_repos()) if data["repos"] else []
    if errors:  # the test set must be clean to run: refuse before mirroring anything
        print(f"manifest {args.manifest} is invalid ({len(errors)} error(s)):", flush=True)
        for e in errors:
            print(f"  {e}", flush=True)
        return 2
    benchmarks = []
    if args.owasp:  # validated before anything is mirrored, like the manifest
        sample = owasp.load_sample(args.owasp)
        errors = owasp.validate_sample(sample)
        clash = sorted({b.get("id") for b in sample["benchmarks"]} & {r.get("id") for r in data["repos"]})
        errors += [f"benchmark id {c} is also a manifest row id" for c in clash]
        if errors:
            print(f"OWASP sample {args.owasp} is invalid ({len(errors)} error(s)):", flush=True)
            for e in errors:
                print(f"  {e}", flush=True)
            return 2
        benchmarks = sample["benchmarks"]
    repos = data["repos"]  # [{id, repo_url, tier, ...}]
    good = []
    for r in repos:  # mirror once per repo, then pin the commit to check out
        try:
            r["mirror_dir"] = os.path.join(args.mirror_root, r["id"])
            if not (r.get("commit_sha") or r.get("vulnerable_commit") or r.get("patched_commit")):
                raise ValueError("manifest row has none of commit_sha/vulnerable_commit/patched_commit")
            repo.mirror(r["repo_url"], r["mirror_dir"])
            if r.get("vulnerable_commit") and r.get("patched_commit"):
                commits = [(r["vulnerable_commit"], "vulnerable"), (r["patched_commit"], "patched")]
            else:  # no pair (commit_sha-only row is forced to kind 'vulnerable'): commit_sha (or the vulnerable side) is the vulnerable commit
                sha = r.get("commit_sha") or r.get("vulnerable_commit") or repo.vulnerable_commit(
                    r["patched_commit"], r["mirror_dir"])
                commits = [(sha, "vulnerable")]
            r["commits"] = commits
            good.append(r)
        except Exception as e:
            print(f"SKIPPING repo {r.get('id')}: {e}", flush=True)
    items, meta_by_key = {}, {}
    for r in good:
        case = r.get("case_id", "")
        for sha, kind in r["commits"]:
            items.setdefault(r["id"], []).append((sha, kind, case))
            meta_by_key[(r["id"], sha, case)] = dict(r, commit_sha=sha, commit_kind=kind, case_id=case)
    owasp_items = {}
    for b in benchmarks:  # one mirror per benchmark repo; every case is a single-commit item on its pin
        mirror_dir = os.path.join(args.mirror_root, b["id"])
        try:
            repo.mirror(b["repo_url"], mirror_dir)
        except Exception as e:
            print(f"SKIPPING OWASP benchmark {b['id']}: {e}", flush=True)
            continue
        sha = b["pinned_sha"]
        for c in b["cases"]:
            owasp_items.setdefault(b["id"], []).append((sha, "owasp", c["case_id"]))
            meta_by_key[(b["id"], sha, c["case_id"])] = {
                "id": b["id"], "repo_url": b["repo_url"], "tier": "owasp", "mirror_dir": mirror_dir,
                "commit_sha": sha, "commit_kind": "owasp", "case_id": c["case_id"], "case": dict(c)}
    conn = db.connect(args.db)
    versions = "; ".join(f"{r['tool']}={r['detail']}" for r in preflight.check())
    orion_commit = git_head()
    graph_cache = {}
    launcher = build_launcher(base_env=dict(os.environ), shim_dir=_shim_dir(),
                              graph_cache=graph_cache, tree_root=args.tree_root)
    while True:  # a usage-limit abort pauses, then re-plans: the key comes back as a new attempt
        todo = queue.pending(conn, queue.plan(arms, items, args.runs)
                             + queue.plan(arms, owasp_items, args.owasp_runs))
        if not todo:
            break
        for arm, repo_id, sha, case, n in todo:
            status = run_one(conn, arm=arm, repo_meta=meta_by_key[(repo_id, sha, case)], run_no=n,
                             model_tags=model_tags, base_env=dict(os.environ),
                             orion_commit=orion_commit, cli_versions=versions, launcher=launcher)
            if status == "aborted":
                print(f"usage limit hit; resuming in {args.resume_wait}s", flush=True)
                sleep(args.resume_wait)
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
