"""Scale-tier pre-check (spec 5.4; Task F2): can Orion build the graph of a test commit on this machine?

Before the tag, every test commit (vulnerable AND patched side of every manifest row) gets a graph
build with Joern's heap at JOERN_HEAP_GB and no model loaded. A row whose build fails on EITHER commit
moves to tier "scale" for ALL arms (reported separately), decided before any arm runs so it cannot be
cherry-picked.

  buildable(repo_url, sha, *, mirror_root, builder)  -> {ok, seconds, nodes, error, stage}
  python -m eval.precheck --manifest eval/dataset/manifest.json [--write] [--id ID ...] [--report PATH]

Run it from the repository root. (Not under `python -I`: isolated mode drops the working directory
from sys.path, and the venv's editable install points at another checkout, so `eval` would not import.
The untrusted trees are never the working directory nor on sys.path: they are only exported, parsed by
Joern and deleted.)

What counts as a build failure. Only the COMMIT failing: Joern or the normalizer raising, persist
failing on the data, or the build's pathfind step failing (graph_build keeps that error in the scan's
OrionScan record and persists no CandidateFlows; every orion-lm run on that commit would crash). The
MACHINE failing is not: Neo4j unreachable, a dropped bolt connection, an auth error
(neo4j ServiceUnavailable / SessionExpired / AuthError, anywhere in the exception chain) or a missing
Joern binary is stage "setup" -> "not_checked", never moved (eval.infra.is_infra, the rule the
orion-lm arm shares). So is a mirror or export failure. The CLI
also refuses to start (exit 1, nothing written) unless Neo4j answers and the Joern binaries exist.

Where records go. Every checked row gets a record {result, joern_heap_gb, orion_commit, checked_at,
vulnerable: {sha, ok, seconds, nodes, error, stage}, patched: {...}}, result "ok" | "build_failed" |
"not_checked". Records always go to the report file (--report, default precheck_report.json next to the
manifest; merged by row id, saved after each row). The manifest is only written with --write: then each
checked row's `precheck` is updated and a "build_failed" row moves to tier "scale". Without --write the
manifest is not touched (a dry run).

Re-runs keep the past. A new record carries the earlier ones in `history` (oldest first) and keeps the
original `tier_before` of a moved row, so a later "ok" build never hides or undoes a move: the row stays
"scale" (moving a row back is a human decision) with both records visible.

`seconds` is the builder's wall time only (mirror and export excluded); on a failed build it is the
time until the failure. `nodes` is what the builder reports (the default: the nodes Neo4j wrote, from
the scan's OrionScan record), None when it cannot say.
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

from eval import repo
from eval.infra import InfraError  # noqa: F401  -- re-exported: the machine failed, never a build failure
from eval.infra import is_infra as _is_infra
from eval.infra import joern_missing as _joern_missing
from eval.lmbuild import JOERN_HEAP_GB  # noqa: F401  -- spec 5.4; recorded in every record


class BuildFailed(RuntimeError):
    """The commit failed to build; `nodes` keeps what Neo4j wrote when the graph exists (pathfind)."""

    def __init__(self, msg: str, *, nodes=None):
        super().__init__(msg)
        self.nodes = nodes


def mirror_dir_for(repo_url: str, mirror_root: str) -> str:
    """One bare mirror per repo (github.com/<owner>/<name> -> <mirror_root>/<owner>__<name>), shared by
    every row and both commits of that repo."""
    m = re.search(r"github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", repo_url)
    name = f"{m.group(1)}__{m.group(2)}" if m else re.sub(r"[^\w.-]+", "_", repo_url)
    return os.path.join(mirror_root, name)


# ---- the default builder: the orion-lm arm's own build, no model ---------------------------------

def _print_event(ev) -> None:
    from orion.monitor import _format_event
    print("    " + (_format_event(ev) if isinstance(ev, dict) else str(ev)), flush=True)


def _drop_scan(scan_id: str) -> None:
    """Delete the pre-check's graph partition (and record) from Neo4j: no arm ever reuses it (its
    scan_id is tied to the deleted temp tree), and 500+ builds would otherwise pile up."""
    from neo4j import GraphDatabase
    from orion import config
    from orion.graph import scans
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        scans.delete_scan(driver, scan_id, scans.SCAN_LABELS)
    finally:
        driver.close()


def _nodes_written(scan_id: str):
    from orion.graph import scans
    rec = scans.get_record(scan_id)
    counts = rec.get("counts") if isinstance(rec, dict) else None
    nodes = counts.get("nodes") if isinstance(counts, dict) else None
    if not isinstance(nodes, dict):
        return None
    return sum(v for v in nodes.values() if isinstance(v, int))


def lm_graph_build(tree: str):
    """Build `tree` through eval.lmbuild.lm_build -- the ONE build the orion-lm arm also runs (lm sink
    profile, streaming build, OrionScan record, Joern heap pinned to JOERN_HEAP_GB) -- and return the
    number of nodes Neo4j wrote (sum of the record's counts.nodes) or None when the record does not say.

    Raises InfraError when a Joern binary is missing (lm_build), BuildFailed when the build's pathfind
    step failed (eval.arms.lm._pathfind_error: the same check the arm makes before it runs), and
    whatever the build raises otherwise. Joern's temp files (cpg.bin, the stream work dir) are kept in a
    `tmp` dir next to the tree, so buildable's cleanup removes them too; the scan's Neo4j partition is
    deleted afterwards."""
    from eval import lmbuild
    from eval.arms import lm
    scratch = os.path.join(os.path.dirname(os.path.abspath(tree)), "tmp")
    scan_id = None
    try:
        scan_id = lmbuild.lm_build(tree, _print_event, scratch_dir=scratch)
        nodes = _nodes_written(scan_id)
        flow_error = lm._pathfind_error(scan_id)
        if flow_error:
            raise BuildFailed(f"pathfind failed: {flow_error}", nodes=nodes)
        return nodes
    finally:
        if scan_id is not None:
            try:
                _drop_scan(scan_id)
            except Exception as e:  # the build's result stands; a leftover partition is only clutter
                print(f"    warning: could not delete scan {scan_id} from Neo4j: {e!r}", flush=True)


def buildable(repo_url: str, sha: str, *, mirror_root: str, builder=None, tmp_root=None,
              _mirror=repo.mirror, _export=repo.export_tree) -> dict:
    """Mirror `repo_url`, export `sha` to a fresh temp dir outside any repo, run `builder(tree)` (default
    lm_graph_build) and time it, then delete the tree. Returns {ok, seconds, nodes, error, stage}:
    stage is how far it got ("setup" | "mirror" | "export" | "build"); only stage "build" with ok False
    is a build failure. A machine failure inside the build (_is_infra) is reported as stage "setup".
    Never raises."""
    from eval.run import _leak_guard   # the launcher's rule: no tree under a CLAUDE.md or .git
    builder = builder or lm_graph_build
    out = {"ok": False, "seconds": None, "nodes": None, "error": None, "stage": "setup"}
    work = tempfile.mkdtemp(prefix="orion-precheck-", dir=tmp_root)
    tree = os.path.join(work, "tree")
    t0 = None
    try:
        _leak_guard(tree)
        out["stage"] = "mirror"
        mdir = mirror_dir_for(repo_url, mirror_root)
        os.makedirs(os.path.dirname(os.path.abspath(mdir)), exist_ok=True)
        _mirror(repo_url, mdir)
        out["stage"] = "export"
        _export(mdir, sha, tree)
        out["stage"] = "build"
        t0 = time.monotonic()
        nodes = builder(tree)
        out.update(ok=True, seconds=time.monotonic() - t0,
                   nodes=nodes if isinstance(nodes, int) and not isinstance(nodes, bool) else None)
    except Exception as e:
        if t0 is not None:
            out["seconds"] = time.monotonic() - t0
        if out["stage"] == "build" and _is_infra(e):
            out["stage"] = "setup"
        if isinstance(e, BuildFailed) and isinstance(e.nodes, int):
            out["nodes"] = e.nodes
        out["error"] = f"{e.__class__.__name__}: {e}"[:4000]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


# ---- the CLI -------------------------------------------------------------------------------------

def _orion_commit() -> str:
    from eval.run import git_head
    return git_head(".")


def _preflight() -> list:
    """Why this machine cannot run the pre-check now (empty = ready): Joern binaries present and Neo4j
    answering a read with Orion's credentials."""
    from neo4j import GraphDatabase
    from orion import config
    problems = []
    missing = _joern_missing()
    if missing:
        problems.append(f"Joern binaries not found: {', '.join(missing)} (JOERN_HOME={config.JOERN_HOME})")
    try:
        driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH, connection_timeout=10)
        try:
            with driver.session(database=config.NEO4J_DATABASE) as s:
                s.run("RETURN 1").consume()
        finally:
            driver.close()
    except Exception as e:
        problems.append(f"Neo4j at {config.NEO4J_URI} is not usable: {e.__class__.__name__}: {e}"[:600])
    return problems


def _save(path: str, data: dict) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)   # the manifest's own format (eval/dataset/mine.py _dump)
        f.write("\n")
    os.replace(tmp, path)


def _result(sides: dict) -> str:
    if any(not s["ok"] and s["stage"] == "build" for s in sides.values()):
        return "build_failed"
    if all(s["ok"] for s in sides.values()):
        return "ok"
    return "not_checked"


def _carry(prev, rec: dict) -> dict:
    """`rec` plus the past: earlier records in `history` (oldest first) and the original tier_before."""
    if isinstance(prev, dict):
        rec["history"] = list(prev.get("history") or []) + [{k: v for k, v in prev.items() if k != "history"}]
        if prev.get("tier_before") is not None:
            rec["tier_before"] = prev["tier_before"]
    return rec


def main(argv=None) -> int:
    from eval import manifest
    ap = argparse.ArgumentParser(description="Scale-tier pre-check: graph-build both commits of every "
                                             "manifest row (Joern heap 8 GB, no model).")
    ap.add_argument("--manifest", default="eval/dataset/manifest.json")
    ap.add_argument("--write", action="store_true",
                    help="write the records into the manifest and move every row whose build failed on "
                         "either commit to tier 'scale' (without it the manifest is not touched)")
    ap.add_argument("--id", action="append", default=[], help="check only this row id (repeatable)")
    ap.add_argument("--report", default=None,
                    help="where every record goes (default: precheck_report.json next to the manifest)")
    ap.add_argument("--mirror-root", default=os.path.join("eval", "mirrors", "precheck"))
    ap.add_argument("--tmp-root", default=None, help="where trees are exported (default: the system temp dir)")
    args = ap.parse_args(argv)
    data = manifest.load(args.manifest)
    rows = data["repos"]
    unknown = sorted(set(args.id) - {r.get("id") for r in rows})
    if unknown:
        print(f"unknown row id(s): {', '.join(unknown)}", flush=True)
        return 2
    problems = _preflight()
    if problems:   # a machine problem must never be recorded against a commit: touch nothing
        print("pre-check not started; this machine is not ready:", flush=True)
        for p in problems:
            print(f"  {p}", flush=True)
        return 1
    report_path = args.report or os.path.join(os.path.dirname(args.manifest) or ".", "precheck_report.json")
    report = {"manifest": args.manifest, "rows": {}}
    if os.path.exists(report_path):
        with open(report_path) as f:
            report = json.load(f)
    todo = [r for r in rows if not args.id or r.get("id") in args.id]
    commit = _orion_commit()
    moved = []
    results = []
    for i, row in enumerate(todo, 1):
        sides = {}
        for kind in ("vulnerable", "patched"):
            sha = row.get(f"{kind}_commit")
            print(f"[{i}/{len(todo)}] {row['id']} {kind} {sha}: building", flush=True)
            if not sha:
                res = {"ok": False, "seconds": None, "nodes": None, "stage": "setup",
                       "error": f"row has no {kind}_commit"}
            else:
                res = buildable(row["repo_url"], sha, mirror_root=args.mirror_root, tmp_root=args.tmp_root)
            sides[kind] = dict(res, sha=sha)
            took = "" if res["seconds"] is None else f" in {res['seconds']:.1f}s"
            what = f"ok{took}, {res['nodes']} nodes" if res["ok"] else f"FAILED at {res['stage']}{took}: {res['error']}"
            print(f"[{i}/{len(todo)}] {row['id']} {kind}: {what}"[:2000], flush=True)
        rec = {"result": _result(sides), "joern_heap_gb": JOERN_HEAP_GB, "orion_commit": commit,
               "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **sides}
        results.append(rec["result"])
        report["rows"][row["id"]] = _carry(report["rows"].get(row["id"]), dict(rec))
        report["updated_at"] = rec["checked_at"]
        _save(report_path, report)
        if args.write:
            mrec = _carry(row.get("precheck"), dict(rec))
            if rec["result"] == "build_failed" and row.get("tier") != "scale":
                mrec["tier_before"] = row.get("tier")
                row["tier"] = "scale"
                moved.append(row["id"])
            row["precheck"] = mrec
            _save(args.manifest, data)
    print(f"checked {len(todo)} row(s): {results.count('ok')} ok, {results.count('build_failed')} build "
          f"failed, {results.count('not_checked')} not checked; records in {report_path}; "
          + (f"moved to scale: {', '.join(moved) or 'none'}" if args.write
             else "manifest not touched (no --write)"), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
