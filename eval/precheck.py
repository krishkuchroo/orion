"""Scale-tier pre-check (spec 5.4; Task F2): can Orion build the graph of a test commit on this machine?

Before the tag, every test commit (vulnerable AND patched side of every manifest row) gets a graph
build with Joern's heap at JOERN_HEAP_GB and no model loaded. A row whose build fails on EITHER commit
moves to tier "scale" for ALL arms (reported separately), decided before any arm runs so it cannot be
cherry-picked.

  buildable(repo_url, sha, *, mirror_root, builder)  -> {ok, seconds, nodes, error, stage}
  python -m eval.precheck --manifest eval/dataset/manifest.json [--write] [--id ID ...]

Run it from the repository root. (Not under `python -I`: isolated mode drops the working directory
from sys.path, and the venv's editable install points at another checkout, so `eval` would not import.
The untrusted trees are never the working directory nor on sys.path: they are only exported, parsed by
Joern and deleted.)

The CLI writes a `precheck` record into every row it checks (measured values only; a missing one stays
None) and saves the manifest after each row. With --write it also moves a row whose build failed on
either commit to tier "scale", keeping the old tier in `precheck.tier_before`. A row whose mirror or
export failed was not checked: its record says "not_checked" and it is never moved; neither is a row
outside --id.

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

JOERN_HEAP_GB = 8   # spec 5.4


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


def lm_graph_build(tree: str):
    """Build `tree` exactly as the orion-lm arm does (eval.arms.lm._build_graph: lm sink profile,
    streaming build, OrionScan record) with Joern's heap pinned to JOERN_HEAP_GB, and return the number
    of nodes Neo4j wrote (sum of the record's counts.nodes) or None when the record does not say.
    Joern's temp files (cpg.bin, the stream work dir) are kept in a `tmp` dir next to the tree, so the
    caller's cleanup removes them too; the scan's Neo4j partition is deleted afterwards. Raises when the
    build fails."""
    from orion import config
    from orion.graph import scans
    from eval.arms import lm
    scratch = os.path.join(os.path.dirname(os.path.abspath(tree)), "tmp")
    os.makedirs(scratch, exist_ok=True)
    old_heap, old_tmp = config.JOERN_HEAP_GB, tempfile.tempdir
    config.JOERN_HEAP_GB, tempfile.tempdir = str(JOERN_HEAP_GB), scratch
    scan_id = None
    try:
        scan_id = lm._build_graph(tree, _print_event)
        rec = scans.get_record(scan_id)
        counts = rec.get("counts") if isinstance(rec, dict) else None
        nodes = counts.get("nodes") if isinstance(counts, dict) else None
        if not isinstance(nodes, dict):
            return None
        return sum(v for v in nodes.values() if isinstance(v, int))
    finally:
        config.JOERN_HEAP_GB, tempfile.tempdir = old_heap, old_tmp
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
    is a build failure. Never raises."""
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
        out["error"] = f"{e.__class__.__name__}: {e}"[:4000]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


# ---- the CLI -------------------------------------------------------------------------------------

def _orion_commit() -> str:
    from eval.run import git_head
    return git_head(".")


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


def main(argv=None) -> int:
    from eval import manifest
    ap = argparse.ArgumentParser(description="Scale-tier pre-check: graph-build both commits of every "
                                             "manifest row (Joern heap 8 GB, no model).")
    ap.add_argument("--manifest", default="eval/dataset/manifest.json")
    ap.add_argument("--write", action="store_true",
                    help="also move every row whose build failed on either commit to tier 'scale'")
    ap.add_argument("--id", action="append", default=[], help="check only this row id (repeatable)")
    ap.add_argument("--mirror-root", default=os.path.join("eval", "mirrors", "precheck"))
    ap.add_argument("--tmp-root", default=None, help="where trees are exported (default: the system temp dir)")
    args = ap.parse_args(argv)
    data = manifest.load(args.manifest)
    rows = data["repos"]
    unknown = sorted(set(args.id) - {r.get("id") for r in rows})
    if unknown:
        print(f"unknown row id(s): {', '.join(unknown)}", flush=True)
        return 2
    todo = [r for r in rows if not args.id or r.get("id") in args.id]
    commit = _orion_commit()
    moved = []
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
        if args.write and rec["result"] == "build_failed" and row.get("tier") != "scale":
            rec["tier_before"] = row.get("tier")
            row["tier"] = "scale"
            moved.append(row["id"])
        row["precheck"] = rec
        _save(args.manifest, data)
    results = [r["precheck"]["result"] for r in todo]
    print(f"checked {len(todo)} row(s): {results.count('ok')} ok, {results.count('build_failed')} build "
          f"failed, {results.count('not_checked')} not checked; "
          + (f"moved to scale: {', '.join(moved) or 'none'}" if args.write else "no tier changes (no --write)"),
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
