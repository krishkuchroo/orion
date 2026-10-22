"""Path ground truth proposed from the fix (plan Task E5, spec 5.4 "Path ground truth").

Humans confirm this; F1's manifest stores it. Nothing here is a label until `labelers` is non-empty.

Method (all graph logic is reused from `train.fixmap`, nothing is re-implemented):

1. fix sites on the VULNERABLE scan (`fixmap.fix_sites`, side="vulnerable"), and the same hunks on the
   PATCHED scan (`fixmap.fix_sites(side="patched")`: `fix_sites_patched`, the patched commit's line
   numbers, which a patched (false-alarm) run is matched against).
2. flows through a fix site = vulnerable CandidateFlows whose `path_uids` contain a fix-site call uid.
3. "gone on patched" = `fixmap.pair_yield`'s `flows_gone_on_patched` (cross-scan matcher on
   (file, diff-mapped line, call name); uids hash the scan_id so they are never compared across scans).
   Flows whose source/sink cannot be matched go to `flows_unresolved`, never to gone.
4. accepted entry points = EntryPoints that `ENTERS_AT` the method containing the source call of a
   gone flow (`(e:EntryPoint)-[:ENTERS_AT]->(m:CpgMethod)`, every node scoped by scan_id).

Lead convention: the lead location is the FIX SITE. `sink_uid` / `sink_or_protected_operation` describe
fixmap's gold flow (best-ranked flow through a fix site); `fix_sites` are the fix-site records.

Error policy: `candidate_paths` never raises. A graph read failure (GraphReadError or any query error)
returns a record with `error` set (string), `graph_missed=True` and empty lists, so a batch run over the
test set survives one bad pair. `to_manifest_fields` of such a record is all-empty plus graph_missed=True.

`graph_missed=True` means the human must add the path by hand; `reason` says why:
`no_site_nodes` (no hunk maps to any call), `no_flow_through_site` (sites map, no CandidateFlow passes
through), or `query_error` (any graph read failed, including the read of the flows themselves). When
graph_missed is False, `reason` is None, or `no_flow_gone_on_patched` when flows pass through the fix
and none is gone on the patched scan (some survive), or `all_flows_unresolved` when every flow through the
fix has a source or sink that cannot be matched across the scans (nothing is known about the patched
side). In both cases no entry points are proposed.

The driver (the plan's "run it over every test-set pair"; implemented and unit-tested, NOT run here):

  python -m eval.pathgt --manifest eval/dataset/manifest.json [--id ID ...] [--write] [--report PATH]

Run it from the repository root (like eval.precheck, not under `python -I`). Per row: mirror the repo
(eval.precheck's one-mirror-per-repo layout and default root, shared with the pre-check), read the fix
hunks from the mirror (`train.fixmap.fix_hunks`), build BOTH commits with the lm profile through
eval.lmbuild.lm_build (the pre-check's and the arm's build: Joern heap 8 GB, temp files in the run's own
work dir) and KEEP the two scans (their ids go in the record; `orion gc` them after labeling), then
`candidate_paths` -> `to_manifest_fields`. It mirrors eval.precheck's semantics: a preflight first
(Neo4j answering, Joern present; exit 1 and nothing written otherwise); a machine failure (mirror,
export, Neo4j, Joern: eval.infra) is "not_checked" and proposes nothing; every record goes to the report
(--report, default pathgt_report.json next to the manifest; merged by row id, earlier records kept in
`history`); a dry run (no --write) writes ONLY the report. With --write each "proposed" row gets the
fields merged plus a `pathgt` provenance record. A row that has labelers is NEVER touched (it is a
human's now): it is skipped and recorded "skipped_labeled".
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

from eval import infra, repo
from eval.names import function_name
from train import fixmap
from train.fixmap import GraphReadError  # noqa: F401  -- re-exported for callers

_Q_ENTRIES = ("MATCH (e:EntryPoint {scan_id:$scan_id})-[:ENTERS_AT]->(m:CpgMethod {scan_id:$scan_id}) "
              "RETURN e.uid AS uid, e.kind AS kind, e.exposure AS exposure, "
              "m.full_name AS method_full_name")


def _empty(error=None, reason=None) -> dict:
    return {"fix_sites": [], "fix_sites_patched": [], "flows_through_fix": [],
            "flows_gone_on_patched": [], "flows_unresolved": [],
            "sink_uid": None, "sink": None, "accepted_entry_points": [],
            "graph_missed": True, "reason": reason, "error": error}


def candidate_paths(db, vuln_scan: str, patched_scan: str, hunks: list[dict], *, root: str | None = None) -> dict:
    """Propose the path answer key for one pair. Returns
    {fix_sites: [fixmap site records], fix_sites_patched: [fixmap site records, side "patched"],
     flows_through_fix: [flow uid], flows_gone_on_patched: [flow uid],
     flows_unresolved: [flow uid], sink_uid, sink: {sink_uid, sink_category, file, line, name} | None,
     accepted_entry_points: [{uid, kind, method_full_name, file, line, evidence}], graph_missed, reason,
     error}.
    `hunks` use fixmap's shape (file, old_file?, old_start, old_end, new_start, new_end). Never raises."""
    try:
        return _candidate_paths(db, vuln_scan, patched_scan, hunks, root)
    except Exception as e:  # noqa: BLE001 -- includes GraphReadError; recorded, never fatal
        return _empty(error=f"{type(e).__name__}: {e}", reason="query_error")


def _candidate_paths(db, vuln_scan, patched_scan, hunks, root) -> dict:
    vidx = fixmap._ScanIndex(db, vuln_scan, root)
    sites = fixmap._fix_sites(vidx, hunks, "vulnerable", root, 3)
    cp = _empty()
    cp["fix_sites"] = sites
    cp["fix_sites_patched"] = fixmap.fix_sites(db, patched_scan, hunks, side="patched", root=root)
    if not fixmap._site_uids(sites):
        cp["reason"] = "no_site_nodes"
        return cp
    # A read error here raises (-> query_error); it is never reported as "no flow through the site".
    through = fixmap._through(fixmap._flows(db, vuln_scan), fixmap._site_uids(sites))
    cp["flows_through_fix"] = [f["uid"] for f in through]
    if not through:
        cp["reason"] = "no_flow_through_site"
        return cp
    gold = through[0]   # fixmap.gold_flow's definition: the best-ranked flow through a fix site
    cp["graph_missed"] = False
    cp["sink_uid"] = gold["sink_uid"]
    k = vidx.by_uid.get(gold["sink_uid"])
    cp["sink"] = {"sink_uid": gold["sink_uid"], "sink_category": gold.get("sink_category"),
                  "file": k[0] if k else None, "line": k[1] if k else None, "name": k[2] if k else None}

    rec = fixmap.pair_yield(db, "pathgt", hunks, vulnerable_scan_id=vuln_scan,
                            patched_scan_id=patched_scan, root=root)
    if str(rec.get("reason") or "").startswith("query_error"):
        raise GraphReadError(rec["reason"])
    gone = rec.get("flows_gone_on_patched") or []
    cp["flows_gone_on_patched"] = [f["uid"] for f in gone]
    cp["flows_unresolved"] = [f["uid"] for f in rec.get("flows_unresolved") or []]
    if not gone:
        # every through-fix flow unresolved: nothing is known about the patched side
        unresolved_all = len(cp["flows_unresolved"]) == len(through)
        cp["reason"] = "all_flows_unresolved" if unresolved_all else "no_flow_gone_on_patched"
        return cp

    by_flow = {f["uid"]: f for f in through}
    method_at = {r["fn"]: (fixmap.norm_path(r.get("f"), root), r.get("l"))
                 for r in fixmap._rows(db, vuln_scan, fixmap._Q_METHODS)}
    entries: dict[str, list[dict]] = {}
    for r in fixmap._rows(db, vuln_scan, _Q_ENTRIES):
        entries.setdefault(r.get("method_full_name"), []).append(r)
    accepted: dict[str, dict] = {}
    for g in gone:
        src = vidx.by_uid.get(by_flow[g["uid"]]["source_uid"])
        method = vidx.method(src[0], src[1]) if src else None
        for r in entries.get(method, []) if method else []:
            ev = (f"ENTERS_AT {method}; contains source call at {src[0]}:{src[1]} of flow {g['uid']} "
                  "(through the fix site, absent on patched)")
            if r["uid"] in accepted:
                accepted[r["uid"]]["evidence"] += f"; also flow {g['uid']}"
            else:
                file, line = method_at.get(method, (None, None))
                accepted[r["uid"]] = {"uid": r["uid"], "kind": r.get("kind"), "method_full_name": method,
                                      "file": file, "line": line if isinstance(line, int) else None,
                                      "evidence": ev}
    cp["accepted_entry_points"] = list(accepted.values())
    return cp


def _sites(records) -> list[dict]:
    return [{"file": s["file"], "line": s["line"], "end_line": s["end"],
             "function": function_name(s.get("method_full_name")),
             "method_full_name": s.get("method_full_name")}
            for s in records or []]


def to_manifest_fields(cp: dict) -> dict:
    """The manifest-v2 subset (all JSON-serialisable), for the labelers to confirm or correct:
    fix_sites: [{file, line, end_line, function, method_full_name}] (function =
      eval.names.function_name(method_full_name): None at module level; the shape eval.match reads);
    fix_sites_patched: the same shape on the patched commit (a patched run's L1 key);
    sink_or_protected_operation: {sink_uid, sink_category, file, line, name} | None;
    accepted_entry_points: [{uid, kind, method_full_name, file, line}] (line = the method's
      declaration line on the vulnerable scan, which orion-lm's file+line path metrics need);
    entry_evidence: str (one line per entry point, '' if none); labelers: always [] (a human signs);
    graph_missed: bool (True -> the human adds the path by hand)."""
    eps = cp.get("accepted_entry_points") or []
    return {"fix_sites": _sites(cp.get("fix_sites")),
            "fix_sites_patched": _sites(cp.get("fix_sites_patched")),
            "sink_or_protected_operation": cp.get("sink"),
            "accepted_entry_points": [{k: e.get(k) for k in ("uid", "kind", "method_full_name", "file", "line")}
                                      for e in eps],
            "entry_evidence": "\n".join(f"{e['uid']}: {e.get('evidence')}" for e in eps),
            "labelers": [],
            "graph_missed": bool(cp.get("graph_missed"))}


# ---- the driver ----------------------------------------------------------------------------------

def _print_event(ev) -> None:
    from orion.monitor import _format_event
    print("    " + (_format_event(ev) if isinstance(ev, dict) else str(ev)), flush=True)


def _lm_build(tree: str) -> str:
    """The default builder: eval.lmbuild.lm_build with Joern's temp files in a `tmp` dir next to the
    tree (inside the work dir propose_row deletes). Returns the scan_id; the scan is kept."""
    from eval import lmbuild
    return lmbuild.lm_build(tree, _print_event, scratch_dir=os.path.join(os.path.dirname(tree), "tmp"))


def _open_db():
    from orion.graphdb import GraphDB
    return GraphDB()


def _side(stage="setup", **kw) -> dict:
    return {"sha": None, "scan_id": None, "ok": False, "stage": stage, "error": None, "seconds": None, **kw}


def _build_side(mdir: str, sha: str, *, builder, tmp_root, _export) -> dict:
    """Export `sha` to a fresh work dir outside any repo, build it, delete the tree (the scan stays)."""
    from eval.run import _leak_guard   # the launcher's rule: no tree under a CLAUDE.md or .git
    out = _side(sha=sha)
    work = tempfile.mkdtemp(prefix="pathgt-", dir=tmp_root)
    tree = os.path.join(work, "tree")
    t0 = None
    try:
        _leak_guard(tree)
        out["stage"] = "export"
        _export(mdir, sha, tree)
        out["stage"] = "build"
        t0 = time.monotonic()
        out["scan_id"] = builder(tree)
        out.update(ok=True, seconds=time.monotonic() - t0)
    except Exception as e:
        if t0 is not None:
            out["seconds"] = time.monotonic() - t0
        if out["stage"] == "build" and infra.is_infra(e):
            out["stage"] = "setup"            # the machine, not the commit
        out["error"] = f"{e.__class__.__name__}: {e}"[:4000]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


def propose_row(row: dict, *, mirror_root: str, tmp_root=None, builder=None, open_db=None, hunks=None,
                _mirror=repo.mirror, _export=repo.export_tree) -> dict:
    """One row's record (never raises): {result, vulnerable: side, patched: side, n_hunks, reason,
    graph_missed, error, n_flows_through_fix, n_flows_gone_on_patched, n_flows_unresolved, fields},
    side = {sha, scan_id, ok, stage, error, seconds}. result:
      "proposed"     fields = to_manifest_fields(candidate_paths(...)), ready to merge for the labelers
      "not_checked"  the machine failed (mirror, hunks, export, Neo4j, Joern): nothing proposed
      "build_failed" a commit did not build (stage "build"): nothing proposed
      "query_error"  candidate_paths could not read the graph (not a machine failure): nothing proposed
    builder(tree) -> scan_id (default: eval.lmbuild.lm_build); open_db() -> a GraphDB-like reader;
    hunks(mirror_dir, vulnerable, patched) -> fixmap hunks (default train.fixmap.fix_hunks)."""
    from eval.precheck import mirror_dir_for   # one bare mirror per repo, shared with the pre-check
    builder, open_db, hunks = builder or _lm_build, open_db or _open_db, hunks or fixmap.fix_hunks
    rec = {"result": "not_checked", "vulnerable": _side(sha=row.get("vulnerable_commit")),
           "patched": _side(sha=row.get("patched_commit")), "n_hunks": None, "reason": None,
           "graph_missed": None, "error": None, "n_flows_through_fix": None,
           "n_flows_gone_on_patched": None, "n_flows_unresolved": None, "fields": None}
    v, p = row.get("vulnerable_commit"), row.get("patched_commit")
    if not (v and p):
        rec["error"] = "row has no vulnerable_commit/patched_commit pair"
        return rec
    try:
        mdir = mirror_dir_for(row["repo_url"], mirror_root)
        os.makedirs(os.path.dirname(os.path.abspath(mdir)), exist_ok=True)
        _mirror(row["repo_url"], mdir)
    except Exception as e:
        rec["error"] = f"mirror: {e.__class__.__name__}: {e}"[:4000]
        return rec
    try:
        hs = hunks(mdir, v, p)
    except Exception as e:
        rec["error"] = f"fix hunks: {e.__class__.__name__}: {e}"[:4000]
        return rec
    rec["n_hunks"] = len(hs)
    for kind, sha in (("vulnerable", v), ("patched", p)):
        rec[kind] = _build_side(mdir, sha, builder=builder, tmp_root=tmp_root, _export=_export)
        if not rec[kind]["ok"]:
            rec["result"] = "build_failed" if rec[kind]["stage"] == "build" else "not_checked"
            rec["error"] = f"{kind}: {rec[kind]['error']}"
            return rec
    try:
        db = open_db()
    except Exception as e:
        rec["error"] = f"graph: {e.__class__.__name__}: {e}"[:4000]
        return rec
    try:
        cp = candidate_paths(db, rec["vulnerable"]["scan_id"], rec["patched"]["scan_id"], hs)
    finally:
        try:
            db.close()
        except Exception:   # noqa: BLE001 -- closing a dead connection changes nothing proposed
            pass
    rec.update(reason=cp.get("reason"), graph_missed=cp.get("graph_missed"), error=cp.get("error"),
               n_flows_through_fix=len(cp.get("flows_through_fix") or []),
               n_flows_gone_on_patched=len(cp.get("flows_gone_on_patched") or []),
               n_flows_unresolved=len(cp.get("flows_unresolved") or []))
    if cp.get("error"):
        rec["result"] = "not_checked" if infra.is_infra_text(cp["error"]) else "query_error"
        return rec
    rec.update(result="proposed", fields=to_manifest_fields(cp))
    return rec


def _preflight() -> list:
    """Why this machine cannot run the driver now (empty = ready): the pre-check's own preflight."""
    from eval import precheck
    return precheck._preflight()


def _orion_commit() -> str:
    from eval.run import git_head
    return git_head(".")


def main(argv=None) -> int:
    from eval import manifest, precheck
    ap = argparse.ArgumentParser(description="E5 path ground truth: build both commits of every manifest "
                                             "row (lm profile) and propose its fix sites, sink and entry points.")
    ap.add_argument("--manifest", default="eval/dataset/manifest.json")
    ap.add_argument("--id", action="append", default=[], help="only this row id (repeatable)")
    ap.add_argument("--write", action="store_true",
                    help="merge each proposed row's fields into the manifest (rows with labelers are never "
                         "touched); without it only the report is written")
    ap.add_argument("--report", default=None,
                    help="where every record goes (default: pathgt_report.json next to the manifest)")
    ap.add_argument("--mirror-root", default=os.path.join("eval", "mirrors", "precheck"),
                    help="bare mirrors, one per repo (the pre-check's layout and default)")
    ap.add_argument("--tmp-root", default=None, help="where trees are exported (default: the system temp dir)")
    args = ap.parse_args(argv)
    data = manifest.load(args.manifest)
    rows = data["repos"]
    unknown = sorted(set(args.id) - {r.get("id") for r in rows})
    if unknown:
        print(f"unknown row id(s): {', '.join(unknown)}", flush=True)
        return 2
    problems = _preflight()
    if problems:   # a machine problem must never be recorded against a row: touch nothing
        print("pathgt not started; this machine is not ready:", flush=True)
        for p in problems:
            print(f"  {p}", flush=True)
        return 1
    report_path = args.report or os.path.join(os.path.dirname(args.manifest) or ".", "pathgt_report.json")
    report = {"manifest": args.manifest, "rows": {}}
    if os.path.exists(report_path):
        with open(report_path) as f:
            report = json.load(f)
    todo = [r for r in rows if not args.id or r.get("id") in args.id]
    commit = _orion_commit()
    results, written = [], []
    for i, row in enumerate(todo, 1):
        stamp = {"orion_commit": commit, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if row.get("labelers"):
            rec = {"result": "skipped_labeled", **stamp,
                   "note": f"row has labelers {row['labelers']}: never overwritten"}
        else:
            print(f"[{i}/{len(todo)}] {row.get('id')}: building both commits", flush=True)
            rec = {**propose_row(row, mirror_root=args.mirror_root, tmp_root=args.tmp_root), **stamp}
        results.append(rec["result"])
        print(f"[{i}/{len(todo)}] {row.get('id')}: {rec['result']}"
              + (f" ({rec.get('reason')})" if rec.get("reason") else "")
              + (f": {rec['error']}" if rec.get("error") else "")[:2000], flush=True)
        report["rows"][row["id"]] = precheck._carry(report["rows"].get(row["id"]), dict(rec))
        report["updated_at"] = stamp["checked_at"]
        precheck._save(report_path, report)
        if args.write and rec["result"] == "proposed" and not row.get("labelers"):
            row.update(rec["fields"])
            row["pathgt"] = {k: rec.get(k) for k in ("result", "reason", "graph_missed", "n_hunks",
                                                     "n_flows_through_fix", "n_flows_gone_on_patched",
                                                     "n_flows_unresolved", "orion_commit", "checked_at")}
            row["pathgt"].update(vulnerable_scan_id=rec["vulnerable"]["scan_id"],
                                 patched_scan_id=rec["patched"]["scan_id"])
            written.append(row["id"])
            precheck._save(args.manifest, data)
    counts = {k: results.count(k) for k in ("proposed", "not_checked", "build_failed", "query_error",
                                             "skipped_labeled")}
    print(f"checked {len(todo)} row(s): " + ", ".join(f"{n} {k}" for k, n in counts.items())
          + f"; records in {report_path}; "
          + (f"fields written for: {', '.join(written) or 'none'}" if args.write
             else "manifest not touched (no --write)"), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
