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
"""
from __future__ import annotations

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

