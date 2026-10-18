"""Input slicing for Orion-LM: CandidateFlows -> path slices (only the path nodes) + a pruned schema.

Every query goes through `tools.run_cypher`, so each labelled node carries `{scan_id:$scan_id}`.
`GraphDB.run_cypher` binds only `scan_id`, so other values are inlined (ints / escaped string literals).
"""
from __future__ import annotations

import json

from orion import strategies
from orion.lm import tools


def _lit(s: str) -> str:
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _rows(res: dict) -> list[dict]:
    if "error" in res:
        raise RuntimeError(res["error"])
    return res["rows"]


def candidate_flows(db, scan_id: str, *, max_flows: int = 50) -> list[dict]:
    n = int(max_flows)
    q = ("MATCH (f:CandidateFlow {scan_id:$scan_id}) "
         "RETURN f.rank AS rank, f.source_uid AS source_uid, f.sink_uid AS sink_uid, "
         "f.sink_category AS sink_category, f.path_uids AS path_uids "
         f"ORDER BY f.rank LIMIT {n}")
    out = []
    for r in _rows(tools.run_cypher(db, scan_id, q, limit=n)):
        raw = r.get("path_uids")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = []
        out.append({"rank": r.get("rank"), "source_uid": r.get("source_uid"),
                    "sink_uid": r.get("sink_uid"), "sink_category": r.get("sink_category"),
                    "path_uids": list(raw or [])})
    return out


def flow_slice(db, scan_id: str, flow: dict) -> dict:
    uids = list(flow.get("path_uids") or [])
    found: dict[str, dict] = {}
    if uids:
        uniq = list(dict.fromkeys(uids))
        q = ("MATCH (c:CpgCall {scan_id:$scan_id}) "
             f"WHERE c.uid IN [{', '.join(_lit(u) for u in uniq)}] "
             "RETURN c.uid AS uid, c.file_path AS file, c.method_full_name AS function, "
             "c.line AS line, c.code AS code")
        for r in _rows(tools.run_cypher(db, scan_id, q, limit=len(uniq))):
            found[r.get("uid")] = r
    nodes = []
    for u in uids:  # path order; uids absent from the graph are skipped
        r = found.get(u)
        if r is not None:
            nodes.append({"file": r.get("file", r.get("file_path")),
                          "function": r.get("function", r.get("method_full_name")),
                          "line": r.get("line"), "code": r.get("code")})
    rank = flow.get("rank")
    return {"flow_id": f"F{rank}", "rank": rank, "sink_category": flow.get("sink_category"),
            "source_uid": flow.get("source_uid"), "sink_uid": flow.get("sink_uid"), "nodes": nodes}


_KEEP_STARTS = (
    "Schema-of-record", "  (:CpgMethod ", "  (:CpgCall ", "  (:EntryPoint ", "  (:CandidateFlow",
    "Edges", "  (:CpgMethod)-[:CONTAINS_CALL]", "  (:CpgCall)-[:RESOLVES_TO]",
    "  (:CpgCall)-[:FLOWS_TO", "  (:EntryPoint)-[:ENTERS_AT]",
    "File attribution", "`code` on CpgCall", "REACHABILITY", "CENTRALITY",
)


_HEADS = ("Schema-of-record", "Edges", "File attribution", "`code` on", "REACHABILITY",
          "CENTRALITY", "RUNTIME", "ATTACKER-CONTROLLED")


def pruned_schema() -> str:
    """Dataflow-relevant lines of strategies.SCHEMA (selected by line, not re-typed). A decision made on a
    head line also covers its continuation lines (those that do not start a new entry)."""
    out: list[str] = []
    keep = False
    for ln in strategies.SCHEMA.split("\n"):
        is_head = ln.startswith(("  (:",) + _HEADS)
        if is_head:
            keep = ln.startswith(_KEEP_STARTS)
        if keep and ln.strip():
            out.append(ln)
    return "\n".join(out) + "\nEvery node pattern must carry {scan_id:$scan_id}."
