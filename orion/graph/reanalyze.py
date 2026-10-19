"""`orion reanalyze`: recompute a scan's CandidateFlows from the graph already in Neo4j -- no Joern.

pathfind reads only CpgCall properties (name, code, centrality), FLOWS_TO (+ arg_index), ENTERS_AT
and CONTAINS_CALL, and all of those are persisted. So after a sink-hint or pathfind change, an
existing scan's flows can be rebuilt without re-parsing the repo: load those into a
`schema.Batch`, run pathfind with the profile the scan was built with (as the CURRENT code defines
it), then replace the scan's :CandidateFlow nodes and nothing else.

Gated like `--scan-id`: the scan needs a complete OrionScan record, and `engine`, when given, must
agree with the recorded profile -- reanalyzing a default scan with the lm sinks would put lm flows
under the default scan_id, the clobbering scan_id_for exists to prevent. The record is 'building'
while the flows are swapped, so a crash in between leaves a scan `--scan-id` refuses.
"""
from __future__ import annotations

from neo4j import GraphDatabase

from .. import config
from . import pathfind, persist, profiles, scans, schema


class ReanalyzeRefused(RuntimeError):
    """The scan can't be reanalyzed as asked (no record, incomplete, or the other engine)."""


_BASE = {p.name: p for p in (profiles.EXPRESS, profiles.GENERIC)}


def profile_named(name: str) -> profiles.Profile:
    """The Profile a recorded profile name stands for, as the current code defines it."""
    base, lm = (name[:-3], True) if name.endswith("+lm") else (name, False)
    if base not in _BASE:
        raise ReanalyzeRefused(f"unknown profile {name!r} in the scan record")
    return profiles.with_lm_sinks(_BASE[base]) if lm else _BASE[base]


def load_batch(session, scan_id: str) -> schema.Batch:
    """The part of a persisted scan pathfind reads, as a Batch (every MATCH scoped to `scan_id`)."""
    b = schema.Batch(scan_id)
    for r in session.run("MATCH (c:CpgCall {scan_id:$sid}) RETURN properties(c) AS p", sid=scan_id):
        b.emit_node("CpgCall", dict(r["p"]))
    for r in session.run("MATCH (a:CpgCall {scan_id:$sid})-[f:FLOWS_TO {scan_id:$sid}]->"
                         "(c:CpgCall {scan_id:$sid}) RETURN a.uid AS a, c.uid AS c, f.arg_index AS i",
                         sid=scan_id):
        props = {"arg_index": r["i"]} if r["i"] is not None else {}
        b.emit_edge("FLOWS_TO", "CpgCall", {"uid": r["a"]}, "CpgCall", {"uid": r["c"]}, props)
    for r in session.run("MATCH (e:EntryPoint {scan_id:$sid})-[:ENTERS_AT]->(m:CpgMethod {scan_id:$sid}) "
                         "RETURN e.uid AS e, m.full_name AS m", sid=scan_id):
        b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": r["e"]}, "CpgMethod", {"full_name": r["m"]})
    for r in session.run("MATCH (m:CpgMethod {scan_id:$sid})-[:CONTAINS_CALL]->(c:CpgCall {scan_id:$sid}) "
                         "RETURN m.full_name AS m, c.uid AS c", sid=scan_id):
        b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": r["m"]}, "CpgCall", {"uid": r["c"]})
    return b


def _check(scan_id: str, engine: str | None) -> dict:
    rec = scans.get_record(scan_id)
    if rec is None:
        raise ReanalyzeRefused(f"scan {scan_id} has no OrionScan record (built before scan records "
                               "existed); rebuild it with: orion scan <repo>")
    if rec.get("status") != scans.COMPLETE:
        raise ReanalyzeRefused(f"scan {scan_id} is incomplete (status {rec.get('status')!r}); rebuild it "
                               "with: orion scan <repo>")
    recorded = rec.get("profile") or ""
    if engine is not None and (engine == "lm") != recorded.endswith("+lm"):
        raise ReanalyzeRefused(f"scan {scan_id} was built with profile {recorded!r}, which does not match "
                               f"--engine {engine}; build that engine's scan with: orion scan <repo>"
                               + (" --engine lm --model <path>" if engine == "lm" else ""))
    return rec


def reanalyze(scan_id: str, engine: str | None = None) -> dict:
    """Replace `scan_id`'s CandidateFlows with a fresh pathfind over its persisted call graph.
    Returns {"scan_id", "profile", "removed", "written", "pathfind"}."""
    rec = _check(scan_id, engine)
    profile = profile_named(rec.get("profile") or "")
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            batch = load_batch(s, scan_id)
        summary = pathfind.pathfind(batch, profile)
        flows = [(label, props) for label, props in batch.nodes if label == "CandidateFlow"]
        scans.set_status(scan_id, scans.BUILDING)
        removed = scans.delete_scan(driver, scan_id, ["CandidateFlow"])["CandidateFlow"]
    finally:
        driver.close()
    written = persist.add_nodes(flows)
    counts = dict(rec.get("counts") or {})
    counts["nodes"] = {**counts.get("nodes", {}),
                       "CandidateFlow": written["counts"].get("CandidateFlow", {}).get("written", 0)}
    counts["mismatches"] = counts.get("mismatches", []) + written["mismatches"]
    counts["precompute"] = {**counts.get("precompute", {}), "pathfind": summary}
    scans.mark_complete(scan_id, counts, reanalyzed_at=scans._now())
    return {"scan_id": scan_id, "profile": profile.name, "removed": removed,
            "written": counts["nodes"]["CandidateFlow"], "pathfind": summary}
