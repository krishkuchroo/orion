"""The one additive writer for the runtime stage. The only impure DB module here.

Mirrors embed.py exactly: its OWN neo4j driver (not the read-only GraphDB), additive SET/CREATE, and
its OWN idempotent per-scan clear. It writes NO NODE_KEY label -- only `executed`/`hit_count` props on
existing CpgCall/CpgMethod nodes and a new OBSERVED_CALL edge between existing CpgMethod nodes. So
persist._clear (label-scoped to NODE_KEY.keys()) never touches it, and the static graph -- and its
217/1075 FLOWS_TO parity -- stays byte-for-byte identical.

`build_static_pairs` and the plan come from correlate.py (pure). Everything here is I/O.
"""
from __future__ import annotations

from neo4j import GraphDatabase

from .. import config
from .base import WritePlan

# The stage's write vocabulary, as constants so a token-free test can assert it only ever DELETEs
# OBSERVED_CALL relationships and REMOVEs runtime props -- never DELETEs a node and never names a
# NODE_KEY label in a destructive clause (that is the mechanical guarantee the static graph, and its
# 217/1075 FLOWS_TO parity, cannot be perturbed).
CLEAR_EDGES = "MATCH (:CpgMethod {scan_id:$scan_id})-[r:OBSERVED_CALL]->() DELETE r"
CLEAR_PROPS = ("MATCH (n {scan_id:$scan_id}) WHERE n.executed IS NOT NULL "
               "REMOVE n.executed, n.hit_count")
SET_CALLS = ("UNWIND $rows AS row MATCH (c:CpgCall {scan_id:$scan_id, uid:row.uid}) "
             "SET c.executed = true, c.hit_count = row.hits")
SET_METHODS = ("UNWIND $rows AS row MATCH (m:CpgMethod {scan_id:$scan_id, full_name:row.full_name}) "
               "SET m.executed = true, m.hit_count = row.hits")
CREATE_EDGES = ("UNWIND $rows AS row "
                "MATCH (a:CpgMethod {scan_id:$scan_id, full_name:row.a}) "
                "MATCH (b:CpgMethod {scan_id:$scan_id, full_name:row.b}) "
                "CREATE (a)-[:OBSERVED_CALL {scan_id:$scan_id, hits:row.hits}]->(b)")


def _clear(session, scan_id: str) -> None:
    """Remove any prior runtime enrichment for this scan (idempotent re-run)."""
    session.run(CLEAR_EDGES, scan_id=scan_id)
    session.run(CLEAR_PROPS, scan_id=scan_id)


def static_pairs(session, scan_id: str) -> set[tuple[str, str]]:
    """The set of method→method pairs the STATIC graph already links (CONTAINS_CALL+RESOLVES_TO).
    Used to score which OBSERVED_CALL edges are novel (the J metric). Read-only."""
    rows = session.run(
        "MATCH (a:CpgMethod {scan_id:$scan_id})-[:CONTAINS_CALL]->(:CpgCall)"
        "-[:RESOLVES_TO]->(b:CpgMethod {scan_id:$scan_id}) "
        "RETURN DISTINCT a.full_name AS a, b.full_name AS b", scan_id=scan_id)
    return {(r["a"], r["b"]) for r in rows}


def unreachable_executed(session, scan_id: str) -> int:
    """Count nodes runtime executed that the static BFS marked reachable_from_entry=false (the U
    metric): guesses overturned with ground truth. Read after writeback stamps `executed`."""
    rec = session.run(
        "MATCH (n {scan_id:$scan_id}) WHERE n.executed = true AND n.reachable_from_entry = false "
        "RETURN count(n) AS u", scan_id=scan_id).single()
    return int(rec["u"]) if rec else 0


def apply_plan(scan_id: str, plan: WritePlan) -> dict:
    """Write `plan` into the scan partition and return a metric dict. Own driver, closed in finally."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            _clear(s, scan_id)
            if plan.call_hits:
                s.run(SET_CALLS, scan_id=scan_id,
                      rows=[{"uid": u, "hits": h} for u, h in plan.call_hits.items()])
            if plan.method_hits:
                s.run(SET_METHODS, scan_id=scan_id,
                      rows=[{"full_name": f, "hits": h} for f, h in plan.method_hits.items()])
            if plan.edges:
                s.run(CREATE_EDGES, scan_id=scan_id,
                      rows=[{"a": a, "b": b, "hits": h} for (a, b), h in plan.edges.items()])
            pairs = static_pairs(s, scan_id)
            novel = sum(1 for pair in plan.edges if pair not in pairs)
            u = unreachable_executed(s, scan_id)
        return {
            "calls_marked": len(plan.call_hits),
            "methods_marked": len(plan.method_hits),
            "observed_edges": len(plan.edges),
            "novel_edges": novel,
            "unreachable_executed": u,
            "dropped": plan.dropped,
        }
    finally:
        driver.close()
