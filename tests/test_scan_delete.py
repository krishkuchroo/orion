"""Change 4: deleting / counting a scan touches only that scan's nodes, in bounded batches.

Before: persist._clear, GraphDB.clear_scan, GraphDB.node_count and the runtime CLEAR_PROPS all
matched `(n {scan_id:$sid})` with no label -- an AllNodesScan over every scan in the database, in
one transaction. Now: one `MATCH (n:Label {scan_id:$sid})` per label, served by a scan_id index,
deleting LIMIT-sized batches until nothing is left. Live Neo4j, throwaway `test-<uuid>` scans.
"""
from __future__ import annotations

import pytest

from orion import config
from orion.graph import persist, scans
from orion.graph.schema import NODE_KEY
from orion.graphdb import GraphDB
from orion.runtime import writeback


def _ops(plan) -> list[str]:
    out = [plan["operatorType"].split("@")[0]]
    for child in plan.get("children", []):
        out += _ops(child)
    return out


def _plan(driver, cypher: str) -> list[str]:
    with driver.session(database=config.NEO4J_DATABASE) as s:
        return _ops(s.run("EXPLAIN " + cypher, sid="x", scan_id="x", batch=1).consume().plan)


def test_scan_lookups_use_a_scan_id_index(neo4j_driver):
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        scans.ensure_scan_indexes(s)
    statements = [(f"{name}[{label}]", tmpl.format(label=label))
                  for label in scans.SCAN_LABELS
                  for name, tmpl in (("DELETE_BATCH", scans.DELETE_BATCH), ("COUNT", scans.COUNT))]
    statements += [(f"CLEAR_PROPS[{label}]", writeback.CLEAR_PROPS.format(label=label))
                   for label in writeback.RUNTIME_LABELS]
    statements += [(f"UNREACHABLE_EXECUTED[{label}]", writeback.UNREACHABLE_EXECUTED.format(label=label))
                   for label in writeback.RUNTIME_LABELS]
    for name, cypher in statements:
        ops = _plan(neo4j_driver, cypher)
        assert "AllNodesScan" not in ops and "NodeByLabelScan" not in ops, f"{name} plans {ops}"
        assert "NodeIndexSeek" in ops, f"{name} plans {ops}"


def _seed(driver, sid: str) -> None:
    """A tiny scan with a graph edge, a semantic Chunk and a scan record."""
    with driver.session(database=config.NEO4J_DATABASE) as s:
        s.run("CREATE (m:CpgMethod {scan_id:$sid, full_name:'m'})"
              "-[:CONTAINS_CALL {scan_id:$sid}]->(:CpgCall {scan_id:$sid, uid:'c'}), "
              "(:Chunk {scan_id:$sid, file:'f', span:'1-2', text:'t'}), "
              "(:OrionScan {scan_id:$sid, status:'complete'})", sid=sid).consume()


def _labels(driver, sid: str) -> dict[str, int]:
    """Every node carrying `sid`, by label -- label-less on purpose (this is the test's oracle)."""
    with driver.session(database=config.NEO4J_DATABASE) as s:
        return {r["l"]: r["n"] for r in s.run(
            "MATCH (n {scan_id:$sid}) UNWIND labels(n) AS l RETURN l, count(*) AS n", sid=sid)}


def test_clear_scan_removes_everything_and_spares_the_neighbour(neo4j_driver, scan_ids):
    a, b = scan_ids("a"), scan_ids("b")
    _seed(neo4j_driver, a)
    _seed(neo4j_driver, b)
    db = GraphDB()
    try:
        db.clear_scan(a)
    finally:
        db.close()
    assert _labels(neo4j_driver, a) == {}
    assert _labels(neo4j_driver, b) == {"CpgMethod": 1, "CpgCall": 1, "Chunk": 1, "OrionScan": 1}


def test_persist_clear_spares_chunk_and_scan_record(neo4j_driver, scan_ids):
    b = scan_ids("b")
    _seed(neo4j_driver, b)
    persist._clear(neo4j_driver, b)
    assert _labels(neo4j_driver, b) == {"Chunk": 1, "OrionScan": 1}


def test_delete_reports_counts_across_many_batches(neo4j_driver, scan_ids):
    a = scan_ids("a")
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        s.run("UNWIND range(0, 24999) AS i CREATE (:CpgCall {scan_id:$sid, uid:toString(i)})",
              sid=a).consume()
        s.run("MATCH (x:CpgCall {scan_id:$sid}) WITH x, toInteger(x.uid) AS i WHERE i > 0 "
              "MATCH (y:CpgCall {scan_id:$sid, uid:toString(i - 1)}) "
              "CREATE (y)-[:FLOWS_TO {scan_id:$sid}]->(x)", sid=a).consume()
    deleted = scans.delete_scan(neo4j_driver, a, ["CpgCall"])
    assert deleted == {"CpgCall": 25000}
    assert _labels(neo4j_driver, a) == {}
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        rels = s.run("MATCH ()-[r:FLOWS_TO {scan_id:$sid}]->() RETURN count(r) AS n", sid=a).single()["n"]
    assert rels == 0


def test_node_count_counts_graph_and_chunks_not_the_record(neo4j_driver, scan_ids):
    a = scan_ids("a")
    _seed(neo4j_driver, a)       # CpgMethod + CpgCall + Chunk (+ the OrionScan record)
    db = GraphDB()
    try:
        assert db.node_count(a) == 3
    finally:
        db.close()


def test_runtime_writeback_clear_and_count_stay_inside_the_scan(neo4j_driver, scan_ids):
    """Guard for the per-label CLEAR_PROPS / UNREACHABLE_EXECUTED rewrite: a re-run clears only this
    scan's runtime props, counts its executed-but-'unreachable' nodes, and leaves a neighbour alone."""
    from orion.runtime.base import WritePlan
    a, b = scan_ids("a"), scan_ids("b")
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        for sid in (a, b):
            s.run("CREATE (:CpgMethod {scan_id:$sid, full_name:'m', reachable_from_entry:false}), "
                  "(:CpgCall {scan_id:$sid, uid:'c1', reachable_from_entry:false}), "
                  "(:CpgCall {scan_id:$sid, uid:'c2', reachable_from_entry:true})", sid=sid).consume()
    hits = WritePlan(call_hits={"c1": 3, "c2": 1}, method_hits={"m": 2})
    assert writeback.apply_plan(b, hits)["unreachable_executed"] == 2
    assert writeback.apply_plan(a, hits)["unreachable_executed"] == 2     # c1 + m
    assert writeback.apply_plan(a, WritePlan())["unreachable_executed"] == 0   # re-run clears a
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        left = {r["sid"]: r["n"] for r in s.run(
            "UNWIND $sids AS sid MATCH (n {scan_id:sid}) WHERE n.executed IS NOT NULL "
            "RETURN sid, count(n) AS n", sids=[a, b])}
    assert left == {b: 3}


def test_every_label_carrying_scan_id_is_in_scan_labels(neo4j_driver):
    """The per-label delete only reaches labels it knows. Every label any node in the database
    carries a scan_id on (38 real scans + whatever tests left) must be one of them."""
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        found = {r["l"] for r in s.run(
            "MATCH (n) WHERE n.scan_id IS NOT NULL UNWIND labels(n) AS l RETURN DISTINCT l")}
    assert found <= set(scans.SCAN_LABELS), f"labels a scan delete would miss: {found - set(scans.SCAN_LABELS)}"
    assert set(NODE_KEY) < set(scans.SCAN_LABELS)
