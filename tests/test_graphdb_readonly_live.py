"""@slow live proof that Neo4j itself refuses writes sent through GraphDB.run_cypher (READ access
mode), independently of the text guard; plus the lm path's EXPLAIN query-type check, the per-query
timeout and the bounded fetch, against the real database.

Skips when Neo4j is unreachable. Safety: it creates ONE throwaway node whose scan_id is a fresh
`rotest-<uuid>` and every write it attempts (and the final cleanup) is pinned to that unique scan_id,
so nothing can match another scan's data.

    ./.venv/bin/pytest tests/test_graphdb_readonly_live.py -m slow -v -s
"""
from __future__ import annotations

import time
import uuid

import pytest
from neo4j import GraphDatabase

from orion import config, graphdb
from orion.graphdb import GraphDB
from orion.lm import tools

pytestmark = pytest.mark.slow


@pytest.fixture
def ro_node():
    try:
        drv = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
        drv.verify_connectivity()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")
    sid = f"rotest-{uuid.uuid4().hex}"
    with drv.session(database=config.NEO4J_DATABASE) as s:  # a normal WRITE session, test setup only
        s.run("CREATE (:RoTest {scan_id:$sid, marker:'keep'})", sid=sid).consume()
    db = GraphDB()
    try:
        yield drv, db, sid
    finally:
        db.close()
        with drv.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n:RoTest {scan_id:$sid}) DETACH DELETE n", sid=sid).consume()
        drv.close()


def _intact(drv, sid) -> bool:
    """The throwaway node still exists, unmodified."""
    with drv.session(database=config.NEO4J_DATABASE) as s:
        rec = s.run("MATCH (n:RoTest {scan_id:$sid}) RETURN count(n) AS c, collect(n.pwned) AS p",
                    sid=sid).single()
    return rec["c"] == 1 and rec["p"] == []


def test_text_guard_still_answers_first(ro_node):
    drv, db, sid = ro_node
    out = db.run_cypher(sid, f"MATCH (n {{scan_id:'{sid}'}}) DETACH DELETE n")
    assert "read-only" in out.get("error", ""), out
    assert _intact(drv, sid)


def test_database_refuses_writes_even_when_the_text_guard_misses(ro_node, monkeypatch):
    drv, db, sid = ro_node
    monkeypatch.setattr(graphdb, "_has_write_keyword", lambda q: False)  # simulate a text-guard miss
    writes = [
        f"MATCH (n {{scan_id:'{sid}'}}) DETACH DELETE n",
        f"MATCH (n {{scan_id:'{sid}'}}) SET n.pwned = true",
        "MATCH (n WHERE n.scan_id = $scan_id) WITH n AS `'` DETACH DELETE `'`",  # the reported bypass
    ]
    for q in writes:
        for kw in ({}, {"bounded": True, "timeout": tools.QUERY_TIMEOUT_S}):  # MCP path and lm path
            out = db.run_cypher(sid, q, **kw)
            assert "error" in out, (q, kw, out)
            print(f"\n[neo4j refused] {q}\n  -> {out['error']}")
            assert _intact(drv, sid), q


def test_lm_rejects_a_non_read_plan_before_running_it(ro_node, monkeypatch):
    drv, db, sid = ro_node
    monkeypatch.setattr(graphdb, "_has_write_keyword", lambda q: False)
    monkeypatch.setattr(tools, "_has_write_keyword", lambda q: False)

    class Spy:
        def __init__(self): self.ran = []
        def run_cypher(self, scan_id, query, limit=50, **kw):
            self.ran.append(query)
            return db.run_cypher(scan_id, query, limit, **kw)

    spy = Spy()
    q = "MATCH (n:RoTest {scan_id:$scan_id}) SET n.pwned = true RETURN n"
    out = tools.run_cypher(spy, sid, q)
    print(f"\n[lm query-type check] {q}\n  -> {out}")
    assert "error" in out and "read-only" in out["error"], out
    assert spy.ran == ["EXPLAIN " + q]  # only the plan was requested; the write never executed
    assert _intact(drv, sid)


def test_timeout_stops_a_slow_query(ro_node):
    _, db, sid = ro_node
    t0 = time.monotonic()
    out = db.run_cypher(sid, "UNWIND range(1, 2000000000) AS x WITH x WHERE x % 7 = 0 RETURN count(x) AS c",
                        timeout=1, bounded=True)
    took = time.monotonic() - t0
    print(f"\n[timeout] after {took:.1f}s -> {out}")
    assert "error" in out and "TransactionTimedOut" in out["error"], out
    assert took < 15


def test_lm_timeout_message_is_short_and_actionable(ro_node, monkeypatch):
    _, db, sid = ro_node
    monkeypatch.setattr(tools, "QUERY_TIMEOUT_S", 1)
    q = ("MATCH (c:CpgCall {scan_id:$scan_id}) WITH count(c) AS k "
         "UNWIND range(1, 2000000000) AS x WITH x WHERE x % 7 = 0 RETURN count(x) AS c")
    out = tools.run_cypher(db, sid, q)
    print(f"\n[lm timeout] -> {out}")
    assert "error" in out and "timed out" in out["error"], out


def test_bounded_fetch_returns_at_most_limit(ro_node):
    _, db, sid = ro_node
    out = db.run_cypher(sid, "UNWIND range(1, 100000) AS x RETURN x", limit=5, bounded=True,
                        timeout=tools.QUERY_TIMEOUT_S)
    assert out["rows"] == [{"x": i} for i in range(1, 6)]
    assert out["row_count"] == 5 and out["truncated"] is True and out["query_type"] == "r"


@pytest.mark.parametrize("q", [
    "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code",
    "MATCH (c:CpgCall {scan_id:$scan_id}) WITH c MATCH (c:CpgCall {scan_id:$scan_id})-[:CONTAINS_CALL]-(m) RETURN m",
    "MATCH (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO*1..3]->(m) RETURN m.code",
    "MATCH (c:CpgCall {scan_id:$scan_id})<-[:CONTAINS_CALL]-(m)-[:DEFINED_IN]->(f) RETURN f.file_path",
    "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE NOT (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO]->() RETURN c",
    "MATCH (a:CpgCall {scan_id:$scan_id}) RETURN [(a:CpgCall {scan_id:$scan_id})-->(b) | b.code] AS xs",
    "MATCH p=shortestPath((a:CpgCall {scan_id:$scan_id})-[*..12]-(b:CpgCall {scan_id:$scan_id})) RETURN length(p)",
    "MATCH p=(a:CpgCall {scan_id:$scan_id})-[:FLOWS_TO*1..4]->(b) WHERE any(x IN nodes(p) WHERE x.line > 0) RETURN p",
])
def test_rule_following_queries_are_valid_cypher(ro_node, q):
    """The forms the model is told to write must parse and run on the real Neo4j 5.26."""
    _, db, sid = ro_node
    out = tools.run_cypher(db, sid, q)
    assert "rows" in out, out
