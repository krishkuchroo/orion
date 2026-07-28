"""Items 3 + 5: chunked + parallel persist, with a label-scoped clear.

Two layers:
  - pure/Neo4j-free: `_chunks`, `_node_jobs`, `_edge_jobs` split rows into bounded write jobs.
  - Neo4j-backed (skips if the DB is down, like test_persist_indexes): a synthetic batch persisted
    with a TINY chunk size at BOTH concurrency 1 (sequential) and 4 (parallel) must yield the same
    deduped graph -- node dedup last-wins, non-FLOWS_TO edge collapse, parallel-arg_index FLOWS_TO
    preserved -- proving chunking/parallelism don't corrupt the load. Plus: the label-scoped clear
    spares a :Chunk node carrying the same scan_id (the item-4 overlap-safety property).
"""
from __future__ import annotations

import pytest
from neo4j import GraphDatabase

from orion import config
from orion.graph import persist, schema


# --- pure: chunking --------------------------------------------------------------------------

def test_chunks_splits_and_floors_size():
    assert list(persist._chunks([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]
    assert list(persist._chunks([1, 2, 3], 10)) == [[1, 2, 3]]     # size >= len -> one chunk
    assert list(persist._chunks([], 5)) == []                       # empty -> no chunks
    assert list(persist._chunks([1, 2], 0)) == [[1], [2]]           # size floored to 1


def test_node_jobs_chunk_to_config_size(monkeypatch):
    monkeypatch.setattr(config, "PERSIST_CHUNK_SIZE", 2)
    nodes = [("CpgCall", {"scan_id": "s", "uid": f"c{i}"}) for i in range(5)]
    jobs = persist._node_jobs(nodes)
    # 5 CpgCall rows / chunk 2 -> 3 jobs, all CREATE, total rows preserved
    assert len(jobs) == 3
    assert all("CREATE (n:`CpgCall`)" in cypher for cypher, _ in jobs)
    assert sum(len(rows) for _, rows in jobs) == 5


def test_edge_jobs_chunk_to_config_size(monkeypatch):
    monkeypatch.setattr(config, "PERSIST_CHUNK_SIZE", 2)
    edges = [("FLOWS_TO", "CpgCall", {"scan_id": "s", "uid": "a"},
              "CpgCall", {"scan_id": "s", "uid": f"b{i}"}, {"arg_index": i}) for i in range(5)]
    jobs = persist._edge_jobs(edges)
    assert len(jobs) == 3                                           # 5 FLOWS_TO rows / chunk 2
    assert all("CREATE (a)-[r:`FLOWS_TO`]->(b)" in cypher for cypher, _ in jobs)
    assert sum(len(rows) for _, rows in jobs) == 5


# --- Neo4j-backed: chunked + parallel load parity + label-scoped clear ------------------------

def _drv_or_skip():
    try:
        drv = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
        drv.verify_connectivity()
        return drv
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")


def _synthetic_batch(sid: str) -> schema.Batch:
    b = schema.Batch(sid)
    for i in range(12):
        b.emit_node("CpgCall", {"uid": f"c{i}", "name": "n", "code": f"orig{i}",
                                "method_full_name": "m", "file_path": "f.js", "line": i, "column": 0})
    # duplicate NODE_KEY (c0) -> collapses to one, last props winning
    b.emit_node("CpgCall", {"uid": "c0", "name": "n", "code": "DUP",
                            "method_full_name": "m", "file_path": "f.js", "line": 0, "column": 0})
    b.emit_node("CpgMethod", {"full_name": "m", "name": "m", "is_external": False})
    # duplicate non-FLOWS_TO edge -> collapses to one
    b.emit_edge("RESOLVES_TO", "CpgCall", {"uid": "c0"}, "CpgMethod", {"full_name": "m"}, {})
    b.emit_edge("RESOLVES_TO", "CpgCall", {"uid": "c0"}, "CpgMethod", {"full_name": "m"}, {})
    # two FLOWS_TO between the same pair differing only by arg_index -> BOTH survive
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c0"}, "CpgCall", {"uid": "c1"}, {"arg_index": 0})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c0"}, "CpgCall", {"uid": "c1"}, {"arg_index": 1})
    return b


@pytest.mark.parametrize("concurrency", [1, 4])
def test_chunked_persist_parity_seq_and_parallel(monkeypatch, concurrency):
    """Tiny chunks + both concurrencies must produce the identical deduped graph."""
    sid = f"test-chunk-{concurrency}"
    monkeypatch.setattr(config, "PERSIST_CHUNK_SIZE", 3)     # force many chunks over 12 nodes
    monkeypatch.setattr(config, "PERSIST_CONCURRENCY", concurrency)
    drv = _drv_or_skip()
    try:
        persist.persist(_synthetic_batch(sid))
        with drv.session(database=config.NEO4J_DATABASE) as s:
            calls = s.run("MATCH (c:CpgCall {scan_id:$s}) RETURN count(c) AS n", s=sid).single()["n"]
            methods = s.run("MATCH (m:CpgMethod {scan_id:$s}) RETURN count(m) AS n", s=sid).single()["n"]
            resolves = s.run("MATCH (:CpgCall {scan_id:$s})-[r:RESOLVES_TO]->() RETURN count(r) AS n",
                             s=sid).single()["n"]
            flows = persist.flows_count(sid)
            c0_code = s.run("MATCH (c:CpgCall {scan_id:$s, uid:'c0'}) RETURN c.code AS code",
                            s=sid).single()["code"]
        assert calls == 12          # c0 duplicate collapsed
        assert methods == 1
        assert resolves == 1        # duplicate RESOLVES_TO collapsed
        assert flows == 2           # both arg_index FLOWS_TO survived
        assert c0_code == "DUP"     # last-write-wins on the duplicate node
    finally:
        with drv.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n {scan_id:$s}) DETACH DELETE n", s=sid)
        drv.close()


def test_persist_unions_node_props_end_to_end():
    """Regression for the review's finding #1: two CpgMethod rows share a NODE_KEY (full_name) but
    only the FIRST carries file_path/line. MERGE ... SET n += props would union them; the persisted
    node MUST retain file_path/line (a plain last-row replace would drop them)."""
    sid = "test-chunk-union"
    drv = _drv_or_skip()
    try:
        b = schema.Batch(sid)
        b.emit_node("CpgMethod", {"full_name": "foo", "name": "foo", "file_path": "a.js", "line": 7})
        b.emit_node("CpgMethod", {"full_name": "foo", "name": "foo", "is_external": True})  # no span
        persist.persist(b)
        with drv.session(database=config.NEO4J_DATABASE) as s:
            rec = s.run("MATCH (m:CpgMethod {scan_id:$s, full_name:'foo'}) "
                        "RETURN m.file_path AS fp, m.line AS ln, m.is_external AS ext",
                        s=sid).single()
            n = s.run("MATCH (m:CpgMethod {scan_id:$s}) RETURN count(m) AS n", s=sid).single()["n"]
        assert n == 1, "the two same-full_name rows must collapse to one node"
        assert rec["fp"] == "a.js" and rec["ln"] == 7, "unioned span props must survive the collapse"
        assert rec["ext"] is True, "props from the later row must also be present (union)"
    finally:
        with drv.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n {scan_id:$s}) DETACH DELETE n", s=sid)
        drv.close()


def test_clear_is_label_scoped_and_spares_chunk_nodes():
    """persist's clear must delete only the graph-label nodes, leaving a :Chunk with the same
    scan_id intact -- the property that lets embed run concurrently with persist (item 4)."""
    sid = "test-chunk-labelscope"
    drv = _drv_or_skip()
    try:
        with drv.session(database=config.NEO4J_DATABASE) as s:
            s.run("CREATE (c:Chunk {scan_id:$s, file:'f', span:'1-2', text:'t'})", s=sid)
        persist.persist(_synthetic_batch(sid))    # its clear must NOT touch the Chunk
        with drv.session(database=config.NEO4J_DATABASE) as s:
            chunks = s.run("MATCH (c:Chunk {scan_id:$s}) RETURN count(c) AS n", s=sid).single()["n"]
            calls = s.run("MATCH (c:CpgCall {scan_id:$s}) RETURN count(c) AS n", s=sid).single()["n"]
        assert chunks == 1, "label-scoped clear wrongly deleted the semantic Chunk node"
        assert calls == 12, "graph nodes should still be loaded"
    finally:
        with drv.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n {scan_id:$s}) DETACH DELETE n", s=sid)
        drv.close()
