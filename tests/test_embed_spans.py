"""Item 4: overlap persist with the semantic index, by reading code spans from the in-memory batch.

`embed._spans_from_batch` must reproduce `embed._spans_from_graph` exactly -- otherwise the
concurrent (batch-fed) index would chunk differently from the old serial (graph-fed) one. Two tests:
  - pure: the dedup/filter/order semantics on a hand-built batch (no Neo4j, no model).
  - Neo4j-backed (skips if the DB is down): build NodeGoat capturing the batch via build's on_batch
    hook, then assert the batch-derived spans EQUAL the graph-derived spans for the persisted scan.
"""
from __future__ import annotations

import pytest

from orion import embed
from orion.graph import schema


def test_spans_from_batch_dedup_filter_and_order():
    b = schema.Batch("s")
    # duplicate full_name -> last-wins (mirrors persist's NODE_KEY collapse): (a.js, 5) survives
    b.emit_node("CpgMethod", {"full_name": "a.f", "name": "f", "file_path": "z.js", "line": 10})
    b.emit_node("CpgMethod", {"full_name": "a.f", "name": "f", "file_path": "a.js", "line": 5})
    # no file_path/line -> filtered out (matches the graph query's WHERE ... IS NOT NULL)
    b.emit_node("CpgMethod", {"full_name": "b.g", "name": "g"})
    # a method that survives and sorts after a.f by (file_path, line)
    b.emit_node("CpgMethod", {"full_name": "c.h", "name": "h", "file_path": "z.js", "line": 3})
    b.emit_node("CpgFile", {"uid": "u1", "file_path": "z.js"})
    b.emit_node("CpgFile", {"uid": "u2", "file_path": "a.js"})
    b.emit_node("CpgFile", {"uid": "u3", "file_path": "a.js"})   # duplicate path -> distinct

    methods, files = embed._spans_from_batch(b)
    assert files == ["a.js", "z.js"]                            # distinct + ordered
    assert methods == [
        {"full_name": "a.f", "file_path": "a.js", "line": 5},   # deduped to last, ordered first
        {"full_name": "c.h", "file_path": "z.js", "line": 3},
    ]                                                           # b.g filtered (no span)


def test_spans_from_batch_matches_graph_query():
    """The item-4 correctness guarantee: batch-derived spans == graph-derived spans on a real build."""
    from neo4j import GraphDatabase
    from orion import config, graph_build
    from orion.graphdb import GraphDB
    try:
        db = GraphDB()
        if not db.ping():
            pytest.skip("Neo4j not reachable")
        db.close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")

    captured: dict = {}
    scan_id = graph_build.build("fixtures/NodeGoat", None, None,
                                on_batch=lambda batch: captured.__setitem__("batch", batch))
    assert "batch" in captured, "build must invoke on_batch with the normalized batch"

    drv = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with drv.session(database=config.NEO4J_DATABASE) as s:
            graph_spans = embed._spans_from_graph(s, scan_id)
    finally:
        drv.close()
    batch_spans = embed._spans_from_batch(captured["batch"])
    assert batch_spans == graph_spans, "batch-derived spans must match the persisted-graph query"
