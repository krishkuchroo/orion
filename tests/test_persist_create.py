"""Item 1: CREATE-not-MERGE persist, with Python-side dedup that reproduces MERGE's collapse.

Token-free, Neo4j-free tests for the pure row-builders `persist._node_rows` and `persist._edge_rows`
and the query builders `_node_create`/`_edge_create`. The end-to-end graph parity (per-label node
counts, per-type edge counts, FLOWS_TO == 217/1075) is guarded by the @slow
test_stream_two_partition_persist_parity on real Neo4j; here we prove the collapse semantics that
make CREATE safe."""
from __future__ import annotations

from orion.graph import persist


# --- nodes: dedup by NODE_KEY, last-write-wins (== MERGE ... SET n += props) --------------------

def test_node_rows_dedup_by_node_key_last_wins():
    # Two CpgFile rows share (scan_id, uid) -> collapse to ONE, last props winning. A distinct uid
    # stays separate. CpgFile NODE_KEY is (scan_id, uid).
    nodes = [
        ("CpgFile", {"scan_id": "s", "uid": "a", "file_path": "old.js"}),
        ("CpgFile", {"scan_id": "s", "uid": "a", "file_path": "new.js"}),   # same key -> wins
        ("CpgFile", {"scan_id": "s", "uid": "b", "file_path": "b.js"}),
    ]
    rows = persist._node_rows(nodes)
    assert set(rows.keys()) == {"CpgFile"}
    props = [r["props"] for r in rows["CpgFile"]]
    assert len(props) == 2                                   # 3 rows -> 2 nodes (a collapsed)
    a = next(p for p in props if p["uid"] == "a")
    assert a["file_path"] == "new.js"                        # last-write-wins, like MERGE's SET


def test_node_rows_groups_per_label():
    nodes = [
        ("CpgFile", {"scan_id": "s", "uid": "f"}),
        ("CpgMethod", {"scan_id": "s", "full_name": "m"}),
    ]
    rows = persist._node_rows(nodes)
    assert set(rows.keys()) == {"CpgFile", "CpgMethod"}
    assert rows["CpgFile"] == [{"props": {"scan_id": "s", "uid": "f"}}]


# --- edges: non-FLOWS_TO dedup by endpoint pattern; FLOWS_TO keeps every parallel arg_index -----

def _edge(rtype, fk, tk, props):
    # matches schema.Batch.edges tuple shape: (rtype, from_label, from_key, to_label, to_key, props)
    return (rtype, "CpgCall", fk, "CpgCall", tk, props)


def test_edge_rows_dedup_non_flows_last_wins():
    # Same RESOLVES_TO endpoints twice -> ONE row, last props winning (== relationship MERGE).
    edges = [
        _edge("RESOLVES_TO", {"scan_id": "s", "uid": "a"}, {"scan_id": "s", "uid": "b"}, {"v": 1}),
        _edge("RESOLVES_TO", {"scan_id": "s", "uid": "a"}, {"scan_id": "s", "uid": "b"}, {"v": 2}),
        _edge("RESOLVES_TO", {"scan_id": "s", "uid": "a"}, {"scan_id": "s", "uid": "c"}, {"v": 9}),
    ]
    out = persist._edge_rows(edges)
    (sig,) = list(out.keys())
    assert sig[0] == "RESOLVES_TO"
    rows = out[sig]
    assert len(rows) == 2                                    # (a->b) collapsed, (a->c) kept
    ab = next(r for r in rows if r["tk"]["uid"] == "b")
    assert ab["props"]["v"] == 2                             # last-write-wins


def test_edge_rows_flows_to_keeps_parallel_arg_index():
    # sink(x, x): two FLOWS_TO between the same call pair differing only by arg_index -> BOTH survive.
    edges = [
        _edge("FLOWS_TO", {"scan_id": "s", "uid": "x"}, {"scan_id": "s", "uid": "y"}, {"arg_index": 0}),
        _edge("FLOWS_TO", {"scan_id": "s", "uid": "x"}, {"scan_id": "s", "uid": "y"}, {"arg_index": 1}),
    ]
    out = persist._edge_rows(edges)
    (sig,) = list(out.keys())
    assert sig[0] == "FLOWS_TO"
    rows = out[sig]
    assert len(rows) == 2                                    # NOT deduped
    assert {r["props"]["arg_index"] for r in rows} == {0, 1}


def test_edge_rows_preserves_first_seen_sig_order():
    edges = [
        _edge("CONTAINS_CALL", {"scan_id": "s", "uid": "a"}, {"scan_id": "s", "uid": "b"}, {}),
        _edge("FLOWS_TO", {"scan_id": "s", "uid": "c"}, {"scan_id": "s", "uid": "d"}, {"arg_index": 0}),
    ]
    out = persist._edge_rows(edges)
    assert [sig[0] for sig in out.keys()] == ["CONTAINS_CALL", "FLOWS_TO"]


# --- query builders emit CREATE (not MERGE) ----------------------------------------------------

def test_query_builders_use_create():
    nq = persist._node_create("CpgFile")
    assert "CREATE (n:`CpgFile`)" in nq and "MERGE" not in nq
    eq = persist._edge_create("RESOLVES_TO", "CpgCall", "CpgMethod", ("scan_id", "uid"),
                              ("scan_id", "full_name"))
    assert "CREATE (a)-[r:`RESOLVES_TO`]->(b)" in eq and "MERGE" not in eq
    assert "MATCH (a:`CpgCall`" in eq and "MATCH (b:`CpgMethod`" in eq   # endpoints still index-matched
