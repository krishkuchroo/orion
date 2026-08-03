"""Item 1: entry-point reachability pruning.

Token-free, infra-free tests for `graph.reachability.tag_reachability` -- the build-time BFS that
stamps `reachable_from_entry` / `hop_distance` onto every CpgMethod/CpgCall in a `schema.Batch`.
Everything runs on a synthetic in-memory batch (no Neo4j, no Joern), mirroring
`test_persist_chunked._synthetic_batch`.
"""
from __future__ import annotations

from orion.graph import reachability, schema


def _synthetic_batch(sid: str = "t") -> schema.Batch:
    """A tiny graph with one reachable chain, one data-flow hop, and one disconnected orphan.

      EntryPoint -ENTERS_AT-> entry(method,0)
      entry -CONTAINS_CALL-> c1(call,1)
      c1 -RESOLVES_TO-> helper(method,2)
      helper -CONTAINS_CALL-> c2(call,3)
      c1 -FLOWS_TO-> c3(call,2)            (data-flow reach, independent of the call chain)
      orphan(method,-1) -CONTAINS_CALL-> c9(call,-1)   (no entry can reach it)
    """
    b = schema.Batch(sid)
    for full in ("entry", "helper", "orphan"):
        b.emit_node("CpgMethod", {"full_name": full, "name": full, "is_external": False})
    for uid in ("c1", "c2", "c3", "c9"):
        b.emit_node("CpgCall", {"uid": uid, "name": uid, "code": uid,
                                "method_full_name": "m", "file_path": "f.js", "line": 0, "column": 0})
    b.emit_node("EntryPoint", {"uid": "e1", "kind": "http", "method_full_name": "entry",
                               "exposure": "exposed"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "e1"}, "CpgMethod", {"full_name": "entry"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "entry"}, "CpgCall", {"uid": "c1"})
    b.emit_edge("RESOLVES_TO", "CpgCall", {"uid": "c1"}, "CpgMethod", {"full_name": "helper"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "helper"}, "CpgCall", {"uid": "c2"})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c1"}, "CpgCall", {"uid": "c3"}, {"arg_index": 0})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "orphan"}, "CpgCall", {"uid": "c9"})
    return b


def _props(batch: schema.Batch, label: str, key_prop: str, key_val: str) -> dict:
    for lbl, props in batch.nodes:
        if lbl == label and props.get(key_prop) == key_val:
            return props
    raise AssertionError(f"no {label} with {key_prop}={key_val}")


def test_hop_distances_and_reachable_set():
    b = _synthetic_batch()
    summary = reachability.tag_reachability(b)

    expected = {
        ("CpgMethod", "entry"): 0,
        ("CpgCall", "c1"): 1,
        ("CpgMethod", "helper"): 2,
        ("CpgCall", "c2"): 3,
        ("CpgCall", "c3"): 2,       # reached via FLOWS_TO from c1
    }
    key = {"CpgMethod": "full_name", "CpgCall": "uid"}
    for (label, ident), hop in expected.items():
        p = _props(b, label, key[label], ident)
        assert p["reachable_from_entry"] is True
        assert p["hop_distance"] == hop

    # summary counts: 3 methods total (2 reached), 4 calls total (3 reached)
    assert summary == {"reached_methods": 2, "reached_calls": 3,
                       "total_methods": 3, "total_calls": 4}


def test_orphan_is_unreached():
    b = _synthetic_batch()
    reachability.tag_reachability(b)
    for label, kp, kv in (("CpgMethod", "full_name", "orphan"), ("CpgCall", "uid", "c9")):
        p = _props(b, label, kp, kv)
        assert p["reachable_from_entry"] is False
        assert p["hop_distance"] == -1


def test_no_entrypoints_defaults_everything_unreached():
    b = schema.Batch("t")
    b.emit_node("CpgMethod", {"full_name": "m", "name": "m", "is_external": False})
    b.emit_node("CpgCall", {"uid": "c", "name": "c", "code": "c"})
    summary = reachability.tag_reachability(b)
    assert summary["reached_methods"] == 0 and summary["reached_calls"] == 0
    for _label, props in b.nodes:
        assert props["reachable_from_entry"] is False
        assert props["hop_distance"] == -1


def test_idempotent():
    b1 = _synthetic_batch()
    reachability.tag_reachability(b1)
    once = [(lbl, dict(p)) for lbl, p in b1.nodes]

    b2 = _synthetic_batch()
    reachability.tag_reachability(b2)
    reachability.tag_reachability(b2)   # run twice
    twice = [(lbl, dict(p)) for lbl, p in b2.nodes]

    assert once == twice


def _chokepoint_batch(sid: str = "t") -> schema.Batch:
    """Two entries funnel through one shared method, which fans out to two sinks. The shared method
    (and its call) sit on every entry->sink path => high betweenness; the sink calls are leaves => 0.

      entryA -CONTAINS_CALL-> cA -RESOLVES_TO-> shared
      entryB -CONTAINS_CALL-> cB -RESOLVES_TO-> shared
      shared -CONTAINS_CALL-> {s1, s2}   (leaf sink calls)
      orphan(method) -CONTAINS_CALL-> c9  (unreachable)
    """
    b = schema.Batch(sid)
    for full in ("entryA", "entryB", "shared", "orphan"):
        b.emit_node("CpgMethod", {"full_name": full, "name": full, "is_external": False})
    for uid in ("cA", "cB", "s1", "s2", "c9"):
        b.emit_node("CpgCall", {"uid": uid, "name": uid, "code": uid, "method_full_name": "m",
                                "file_path": "f.js", "line": 0, "column": 0})
    for e, m in (("eA", "entryA"), ("eB", "entryB")):
        b.emit_node("EntryPoint", {"uid": e, "method_full_name": m})
        b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": e}, "CpgMethod", {"full_name": m})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "entryA"}, "CpgCall", {"uid": "cA"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "entryB"}, "CpgCall", {"uid": "cB"})
    b.emit_edge("RESOLVES_TO", "CpgCall", {"uid": "cA"}, "CpgMethod", {"full_name": "shared"})
    b.emit_edge("RESOLVES_TO", "CpgCall", {"uid": "cB"}, "CpgMethod", {"full_name": "shared"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "shared"}, "CpgCall", {"uid": "s1"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "shared"}, "CpgCall", {"uid": "s2"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "orphan"}, "CpgCall", {"uid": "c9"})
    return b


def test_centrality_chokepoint_beats_leaf():
    b = _chokepoint_batch()
    reachability.tag_reachability(b)
    summary = reachability.tag_centrality(b)

    shared = _props(b, "CpgMethod", "full_name", "shared")["centrality"]
    leaf = _props(b, "CpgCall", "uid", "s1")["centrality"]
    orphan = _props(b, "CpgMethod", "full_name", "orphan")["centrality"]

    assert shared > 0.0            # a real chokepoint
    assert leaf == 0.0             # a leaf sink is on no shortest path's interior
    assert shared > leaf
    assert orphan == 0.0           # unreachable -> centrality 0.0
    assert summary["nodes"] == 7   # 3 reachable methods + 4 reachable calls (orphan/c9 excluded)


def test_centrality_requires_reachability_and_is_idempotent():
    b = _chokepoint_batch()
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    once = {(l, p.get("full_name") or p.get("uid")): p.get("centrality")
            for l, p in b.nodes if l in ("CpgMethod", "CpgCall")}
    reachability.tag_centrality(b)   # run again
    twice = {(l, p.get("full_name") or p.get("uid")): p.get("centrality")
             for l, p in b.nodes if l in ("CpgMethod", "CpgCall")}
    assert once == twice


def test_duplicate_node_key_all_stamped():
    """persist unions duplicate NODE_KEY rows; every duplicate props dict must carry the flag so the
    union is consistent regardless of which wins per-key."""
    b = schema.Batch("t")
    b.emit_node("CpgMethod", {"full_name": "entry", "name": "entry"})
    b.emit_node("CpgMethod", {"full_name": "entry", "name": "entry", "is_external": True})  # dup key
    b.emit_node("EntryPoint", {"uid": "e", "method_full_name": "entry"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "e"}, "CpgMethod", {"full_name": "entry"})
    reachability.tag_reachability(b)
    entry_props = [p for lbl, p in b.nodes if lbl == "CpgMethod"]
    assert len(entry_props) == 2
    for p in entry_props:
        assert p["reachable_from_entry"] is True and p["hop_distance"] == 0
