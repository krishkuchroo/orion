"""Item 2: source->sink pathfinding.

Token-free, infra-free tests for `graph.pathfind.pathfind` -- the build-time BFS that emits ranked
`:CandidateFlow` nodes over the in-memory `schema.Batch`. Uses the shipped EXPRESS profile for the
sink vocabulary (code_exec: eval/Function/exec/execSync; log: log; ...).
"""
from __future__ import annotations

import json

from orion.graph import pathfind, profiles, reachability, schema


def _batch(sid: str = "t") -> schema.Batch:
    """One entry method whose source call taints two sinks (a high-severity eval chain and a
    low-severity log), a self-loop call that is itself an exec sink, and a harmless dead-end.

      EntryPoint -> handler
      handler -CONTAINS_CALL-> c_src, c_loop
      c_src -FLOWS_TO-> c_mid -FLOWS_TO-> c_sink(eval)   (code_exec, path len 3)
      c_src -FLOWS_TO-> c_log(log)                       (log, path len 2)
      c_src -FLOWS_TO-> c_dead(harmless)                 (no sink -> no flow)
      c_loop -FLOWS_TO-> c_loop (self-loop; exec sink)   (code_exec, path len 1, source==sink)
    """
    b = schema.Batch(sid)
    b.emit_node("CpgMethod", {"full_name": "handler", "name": "handler", "is_external": False})
    calls = {
        "c_src": ("read", "req.body.x"),
        "c_mid": ("sanitize", "sanitize(x)"),
        "c_sink": ("eval", "eval(x)"),
        "c_log": ("log", "logger.log(x)"),
        "c_dead": ("harmless", "noop()"),
        "c_loop": ("exec", "exec(y)"),
    }
    for uid, (name, code) in calls.items():
        b.emit_node("CpgCall", {"uid": uid, "name": name, "code": code,
                                "method_full_name": "handler", "file_path": "h.js", "line": 1, "column": 0})
    b.emit_node("EntryPoint", {"uid": "e", "method_full_name": "handler"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "e"}, "CpgMethod", {"full_name": "handler"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "handler"}, "CpgCall", {"uid": "c_src"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "handler"}, "CpgCall", {"uid": "c_loop"})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c_src"}, "CpgCall", {"uid": "c_mid"}, {"arg_index": 0})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c_mid"}, "CpgCall", {"uid": "c_sink"}, {"arg_index": 0})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c_src"}, "CpgCall", {"uid": "c_log"}, {"arg_index": 0})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c_src"}, "CpgCall", {"uid": "c_dead"}, {"arg_index": 0})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "c_loop"}, "CpgCall", {"uid": "c_loop"}, {"arg_index": 0})
    return b


def _flows(batch: schema.Batch) -> list[dict]:
    return [p for label, p in batch.nodes if label == "CandidateFlow"]


def test_emits_expected_candidate_flows():
    b = _batch()
    summary = pathfind.pathfind(b, profiles.EXPRESS)
    flows = _flows(b)

    assert summary == {"sources": 2, "sinks": 3, "flows": 3}
    assert len(flows) == 3

    by_sink = {f["sink_uid"]: f for f in flows}
    # the eval chain: full tainted path source->mid->sink, classified code_exec
    eval_flow = by_sink["c_sink"]
    assert eval_flow["source_uid"] == "c_src"
    assert eval_flow["sink_category"] == "code_exec"
    assert json.loads(eval_flow["path_uids"]) == ["c_src", "c_mid", "c_sink"]

    # the log sink is low severity
    assert by_sink["c_log"]["sink_category"] == "log"

    # the self-loop exec: source == sink, single-node path
    loop_flow = by_sink["c_loop"]
    assert loop_flow["source_uid"] == "c_loop"
    assert json.loads(loop_flow["path_uids"]) == ["c_loop"]

    # the harmless dead-end is never a sink
    assert "c_dead" not in by_sink


def test_ranking_puts_high_severity_first():
    b = _batch()
    pathfind.pathfind(b, profiles.EXPRESS)
    flows = {f["sink_uid"]: f["rank"] for f in _flows(b)}
    # both code_exec sinks (eval, exec self-loop) outrank the log sink
    assert flows["c_sink"] < flows["c_log"]
    assert flows["c_loop"] < flows["c_log"]
    # ranks are a dense 0..n-1
    assert sorted(flows.values()) == [0, 1, 2]


def test_no_profile_emits_nothing():
    b = _batch()
    summary = pathfind.pathfind(b, None)
    assert summary["flows"] == 0
    assert _flows(b) == []


def test_full_precompute_chain_is_consistent():
    """reachability -> centrality -> pathfind runs end to end and the candidate-flow uids are
    deterministic across two identical batches."""
    b1 = _batch()
    reachability.tag_reachability(b1)
    reachability.tag_centrality(b1)
    pathfind.pathfind(b1, profiles.EXPRESS)

    b2 = _batch()
    reachability.tag_reachability(b2)
    reachability.tag_centrality(b2)
    pathfind.pathfind(b2, profiles.EXPRESS)

    assert {f["uid"] for f in _flows(b1)} == {f["uid"] for f in _flows(b2)}
    assert len(_flows(b1)) == 3
