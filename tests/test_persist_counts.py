"""Change 2: persist must say what it actually wrote.

An edge is CREATEd by `MATCH (a {key}) MATCH (b {key}) CREATE (a)-[...]->(b)`, which creates nothing
-- and raises nothing -- when an endpoint is missing. These tests persist a batch with one such
edge into a throwaway scan and check the summary, strict mode, and the build's warn event.
"""
from __future__ import annotations

import pytest

from orion import config, graph_build
from orion.graph import persist, schema


def _one_lost_edge(sid: str) -> schema.Batch:
    b = schema.Batch(sid)
    b.emit_node("CpgCall", {"uid": "a"})
    b.emit_node("CpgCall", {"uid": "b"})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "a"}, "CpgCall", {"uid": "b"}, {"arg_index": 1})
    b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "a"}, "CpgCall", {"uid": "missing"}, {"arg_index": 1})
    return b


def _flows_in_db(driver, sid: str) -> int:
    with driver.session(database=config.NEO4J_DATABASE) as s:
        return s.run("MATCH (:CpgCall {scan_id:$sid})-[r:FLOWS_TO]->() RETURN count(r) AS n",
                     sid=sid).single()["n"]


def test_lost_edge_is_counted_in_the_summary(neo4j_driver, scan_ids, monkeypatch):
    monkeypatch.setenv("ORION_PERSIST_STRICT", "0")
    sid = scan_ids()
    summary = persist.persist(_one_lost_edge(sid))
    assert _flows_in_db(neo4j_driver, sid) == 1
    assert summary["counts"]["edges"]["FLOWS_TO"] == {"expected": 2, "written": 1}
    assert summary["counts"]["nodes"]["CpgCall"] == {"expected": 2, "written": 2}
    assert any("FLOWS_TO: expected 2, written 1" in m for m in summary["mismatches"])


def test_lost_edge_fails_in_strict_mode(neo4j_driver, scan_ids, monkeypatch):
    monkeypatch.setenv("ORION_PERSIST_STRICT", "1")
    with pytest.raises(RuntimeError, match="FLOWS_TO: expected 2, written 1"):
        persist.persist(_one_lost_edge(scan_ids()))


def test_build_warns_on_a_lost_edge(neo4j_driver, scan_ids, monkeypatch):
    monkeypatch.setenv("ORION_PERSIST_STRICT", "0")
    lossy = persist.persist(_one_lost_edge(scan_ids("lossy")))
    ev = graph_build._persist_warning(lossy)
    assert ev is not None and ev["phase"] == "build" and ev["event"] == "warn"
    assert "FLOWS_TO: expected 2, written 1" in ev["detail"]

    clean = schema.Batch(scan_ids("clean"))
    clean.emit_node("CpgCall", {"uid": "a"})
    assert graph_build._persist_warning(persist.persist(clean)) is None


@pytest.mark.slow
def test_nodegoat_persists_every_row(neo4j_driver, scan_ids):
    from pathlib import Path
    from orion.graph import joern_adapter, pathfind, profiles, reachability, stream_build
    import tempfile
    if not Path("fixtures/NodeGoat/cpg.bin").exists():
        pytest.skip("NodeGoat cpg.bin not present")
    prof = profiles.select_profile("fixtures/NodeGoat")
    env = stream_build.build_envelope("fixtures/NodeGoat/cpg.bin", tempfile.mkdtemp(), prof)
    b = joern_adapter.normalize(env, scan_ids(), language="javascript")
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    pathfind.pathfind(b, prof)
    summary = persist.persist(b)
    assert summary["mismatches"] == []
    assert summary["counts"]["edges"]["FLOWS_TO"] == {"expected": 217, "written": 217}
