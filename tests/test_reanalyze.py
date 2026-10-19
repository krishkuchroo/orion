"""Change 7: `orion reanalyze` recomputes a scan's CandidateFlows from Neo4j alone (no Joern), and
the build-time precompute can fail without failing the build.

Live Neo4j, throwaway `test-<uuid>` scans. pathfind is run in-process on the same batch to get the
expected flows; reanalyze must reproduce them from what was persisted and touch nothing else.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from orion import cli, config, graph_build
from orion.graph import pathfind, persist, profiles, reachability, scans, schema
from tests import graph_snapshot
from tests.test_scan_record import repo  # noqa: F401 -- fixture: Express repo + tiny Joern envelope


def _batch(sid: str) -> schema.Batch:
    """An entry method whose calls reach two sinks, one through a diamond (two equal paths)."""
    b = schema.Batch(sid)
    b.emit_node("CpgMethod", {"full_name": "app.js::h", "name": "h", "file_path": "app.js", "line": 1})
    b.emit_node("EntryPoint", {"uid": "ep", "kind": "handler", "method_full_name": "app.js::h",
                               "exposure": "reachable"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "ep"}, "CpgMethod", {"full_name": "app.js::h"})
    calls = {"src": ("body", "req.body"), "a": ("trim", "s.trim()"), "b": ("lower", "s.lower()"),
             "ev": ("eval", "eval(s)"), "src2": ("query", "req.query"), "rd": ("redirect", "res.redirect(u)")}
    for line, (uid, (name, code)) in enumerate(calls.items(), start=2):
        b.emit_node("CpgCall", {"uid": uid, "name": name, "code": code, "file_path": "app.js", "line": line,
                                "column": 0, "method_full_name": name})
    for uid in ("src", "src2"):
        b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "app.js::h"}, "CpgCall", {"uid": uid})
    for s, d in (("src", "a"), ("src", "b"), ("a", "ev"), ("b", "ev"), ("src2", "rd")):
        b.emit_edge("FLOWS_TO", "CpgCall", {"uid": s}, "CpgCall", {"uid": d}, {"arg_index": 1})
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    return b


def _persisted_without_flows(sid: str, profile: str = "express") -> dict:
    """Persist the batch with NO CandidateFlows and a complete record; return the expected snapshot
    (pathfind run in-process on a copy of the same batch)."""
    b = _batch(sid)
    expected = copy.deepcopy(b)
    pathfind.pathfind(expected, profiles.with_lm_sinks(profiles.EXPRESS) if profile.endswith("+lm")
                      else profiles.EXPRESS)
    scans.mark_building(sid, commit="nocommit", profile=profile)
    persist.persist(b)
    scans.mark_complete(sid, {"nodes": {}, "edges": {}})
    return graph_snapshot.from_batch(expected)


def _shape(driver, sid: str) -> tuple[dict, dict]:
    with driver.session(database=config.NEO4J_DATABASE) as s:
        nodes = {r["l"]: r["n"] for r in s.run(
            "MATCH (n {scan_id:$sid}) UNWIND labels(n) AS l RETURN l, count(*) AS n", sid=sid)}
        rels = {r["t"]: r["n"] for r in s.run(
            "MATCH ({scan_id:$sid})-[r]->() RETURN type(r) AS t, count(r) AS n", sid=sid)}
    return nodes, rels


def _snapshot(driver, sid: str) -> dict:
    with driver.session(database=config.NEO4J_DATABASE) as s:
        return graph_snapshot.from_neo4j(s, sid)


def test_reanalyze_restores_flows_and_touches_nothing_else(neo4j_driver, scan_ids):
    sid = scan_ids()
    expected = _persisted_without_flows(sid)
    assert expected["candidate_flows"], "fixture must produce flows"
    nodes_before, rels_before = _shape(neo4j_driver, sid)
    assert cli.main(["reanalyze", "--scan-id", sid]) == 0
    d = graph_snapshot.diff(expected, _snapshot(neo4j_driver, sid))
    assert not d, graph_snapshot.format_diff(d)
    nodes_after, rels_after = _shape(neo4j_driver, sid)
    flows = len(expected["candidate_flows"])
    assert nodes_after == {**nodes_before, "CandidateFlow": flows}
    assert rels_after == rels_before
    rec = scans.get_record(sid)
    assert rec["status"] == "complete" and rec["reanalyzed_at"]
    assert rec["counts"]["nodes"]["CandidateFlow"] == flows


def test_reanalyze_replaces_old_flows(neo4j_driver, scan_ids):
    """Running it twice leaves one set of flows, not two."""
    sid = scan_ids()
    expected = _persisted_without_flows(sid)
    assert cli.main(["reanalyze", "--scan-id", sid]) == 0
    assert cli.main(["reanalyze", "--scan-id", sid]) == 0
    assert not graph_snapshot.diff(expected, _snapshot(neo4j_driver, sid))


def test_reanalyze_refuses_incomplete_mismatched_or_unrecorded(neo4j_driver, scan_ids, capsys):
    building, claude, bare = scan_ids("building"), scan_ids("claude"), scan_ids("bare")
    for sid in (building, claude):
        _persisted_without_flows(sid)
    scans.set_status(building, "building")
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        s.run("CREATE (:CpgCall {scan_id:$sid, uid:'x'})", sid=bare).consume()
    before = {sid: _shape(neo4j_driver, sid) for sid in (building, claude, bare)}
    capsys.readouterr()
    assert cli.main(["reanalyze", "--scan-id", building]) == 2
    assert "incomplete" in capsys.readouterr().err
    assert cli.main(["reanalyze", "--scan-id", claude, "--engine", "lm"]) == 2
    assert "'express'" in capsys.readouterr().err
    assert cli.main(["reanalyze", "--scan-id", bare]) == 2
    assert "no OrionScan record" in capsys.readouterr().err
    assert {sid: _shape(neo4j_driver, sid) for sid in before} == before


def test_precompute_failure_is_not_fatal(neo4j_driver, scan_ids, repo, monkeypatch):  # noqa: F811
    sid = scan_ids()

    def boom(*a, **k):                  # fault injection into a dependency of build()
        raise RuntimeError("pathfind exploded")

    monkeypatch.setattr(pathfind, "pathfind", boom)
    events: list[dict] = []
    assert graph_build.build(repo, "jssrc", events.append, stream=False, scan_id=sid) == sid
    assert any(e["event"] == "error" and "pathfind" in e["detail"] for e in events)
    nodes, _ = _shape(neo4j_driver, sid)
    assert nodes.get("CpgCall") == 2 and "CandidateFlow" not in nodes
    rec = scans.get_record(sid)
    assert rec["status"] == "complete"
    assert "pathfind exploded" in rec["counts"]["precompute"]["pathfind"]["error"]


@pytest.mark.slow
def test_nodegoat_reanalyze_equals_build(neo4j_driver, scan_ids):
    if not Path("fixtures/NodeGoat/cpg.bin").exists():
        pytest.skip("NodeGoat cpg.bin not present")
    sid = scan_ids()
    graph_build.build("fixtures/NodeGoat", None, None, stream=True, scan_id=sid)
    built = _snapshot(neo4j_driver, sid)
    assert cli.main(["reanalyze", "--scan-id", sid]) == 0
    d = graph_snapshot.diff(built, _snapshot(neo4j_driver, sid))
    assert not d, "reanalyze vs build:\n" + graph_snapshot.format_diff(d)
    golden = json.loads((Path(__file__).parent / "golden" / "nodegoat_default.json").read_text())
    assert not graph_snapshot.diff(golden, built)
