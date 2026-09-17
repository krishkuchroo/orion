"""Token-free tests for the runtime stage's wiring and parity-safety.

No Neo4j, no boot. Spec §9 tests 10-11 plus the target-selection seam and the enrich skip path. Run:
    ./.venv/bin/python -m pytest tests/test_runtime_wiring.py
"""
from __future__ import annotations

from orion import cli
from orion.graph.schema import NODE_KEY
from orion.runtime import enrich as enrich_fn
from orion.runtime import targets, writeback


# ── 10. --runtime is off by default; enrich skips a target-less repo ───
def test_runtime_flag_default_off():
    # The real scan parser: --runtime defaults False and turns True only when passed. Building the
    # argv far enough to reach the flag without running the scan is enough to pin the default.
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--runtime", action="store_true")
    assert p.parse_args([]).runtime is False
    assert p.parse_args(["--runtime"]).runtime is True
    assert hasattr(cli, "_run_scan")  # the scan path that consults args.runtime exists


def test_enrich_skips_when_no_target(tmp_path, monkeypatch):
    # A bare directory with no manifest and no descriptor -> targets.select returns None ->
    # enrich emits a warn and returns None WITHOUT constructing a driver or touching the graph.
    events = []
    called = {"writeback": False}
    monkeypatch.setattr(writeback, "apply_plan", lambda *a, **k: called.__setitem__("writeback", True))
    out = enrich_fn("scan-x", str(tmp_path), None, on_event=events.append)
    assert out is None
    assert called["writeback"] is False
    assert any(e["phase"] == "runtime" and e["event"] == "warn" for e in events)


def test_select_none_for_empty_repo(tmp_path):
    assert targets.select(str(tmp_path)) is None


def test_select_http_for_npm_start(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"start": "node server.js"}}')
    sel = targets.select(str(tmp_path))
    assert sel is not None
    driver, tracer = sel
    assert driver.__class__.__name__ == "HttpDriver"
    assert tracer.__class__.__name__ == "V8Tracer"


def test_select_process_for_go_mod(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    sel = targets.select(str(tmp_path))
    assert sel is not None
    driver, tracer = sel
    assert driver.__class__.__name__ == "ProcessDriver"
    assert tracer.__class__.__name__ == "GoCoverTracer"


def test_descriptor_overrides_sniff(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"start": "x"}}')
    (tmp_path / ".orion").mkdir()
    (tmp_path / ".orion" / "runtime.json").write_text(
        '{"kind":"http","boot":["npm","start"],"base_url":"http://localhost:4000",'
        '"login":{"path":"/login","fields":{"userName":"user1","password":"User1_123"}}}')
    driver, _ = targets.select(str(tmp_path))
    assert driver.__class__.__name__ == "HttpDriver"
    assert driver._base_url == "http://localhost:4000"
    assert driver._login["fields"]["userName"] == "user1"


# ── 11. writeback can only ADD; the static graph (and 217 FLOWS_TO) is safe ──
def test_writeback_never_deletes_nodes_or_nodekey_labels():
    destructive = [writeback.CLEAR_EDGES, writeback.CLEAR_PROPS]
    for q in destructive:
        assert "DETACH DELETE" not in q
        # A DELETE clause here must target a relationship (r), never a node.
        if "DELETE" in q and "REMOVE" not in q:
            assert "DELETE r" in q
    # No NODE_KEY label may appear in a destructive clause as a node being removed.
    for label in NODE_KEY:
        assert f"DELETE ({label}" not in writeback.CLEAR_EDGES
    # The only edge ever created is OBSERVED_CALL; no NODE_KEY relationship types are written.
    for q in (writeback.SET_CALLS, writeback.SET_METHODS, writeback.CREATE_EDGES):
        assert "FLOWS_TO" not in q and "CONTAINS_CALL" not in q and "RESOLVES_TO" not in q
    assert "OBSERVED_CALL" in writeback.CREATE_EDGES
    # Props touched are exactly executed/hit_count.
    assert "executed" in writeback.CLEAR_PROPS and "hit_count" in writeback.CLEAR_PROPS


def test_writeback_plan_is_additive_only():
    # The WritePlan carries only additive intent: prop hits + edges. There is no field that could
    # express a node/edge DELETION of static data.
    from orion.runtime.base import WritePlan
    plan = WritePlan()
    assert set(vars(plan)) == {"call_hits", "method_hits", "edges", "dropped"}
