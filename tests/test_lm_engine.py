"""Token-free tests for orion.lm.engine: `_load_flows` / `_session` are monkeypatched seams, so no
Neo4j, no MLX, no Claude. The engine must never crash the scan and never fabricate a lead."""
from __future__ import annotations

import threading

import pytest

from orion.contracts import Lead
from orion.lm import engine


@pytest.fixture(autouse=True)
def _cheap_index(monkeypatch, tmp_path_factory):
    """Tests that pass a dummy repo path ('.', '/repo') must not walk the real tree: give them an empty one."""
    real, empty = engine.RepoIndex, str(tmp_path_factory.mktemp("empty"))
    monkeypatch.setattr(engine, "RepoIndex", lambda root: real(empty if root in (".", "/repo") else root))


def scripted(leads, steps):
    """Stand-in for `engine._session`: delivers each step via `on_step` as the real prompter does, then
    returns `(leads, steps)` (the same records, which the engine must NOT replay)."""
    def session(generate, db, repo_path, scan_id, batch, **kw):
        for st in steps:
            kw["on_step"](st)
        return leads, steps
    return session


def test_lead_extension_is_backward_compatible():
    assert Lead(index=0, shape="A", text="t", evidence="e", confidence="HIGH").file is None


FLOWS = [{"flow_id": "F0", "rank": 0, "source_uid": "s0", "sink_uid": "k0", "sink_category": "code_exec",
          "nodes": [{"file": "a.js", "function": "f", "line": 10, "code": "exec(x)"}]},
         {"flow_id": "F1", "rank": 1, "source_uid": "s1", "sink_uid": "k1", "sink_category": "sql",
          "nodes": [{"file": "b.js", "function": "g", "line": 20, "code": "query(x)"}]}]


def test_discover_lm_maps_leads_by_flow_id(monkeypatch):
    events, steps = [], []
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)
    monkeypatch.setattr(engine, "_session", scripted(
        [{"flow_id": "F1", "file": "b.js", "function": "g", "line": 20, "cwe": "CWE-89", "confidence": "HIGH"}],
        [{"step_no": 0, "kind": "final"}]))
    leads = engine.discover_lm("s", ".", events.append, model=object(), on_step=steps.append, k=2)  # one batch of both
    assert leads[0].file == "b.js" and leads[0].source_uid == "s1" and leads[0].sink_uid == "k1"  # F1, not F0
    assert leads[0].text and leads[0].evidence          # non-empty, required downstream
    assert steps == [{"step_no": 0, "kind": "final"}]
    assert any(e["event"] == "done" and e["phase"] == "discover" for e in events)


def test_unresolved_flow_id_is_kept_and_tagged(monkeypatch):
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS[:1])
    monkeypatch.setattr(engine, "_session", lambda *a, **k: (
        [{"file": "a.js", "function": "f", "line": 10, "cwe": "CWE-94", "confidence": "LOW"}], []))
    leads = engine.discover_lm("s", ".", lambda e: None, model=object())
    assert leads[0].source_uid == "s0" and "unresolved" in leads[0].evidence


def test_lead_fields_shape_confidence_and_path_roles(monkeypatch):
    three = {"flow_id": "F0", "rank": 0, "source_uid": "s0", "sink_uid": "k0", "sink_category": "sql",
             "nodes": [{"file": "a.js", "function": "f", "line": 1, "code": "req.body"},
                       {"file": "a.js", "function": "f", "line": 2, "code": "x = y"},
                       {"file": "a.js", "function": "f", "line": 3, "code": "query(x)"}]}
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: [three])
    monkeypatch.setattr(engine, "_session", lambda *a, **k: (
        [{"flow_id": "F0", "file": "a.js", "function": "f", "line": "3", "cwe": "CWE-89", "confidence": "high"}], []))
    (lead,) = engine.discover_lm("s", ".", lambda e: None, model=object())
    assert lead.shape == "LM" and lead.confidence == "HIGH" and lead.index == 0
    assert lead.line == 3 and lead.cwe == "CWE-89" and lead.function == "f"
    assert [n["role"] for n in lead.path] == ["source", "step", "sink"]
    assert lead.path[2]["code"] == "query(x)" and "unresolved" not in lead.evidence


def test_unknown_confidence_maps_to_low(monkeypatch):
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS[:1])
    monkeypatch.setattr(engine, "_session", lambda *a, **k: ([{"flow_id": "F0", "confidence": "certain"}], []))
    (lead,) = engine.discover_lm("s", ".", lambda e: None, model=object())
    assert lead.confidence == "LOW" and lead.text and lead.evidence


def test_batches_of_k_each_get_their_own_session_and_turn(monkeypatch):
    events, batches = [], []
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)

    def session(generate, db, repo_path, scan_id, batch, **kw):
        batches.append([f["flow_id"] for f in batch])
        fid = batch[0]["flow_id"]
        steps = [{"step_no": 1, "kind": "run_cypher", "query": "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c"},
                 {"step_no": 2, "kind": "read_code"},
                 {"step_no": 3, "kind": "final"}]
        for st in steps:
            kw["on_step"](st)
        return ([{"flow_id": fid, "file": "x", "function": "y", "line": 1, "cwe": "CWE-1", "confidence": "MEDIUM"}],
                steps)

    monkeypatch.setattr(engine, "_session", session)
    leads = engine.discover_lm("s", ".", events.append, model=object(), k=1)
    assert batches == [["F0"], ["F1"]]
    assert [l.source_uid for l in leads] == ["s0", "s1"] and [l.index for l in leads] == [0, 1]
    assert {e["turn"] for e in events if e["event"] in ("query", "tool") and e["turn"] is not None} == {1, 2}  # index event has no turn
    assert [e["event"] for e in events if e["turn"] == 1 and e["event"] in ("query", "tool")] == ["query", "tool", "tool"]
    assert all(e["shape"] == "LM" and e["phase"] == "discover" for e in events)
    assert sum(e["event"] == "lead" for e in events) == 2
    assert events[0]["event"] == "start" and events[-1]["event"] == "done" and "2" in events[-1]["detail"]


def test_session_failure_is_an_error_event_and_other_batches_still_run(monkeypatch):
    events, steps = [], []
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)

    def session(generate, db, repo_path, scan_id, batch, **kw):
        if batch[0]["flow_id"] == "F0":
            kw["on_step"]({"step_no": 1, "kind": "run_cypher", "query": "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c"})
            raise RuntimeError("Neo.ClientError.Statement.SyntaxError: boom")   # mid-session, after one step
        final = [{"step_no": 1, "kind": "final"}]
        kw["on_step"](final[0])
        return ([{"flow_id": "F1", "file": "b.js", "function": "g", "line": 20, "cwe": "CWE-89", "confidence": "HIGH"}],
                final)

    monkeypatch.setattr(engine, "_session", session)
    leads = engine.discover_lm("s", ".", events.append, model=object(), k=1, on_step=steps.append)
    assert [l.source_uid for l in leads] == ["s1"]            # zero leads for the failed batch, never fabricated
    errs = [e for e in events if e["event"] == "error"]
    assert len(errs) == 1 and errs[0]["turn"] == 1 and "boom" in errs[0]["detail"]
    # the failed batch's earlier step AND the surviving batch's step each reached on_step exactly once
    assert steps == [{"step_no": 1, "kind": "run_cypher", "query": "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c"},
                     {"step_no": 1, "kind": "final"}]
    assert [e["turn"] for e in events if e["event"] == "query"] == [1]
    assert events[-1]["event"] == "done"


def test_load_flows_failure_is_an_error_event_and_zero_leads(monkeypatch):
    events = []

    def boom(db, sid, max_flows):
        raise RuntimeError("Neo.ClientError.Statement.SyntaxError: no CandidateFlow")

    monkeypatch.setattr(engine, "_load_flows", boom)
    monkeypatch.setattr(engine, "_session", lambda *a, **k: pytest.fail("no session without flows"))
    leads = engine.discover_lm("s", ".", events.append, model=object())
    assert leads == []
    assert any(e["event"] == "error" and "CandidateFlow" in e["detail"] for e in events)
    assert events[-1]["event"] == "done"


def test_explicit_flows_bypass_the_graph_and_are_capped_at_max_flows(monkeypatch):
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: pytest.fail("flows were given"))
    seen = []

    def session(generate, db, repo_path, scan_id, batch, **kw):
        seen.extend(f["flow_id"] for f in batch)
        return [], []

    monkeypatch.setattr(engine, "_session", session)
    assert engine.discover_lm("s", ".", lambda e: None, model=object(), flows=FLOWS, max_flows=1) == []
    assert seen == ["F0"]


def test_one_lead_per_flow_and_resolved_lead_beats_unresolved(monkeypatch):
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)
    monkeypatch.setattr(engine, "_session", lambda *a, **k: (
        [{"file": "zz.js", "function": "z", "line": 1, "cwe": "CWE-1", "confidence": "LOW"},       # unresolved -> F0
         {"flow_id": "F0", "file": "a.js", "function": "f", "line": 10, "cwe": "CWE-94", "confidence": "HIGH"},
         {"flow_id": "F0", "file": "a.js", "function": "f", "line": 11, "cwe": "CWE-94", "confidence": "LOW"},
         {"flow_id": "F1", "file": "b.js", "function": "g", "line": 20, "cwe": "CWE-89", "confidence": "HIGH"}], []))
    leads = engine.discover_lm("s", ".", lambda e: None, model=object())
    assert [(l.source_uid, l.sink_uid) for l in leads] == [("s0", "k0"), ("s1", "k1")]
    assert leads[0].line == 10 and "unresolved" not in leads[0].evidence


def test_session_receives_model_generate_and_a_cap_below_the_wrapper(monkeypatch):
    from orion.lm import prompter
    captured = {}

    class Model:
        context_cap = 6000

        def generate(self, messages):
            raise AssertionError("not called in this test")

    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS[:1])

    def session(generate, db, repo_path, scan_id, batch, **kw):
        captured.update(kw, generate=generate, repo_path=repo_path, scan_id=scan_id)
        return [], []

    monkeypatch.setattr(engine, "_session", session)
    m = Model()
    stop = threading.Event()
    engine.discover_lm("sid", "/repo", lambda e: None, model=m, stop=stop)
    assert captured["generate"] == m.generate and captured["scan_id"] == "sid" and captured["repo_path"] == "/repo"
    assert captured["context_cap"] == 6000 - prompter.CONTEXT_MARGIN and captured["stop"] is stop


def test_stop_set_before_a_batch_skips_it(monkeypatch):
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)
    monkeypatch.setattr(engine, "_session", lambda *a, **k: pytest.fail("stopped runs must not start a session"))
    stop = threading.Event()
    stop.set()
    events = []
    assert engine.discover_lm("s", ".", events.append, model=object(), stop=stop) == []
    assert events[-1]["event"] == "done"


def test_missing_model_is_a_loud_error():
    with pytest.raises(ValueError):
        engine.discover_lm("s", ".", lambda e: None, flows=FLOWS)


def test_engine_never_imports_claude_cli_or_discover():
    # `orion.discover` imports claude_cli at module top, so the engine must not import it either.
    import re
    src = open(engine.__file__).read()
    imports = [l for l in src.splitlines() if re.match(r"\s*(from|import)\s", l)]
    assert not any("claude_cli" in l for l in imports), imports
    assert not any(re.search(r"\bdiscover\b", l) for l in imports), imports


def test_single_node_flow_is_the_sink(monkeypatch):
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS[:1])
    monkeypatch.setattr(engine, "_session", scripted([{"flow_id": "F0", "confidence": "HIGH"}], []))
    (lead,) = engine.discover_lm("s", ".", lambda e: None, model=object())
    assert [n["role"] for n in lead.path] == ["sink"]


def test_lead_events_use_post_dedup_indices(monkeypatch):
    events = []
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)
    monkeypatch.setattr(engine, "_session", scripted(
        [{"flow_id": "F0", "confidence": "HIGH"}, {"flow_id": "F0", "confidence": "LOW"},   # dup collapses
         {"flow_id": "F1", "confidence": "HIGH"}], []))
    leads = engine.discover_lm("s", ".", events.append, model=object(), k=2)  # both flows in one batch
    lead_events = [e for e in events if e["event"] == "lead"]
    assert [e["lead"] for e in lead_events] == [l.index for l in leads] == [0, 1]
    assert all(e["turn"] == 1 for e in lead_events)
    assert events.index(lead_events[0]) > max(i for i, e in enumerate(events) if e["event"] in ("start",))


def test_stop_is_reported_in_done_and_tiny_cap_is_floored_with_a_warn(monkeypatch):
    events = []

    class Tiny:
        context_cap = 1200  # minus CONTEXT_MARGIN -> 176, below the floor

        def generate(self, messages):
            raise AssertionError("not called")

    captured = {}

    def session(generate, db, repo_path, scan_id, batch, **kw):
        captured.update(kw)
        stop.set()
        return [], []

    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: FLOWS)
    monkeypatch.setattr(engine, "_session", session)
    stop = threading.Event()
    engine.discover_lm("s", ".", events.append, model=Tiny(), k=1, stop=stop)
    assert captured["context_cap"] == engine.MIN_CONTEXT_CAP
    assert any(e["event"] == "warn" and "floored" in e["detail"] for e in events)
    assert events[-1]["event"] == "done" and "stopped early" in events[-1]["detail"]


def test_each_flow_enriched_and_judged_alone(monkeypatch, tmp_path):
    """K=1: one session per flow; the sink's function is in the case; a flow with no code is still judged."""
    (tmp_path / "a.js").write_text("function run(x){\n  exec(x)\n}\n")
    flows = [{**FLOWS[0], "nodes": [{"file": "a.js", "function": "run", "line": 2, "code": "exec(x)"}]}, FLOWS[1]]
    seen = []
    monkeypatch.setattr(engine, "_load_flows", lambda db, sid, max_flows: flows)
    monkeypatch.setattr(engine, "_session", lambda gen, db, repo, sid, batch, **k: seen.append(batch) or ([], []))
    engine.discover_lm("s", str(tmp_path), lambda e: None, model=object(), db=object())
    assert [len(b) for b in seen] == [1, 1]
    assert seen[0][0]["snippets"][0]["function"] == "run" and seen[1][0]["snippets"] == []


def test_default_k_is_one():
    assert engine.DEFAULT_K == 1


def test_index_event_and_single_build_per_scan(monkeypatch, tmp_path):
    (tmp_path / "a.js").write_text("function run(x){\n  exec(x)\n}\n")
    events, built = [], []
    real = engine.RepoIndex
    monkeypatch.setattr(engine, "RepoIndex", lambda root: built.append(root) or real(root))
    monkeypatch.setattr(engine, "_session", lambda *a, **k: ([], []))
    engine.discover_lm("s", str(tmp_path), events.append, model=object(), db=object(), flows=FLOWS)
    assert built == [str(tmp_path)]
    (ev,) = [e for e in events if e["event"] == "tool" and e["detail"].startswith("index:")]
    assert ev["phase"] == "discover" and ev["shape"] == "LM"
    import re
    assert re.fullmatch(r"index: 1 files, 0 skipped, \d+(\.\d+)?s", ev["detail"])


def test_given_index_is_reused_and_not_rebuilt(monkeypatch, tmp_path):
    idx = engine.RepoIndex(str(tmp_path))
    monkeypatch.setattr(engine, "RepoIndex", lambda root: pytest.fail("index was given"))
    monkeypatch.setattr(engine, "_session", lambda *a, **k: ([], []))
    engine.discover_lm("s", str(tmp_path), lambda e: None, model=object(), db=object(), flows=FLOWS, index=idx)


def test_enrichment_failure_keeps_the_flow_path_only_with_a_warn(monkeypatch):
    events, seen = [], []

    def flaky(flow, index, *, budget):
        if flow["flow_id"] == "F0":
            raise RuntimeError("bad node")
        return dict(flow, snippets=[])

    monkeypatch.setattr(engine.cases, "case_from_flow", flaky)
    monkeypatch.setattr(engine, "_session", lambda gen, db, repo, sid, batch, **k: seen.append(batch) or ([], []))
    engine.discover_lm("s", ".", events.append, model=object(), db=object(), flows=FLOWS)
    assert [b[0]["flow_id"] for b in seen] == ["F0", "F1"]
    assert seen[0][0]["nodes"] == FLOWS[0]["nodes"] and "snippets" not in seen[0][0]
    assert any(e["event"] == "warn" and "F0" in e["detail"] and "bad node" in e["detail"] for e in events)


def test_case_budget_is_forwarded(monkeypatch):
    got = []
    budget = engine.CaseBudget(max_target_lines=7)
    monkeypatch.setattr(engine.cases, "case_from_flow", lambda flow, index, *, budget: got.append(budget) or dict(flow, snippets=[]))
    monkeypatch.setattr(engine, "_session", lambda *a, **k: ([], []))
    engine.discover_lm("s", ".", lambda e: None, model=object(), db=object(), flows=FLOWS[:1], case_budget=budget)
    assert got == [budget]
