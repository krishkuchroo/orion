import gc
import json
import os
import threading
import time
import weakref

import pytest

from eval import infra, normalize, usage
from eval.arms import ArmResult, lm
from orion.contracts import Lead

STEP = {"step_no": 0, "kind": "final", "query": None, "row_count": None, "prompt_tokens": 50,
        "completion_tokens": 5, "cached_tokens": 0, "wall_seconds": 0.1, "error": None}


_REAL_FREE = lm._free_model_memory   # before any test patches it
_REAL_PATHFIND_ERROR = lm._pathfind_error


class FakeModel:
    pass


def _seams(monkeypatch, *, discover=None, scan_id="s1", problem=None):
    """Stand-ins for every heavy seam (Joern/Neo4j build, MLX load, discover_lm, MLX cache)."""
    rec = {"order": [], "loaded": {}, "builds": [], "checked": []}

    def build(repo_dir, on_event):
        rec["order"].append("build")
        rec["builds"].append(repo_dir)
        on_event({"phase": "build", "event": "timing", "detail": "persist: 0.1s"})
        return scan_id

    def load(path, **kw):
        rec["order"].append("load")
        rec["loaded"].update(path=path, **kw)
        return FakeModel()

    def fake_discover(scan_id, repo, on_event, **kw):
        rec["order"].append("discover")
        return (discover or (lambda *a, **k: []))(scan_id, repo, on_event, **kw)

    monkeypatch.setattr(lm, "_build_graph", build)
    monkeypatch.setattr(lm, "_load_model", load)
    monkeypatch.setattr(lm, "_discover", fake_discover)
    monkeypatch.setattr(lm, "_scan_problem",
                        lambda sid, repo_dir: rec["checked"].append(sid) or problem)
    monkeypatch.setattr(lm, "_free_model_memory", lambda: rec["order"].append("release"))
    monkeypatch.setattr(lm, "_pathfind_error", lambda sid: None)
    return rec


def _arm(tmp_path, **over):
    model = tmp_path / "model"
    model.mkdir(exist_ok=True)
    kw = dict(arm="orion-lm", repo_dir=str(tmp_path / "tree"), model_tag=str(model),
              json_out=str(tmp_path / "run" / "findings.json"), on_line=lambda l: None,
              on_start=lambda p: None, graph_cache={}, run_no=2, repo_id="r", commit_sha="v")
    kw.update(over)
    return lm.orion_lm_arm(**kw)


def test_orion_lm_arm_returns_armresult_with_steps_and_seeds_by_run_no(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        kw["on_step"](dict(STEP))
        return []
    rec = _seams(monkeypatch, discover=fake_discover)
    res = _arm(tmp_path)
    assert isinstance(res, ArmResult) and res.status == "ok"
    assert rec["loaded"]["seed"] == 2 and rec["loaded"]["path"] == str(tmp_path / "model")
    assert res.steps == [STEP]          # run_one logs these; the arm writes nothing to the DB


def test_usage_is_one_block_per_step_with_the_frontier_T(tmp_path, monkeypatch):
    steps = [dict(STEP, step_no=1, kind="run_cypher", prompt_tokens=100, cached_tokens=60,
                  completion_tokens=10),
             dict(STEP, step_no=2, prompt_tokens=180, cached_tokens=110, completion_tokens=7),
             dict(STEP, step_no=3, kind="context_overflow", prompt_tokens=None,
                  completion_tokens=None, cached_tokens=None, error="prompt is 9000 tokens")]

    def fake_discover(scan_id, repo, on_event, **kw):
        for s in steps:
            kw["on_step"](s)
        return []
    _seams(monkeypatch, discover=fake_discover)
    res = _arm(tmp_path)
    assert res.usage[0] == {"uncached_in": 40, "cache_read": 60, "cache_write": 0, "out": 10,
                            "reasoning": None}
    assert res.usage[1] == {"uncached_in": 70, "cache_read": 110, "cache_write": 0, "out": 7,
                            "reasoning": None}
    # nothing measured -> nothing invented
    assert res.usage[2] == {"uncached_in": None, "cache_read": None, "cache_write": None,
                            "out": None, "reasoning": None}
    # T = sum prompt (cached + uncached) + sum completion, as for the frontier arms
    assert sum(usage.total(b) for b in res.usage) == (100 + 10) + (180 + 7)


def test_no_leads_writes_an_empty_list(tmp_path, monkeypatch):
    _seams(monkeypatch)
    res = _arm(tmp_path)
    assert res.status == "ok" and res.findings_path == str(tmp_path / "run" / "findings.json")
    assert json.loads(open(res.findings_path).read()) == []
    assert normalize.load_arm(res.findings_path, arm="orion-lm") == []


def test_findings_are_orion_scan_json_and_normalize_reads_them(tmp_path, monkeypatch):
    lead = Lead(index=0, shape="LM", text="CWE-89 at routes/a.js:3 in f", evidence="model lead",
                confidence="HIGH", source_uid="u1", sink_uid="u2", file="routes/a.js",
                function="f", line=3, cwe="CWE-89",
                path=[{"file": "routes/a.js", "function": "f", "line": 3, "code": "q(x)",
                       "role": "sink"}])
    _seams(monkeypatch, discover=lambda *a, **k: [lead])
    res = _arm(tmp_path, arm="orion-lm-base")
    raw = json.loads(open(res.findings_path).read())
    assert raw[0]["decision"] == "INCONCLUSIVE" and raw[0]["reason"] == "unverified (engine=lm)"
    assert raw[0]["lead"]["shape"] == "LM"
    (f,) = normalize.load_arm(res.findings_path, arm="orion-lm")
    assert (f["file"], f["function"], f["line"], f["cwe"]) == ("routes/a.js", "f", 3, "CWE-89")
    assert f["path"][0]["role"] == "sink"


def test_graph_is_built_before_the_model_loads_and_the_model_is_released(tmp_path, monkeypatch):
    refs = []

    def fake_discover(scan_id, repo, on_event, **kw):
        refs.append(weakref.ref(kw["model"]))
        return []
    rec = _seams(monkeypatch, discover=fake_discover)
    _arm(tmp_path)
    assert rec["order"] == ["build", "load", "discover", "release"]
    gc.collect()
    assert refs[0]() is None            # the arm keeps no reference to the model


def test_graph_cache_reuses_a_scan_per_repo_and_commit(tmp_path, monkeypatch):
    seen = []
    rec = _seams(monkeypatch, discover=lambda sid, *a, **k: seen.append(sid) or [])
    cache, lines = {}, []
    _arm(tmp_path, graph_cache=cache)
    _arm(tmp_path, graph_cache=cache, arm="orion-lm-base", repo_dir=str(tmp_path / "tree2"),
         on_line=lines.append)
    assert rec["builds"] == [str(tmp_path / "tree")]   # built once
    assert seen == ["s1", "s1"] and cache == {("r", "v"): "s1"}
    assert rec["checked"] == ["s1"]                    # the reused scan's record is re-checked
    assert any("reusing" in l for l in lines)
    _arm(tmp_path, graph_cache=cache, commit_sha="p")   # another commit is another graph
    assert len(rec["builds"]) == 2 and cache[("r", "p")] == "s1"


def test_unusable_cached_graph_is_rebuilt(tmp_path, monkeypatch):
    rec = _seams(monkeypatch, problem="scan s1 is incomplete")
    lines = []
    _arm(tmp_path, graph_cache={("r", "v"): "s1"}, on_line=lines.append)
    assert rec["builds"] == [str(tmp_path / "tree")]
    assert any("scan s1 is incomplete" in l for l in lines)


def test_watchdog_sets_stop_after_hung_seconds_and_marks_the_run_hung(tmp_path, monkeypatch):
    lead = Lead(index=0, shape="LM", text="t", evidence="e", confidence="LOW", file="a.py", line=1)

    def fake_discover(scan_id, repo, on_event, **kw):
        assert kw["stop"].wait(5), "watchdog never set stop"
        kw["on_step"](dict(STEP, kind="forced_final"))   # the prompter forces a final answer
        return [lead]
    _seams(monkeypatch, discover=fake_discover)
    lines = []
    res = _arm(tmp_path, hung_seconds=0.05, on_line=lines.append)
    assert res.status == "hung"
    assert res.steps[0]["kind"] == "forced_final"
    assert len(json.loads(open(res.findings_path).read())) == 1   # the forced final's leads kept
    assert any("hung" in l and "0.05" in l for l in lines)


def test_steady_progress_keeps_the_watchdog_quiet(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        end = time.monotonic() + 0.6
        while time.monotonic() < end:
            on_event({"phase": "discover", "event": "query", "shape": "LM", "detail": "q"})
            time.sleep(0.02)
        assert not kw["stop"].is_set()
        return []
    _seams(monkeypatch, discover=fake_discover)
    assert _arm(tmp_path, hung_seconds=0.3).status == "ok"


def test_crash_in_discovery_is_crashed_keeps_steps_and_releases_model(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        kw["on_step"](dict(STEP))
        raise RuntimeError("boom in session")
    rec = _seams(monkeypatch, discover=fake_discover)
    lines = []
    res = _arm(tmp_path, on_line=lines.append)
    assert res.status == "crashed" and res.findings_path is None
    assert not os.path.exists(tmp_path / "run" / "findings.json")   # no leads invented
    assert res.steps == [STEP] and res.usage[0]["uncached_in"] == 50
    assert any("boom in session" in l and "Traceback" in l for l in lines)
    assert rec["order"][-1] == "release"


@pytest.mark.parametrize("model_tag", ["", None, "/no/such/model"])
def test_missing_model_path_raises_before_any_build(tmp_path, monkeypatch, model_tag):
    rec = _seams(monkeypatch)
    with pytest.raises(ValueError, match="model"):
        lm.orion_lm_arm(arm="orion-lm", repo_dir=str(tmp_path), model_tag=model_tag,
                        json_out=str(tmp_path / "f.json"), on_line=lambda l: None,
                        on_start=lambda p: None, graph_cache={}, run_no=1, repo_id="r",
                        commit_sha="v")
    assert rec["order"] == []


def test_on_start_gets_this_process_before_the_build(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)
    pids = []
    _arm(tmp_path, on_start=lambda p: (pids.append(p.pid), rec["order"].append("on_start")))
    assert pids == [os.getpid()] and rec["order"][:2] == ["on_start", "build"]


def test_events_reach_on_line_as_readable_text(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        on_event({"phase": "discover", "event": "query", "shape": "LM", "turn": 1,
                  "detail": "batch 1 step 1: run_cypher MATCH (n {scan_id:$scan_id})"})
        return []
    _seams(monkeypatch, discover=fake_discover)
    lines = []
    _arm(tmp_path, on_line=lines.append)
    assert any(l.startswith("[build/timing]") for l in lines)
    assert any(l.startswith("[discover/query] shape=LM turn=1 - batch 1 step 1") for l in lines)


def test_case_id_is_accepted_and_flows_stay_none(tmp_path, monkeypatch):
    seen = {}
    _seams(monkeypatch, discover=lambda sid, repo, on_event, **kw: seen.update(kw) or [])
    _arm(tmp_path, case_id="BenchmarkTest00001")
    assert seen["flows"] is None and isinstance(seen["stop"], threading.Event)


def test_findings_write_failure_is_a_miss_not_a_raise(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        kw["on_step"](dict(STEP))
        return []
    _seams(monkeypatch, discover=fake_discover)
    (tmp_path / "blocker").write_text("a file where the run dir should be")
    lines = []
    res = _arm(tmp_path, json_out=str(tmp_path / "blocker" / "findings.json"), on_line=lines.append)
    assert res.status == "ok" and res.findings_path is None
    assert res.steps == [STEP]            # the run's tokens still reach run_one
    assert any("findings.json" in l for l in lines)


def test_mlx_backend_cache_is_cleared_and_its_peak_reported(tmp_path, monkeypatch):
    """The real _free_model_memory clears MLX's cache; MLX's own peak goes to on_line because psutil
    RSS does not see Metal buffers. A stand-in mlx.core module: no MLX is loaded in tests."""
    import sys
    calls = []
    fake_mx = type(sys)("mlx.core")
    fake_mx.clear_cache = lambda: calls.append("clear")
    fake_mx.reset_peak_memory = lambda: calls.append("reset")
    fake_mx.get_peak_memory = lambda: 512 * 1024 * 1024
    monkeypatch.setitem(sys.modules, "mlx.core", fake_mx)
    rec = _seams(monkeypatch)
    monkeypatch.setattr(lm, "_free_model_memory", _REAL_FREE)
    monkeypatch.setattr(lm, "_load_model", lambda path, **kw: type("M", (), {"backend": "mlx"})())
    lines = []
    _arm(tmp_path, on_line=lines.append)
    assert calls == ["reset", "clear"]          # peak reset before the load, cache cleared after
    assert any("mlx peak memory 512.0 MB" in l for l in lines)
    assert any("backend mlx" in l for l in lines)
    assert rec["order"] == ["build", "discover"]   # load is the stand-in above; release is real


def test_non_mlx_backend_reports_no_mlx_peak(tmp_path, monkeypatch):
    _seams(monkeypatch)
    lines = []
    _arm(tmp_path, on_line=lines.append)
    assert not any("mlx peak" in l for l in lines)


# ---- the REAL orion.lm.engine.discover_lm (no _discover fake): it never raises for a graph or model
# failure, it turns each into an `error` event and returns. The arm must still tell those runs apart
# from a genuine "found nothing".

class _GraphStub:
    """Stands in for orion.graphdb.GraphDB at the level discover_lm's real graph reads use
    (tools.run_cypher: EXPLAIN, then the query): `n` CandidateFlows, each with one CpgCall node.
    `fail` makes every query answer with an error, as GraphDB does when Neo4j is down."""

    def __init__(self, n=2, fail=None):
        self.n, self.fail = n, fail

    def run_cypher(self, scan_id, query, *, limit=None, **kw):
        if self.fail:
            return {"error": self.fail}
        if query.startswith("EXPLAIN"):
            return {"query_type": "r"}
        if "CandidateFlow" in query:
            rows = [{"rank": i, "source_uid": f"s{i}", "sink_uid": f"k{i}", "sink_category": "sql",
                     "path_uids": [f"c{i}"]} for i in range(self.n)]
        else:   # one flow's CpgCall nodes
            import re
            rows = [{"uid": u, "file": "app.py", "function": "handler", "line": 3,
                     "code": "db.execute(q)"} for u in re.findall(r"'(c\d+)'", query)]
        return {"rows": rows, "row_count": len(rows)}

    def close(self):
        pass


class _Model:
    """generate() raises on the calls listed in `fail_calls` (1-based; "all" = every call), else
    answers a final action with one lead on whatever flow the prompt names."""
    backend = "stub"

    def __init__(self, fail_calls="all"):
        self.fail_calls, self.calls = fail_calls, 0

    def generate(self, messages):
        from orion.lm.model import GenResult
        self.calls += 1
        if self.fail_calls == "all" or self.calls in self.fail_calls:
            raise RuntimeError("[metal::malloc] Resource limit exceeded")
        flow = "F1" if "F1" in messages[-1]["content"] else "F0"
        text = json.dumps({"action": "final", "leads": [{"flow_id": flow, "file": "app.py",
                           "function": "handler", "line": 3, "cwe": "CWE-89", "confidence": "HIGH"}]})
        return GenResult(text=text, prompt_tokens=120, completion_tokens=30, cached_tokens=0)


def _real_engine(monkeypatch, tmp_path, *, db, model):
    import orion.graphdb
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("def handler(q):\n    x = q\n    db.execute(q)\n")
    monkeypatch.setattr(lm, "_build_graph", lambda repo_dir, on_event: "s1")
    monkeypatch.setattr(lm, "_load_model", lambda path, **kw: model)
    monkeypatch.setattr(orion.graphdb, "GraphDB", lambda: db)   # discover_lm opens its own db
    monkeypatch.setattr(lm, "_pathfind_error", lambda sid: None)
    lines = []
    res = _arm(tmp_path, repo_dir=str(tree), on_line=lines.append)
    return res, lines


def test_real_engine_every_batch_failing_is_crashed_with_no_findings(tmp_path, monkeypatch):
    model = _Model(fail_calls="all")
    res, lines = _real_engine(monkeypatch, tmp_path, db=_GraphStub(n=2), model=model)
    assert model.calls == 2                                   # both batches really ran
    assert res.status == "crashed" and res.findings_path is None
    assert not os.path.exists(tmp_path / "run" / "findings.json")
    assert sum("[discover/error]" in l for l in lines) == 2
    assert any("crashed" in l and "all 2 batch" in l for l in lines)


def test_real_engine_failed_flow_read_is_crashed_with_no_findings(tmp_path, monkeypatch):
    model = _Model(fail_calls=())
    res, lines = _real_engine(monkeypatch, tmp_path, model=model,
                              db=_GraphStub(fail="CypherSyntaxError: Invalid input 'X'"))
    assert model.calls == 0                                   # no batch could run
    assert res.status == "crashed" and res.findings_path is None
    assert not os.path.exists(tmp_path / "run" / "findings.json")
    assert any("crashed" in l and "loading CandidateFlows failed" in l for l in lines)


def test_real_engine_neo4j_down_at_the_flow_read_is_aborted_not_a_miss(tmp_path, monkeypatch):
    """I7: GraphDB turns ServiceUnavailable into {"error": "ServiceUnavailable: ..."}, slice re-raises it
    as RuntimeError, discover_lm reports it as an error event: the arm reads that as a machine failure."""
    model = _Model(fail_calls=())
    res, lines = _real_engine(monkeypatch, tmp_path, model=model,
                              db=_GraphStub(fail="ServiceUnavailable: Neo4j is down"))
    assert model.calls == 0
    assert res.status == "aborted" and res.findings_path is None
    assert not os.path.exists(tmp_path / "run" / "findings.json")
    assert any("aborted, machine failure" in l and "ServiceUnavailable" in l for l in lines)


def test_real_engine_some_batches_failing_stays_ok_with_a_summary(tmp_path, monkeypatch):
    model = _Model(fail_calls={1})                            # batch 1 (F0) fails, batch 2 (F1) answers
    res, lines = _real_engine(monkeypatch, tmp_path, db=_GraphStub(n=2), model=model)
    assert res.status == "ok" and res.findings_path == str(tmp_path / "run" / "findings.json")
    (f,) = normalize.load_arm(res.findings_path, arm="orion-lm")
    assert (f["file"], f["line"], f["cwe"]) == ("app.py", 3, "CWE-89")
    assert [s["kind"] for s in res.steps] == ["final"]
    assert any("1 of 2 batches failed" in l for l in lines)


def test_real_engine_no_candidate_flows_is_a_genuine_empty_ok(tmp_path, monkeypatch):
    model = _Model(fail_calls=())
    res, lines = _real_engine(monkeypatch, tmp_path, db=_GraphStub(n=0), model=model)
    assert res.status == "ok" and json.loads(open(res.findings_path).read()) == []
    assert not any("batches failed" in l or "crashed" in l for l in lines)


# ---- a pathfind failure at BUILD time: graph_build._precompute keeps {"error": ...} in the scan
# record (counts.precompute.pathfind) and persists no CandidateFlows, so discovery would see zero
# flows and report a clean empty result. The arm reads the record and calls that run crashed.

PATHFIND_FAILED = {"scan_id": "s1", "status": "complete", "profile": "generic+lm",
                   "counts": {"nodes": {}, "edges": {}, "mismatches": [],
                              "precompute": {"reachability": {"reached_methods": 3},
                                             "pathfind": {"error": "RecursionError: maximum recursion "
                                                                   "depth exceeded"}}}}
PATHFIND_OK = dict(PATHFIND_FAILED, counts=dict(PATHFIND_FAILED["counts"], precompute={
    "pathfind": {"flows": 4, "sources": 2, "sinks": 3}}))


def _record(monkeypatch, rec):
    """The real _pathfind_error over a stand-in for the public scans.get_record (no Neo4j)."""
    from orion.graph import scans
    monkeypatch.setattr(lm, "_pathfind_error", _REAL_PATHFIND_ERROR)
    monkeypatch.setattr(scans, "get_record", lambda sid: rec)


def test_pathfind_error_reads_the_scan_record(monkeypatch):
    _record(monkeypatch, PATHFIND_FAILED)
    assert lm._pathfind_error("s1") == "RecursionError: maximum recursion depth exceeded"
    _record(monkeypatch, PATHFIND_OK)
    assert lm._pathfind_error("s1") is None
    _record(monkeypatch, None)                     # no record: the flows cannot be confirmed
    assert "no OrionScan record" in lm._pathfind_error("s1")


def test_fresh_build_whose_pathfind_failed_is_crashed(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)
    _record(monkeypatch, PATHFIND_FAILED)
    lines = []
    res = _arm(tmp_path, on_line=lines.append)
    assert res.status == "crashed" and res.findings_path is None
    assert not os.path.exists(tmp_path / "run" / "findings.json")
    assert any("crashed" in l and "maximum recursion depth exceeded" in l for l in lines)
    assert rec["order"] == ["build"]               # no model loaded, no discovery
    assert res.steps == [] and res.usage == []


def test_cached_scan_whose_pathfind_failed_is_crashed(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)                      # _scan_problem says the record is usable
    _record(monkeypatch, PATHFIND_FAILED)
    lines = []
    res = _arm(tmp_path, graph_cache={("r", "v"): "s1"}, on_line=lines.append)
    assert res.status == "crashed" and res.findings_path is None
    assert not os.path.exists(tmp_path / "run" / "findings.json")
    assert any("crashed" in l and "maximum recursion depth exceeded" in l for l in lines)
    assert rec["builds"] == [] and rec["checked"] == ["s1"] and rec["order"] == []


def test_recorded_pathfind_summary_lets_the_run_proceed(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)
    _record(monkeypatch, PATHFIND_OK)
    assert _arm(tmp_path).status == "ok"
    assert rec["order"] == ["build", "load", "discover", "release"]


# ---- OWASP case mode (Task F2): only the case's CandidateFlows are judged ----------------------

OWASP_CASE = {"case_id": "BenchmarkTest00001", "category": "sqli", "real": True, "cwe": "CWE-89",
              "file": "app.py", "entry": "POST /sqli-00/BenchmarkTest00001 -> handler"}
_REAL_CASE_FLOWS = lm._case_flows


def test_case_mode_passes_the_cases_flows_to_discover(tmp_path, monkeypatch):
    flow = {"flow_id": "F3", "rank": 3, "nodes": [{"file": "app.py", "line": 3}]}
    seen = {}

    def fake_discover(scan_id, repo, on_event, **kw):
        seen.update(kw)
        return []
    rec = _seams(monkeypatch, discover=fake_discover)

    def case_flows(scan_id, case):
        rec["order"].append("case_flows")
        seen["asked"] = (scan_id, case)
        return [flow]
    monkeypatch.setattr(lm, "_case_flows", case_flows)
    lines = []
    res = _arm(tmp_path, case_id="BenchmarkTest00001", case=OWASP_CASE, on_line=lines.append)
    assert res.status == "ok"
    assert seen["flows"] == [flow] and seen["asked"] == ("s1", OWASP_CASE)
    assert rec["order"] == ["build", "case_flows", "load", "discover", "release"]
    assert any("1 CandidateFlow(s) touch app.py" in l for l in lines)
    meta = json.loads((tmp_path / "run" / "case_meta.json").read_text())
    assert meta == {"case_id": "BenchmarkTest00001", "n_flows": 1, "mode": "flows"}


def test_case_with_zero_flows_is_judged_code_only_at_its_entry(tmp_path, monkeypatch):
    """Fix round 1: no CandidateFlow touches the case -> ONE entry-only case through the REAL
    discover_lm (enrichment by cases.case_from_flow, stub model): its target snippet is the handler,
    the model judges it, and case_meta.json says mode entry_only."""
    import orion.graphdb
    monkeypatch.setattr(lm, "_case_flows", lambda scan_id, case: [])
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("import db\n\n\ndef handler(q):\n    x = q\n    db.execute(x)\n")
    model = _Model(fail_calls=())
    seen = []
    real_generate = model.generate

    def generate(messages):
        seen.append(messages[-1]["content"])
        return real_generate(messages)
    model.generate = generate
    monkeypatch.setattr(lm, "_build_graph", lambda repo_dir, on_event: "s1")
    monkeypatch.setattr(lm, "_load_model", lambda path, **kw: model)
    monkeypatch.setattr(orion.graphdb, "GraphDB", lambda: _GraphStub(n=2))
    monkeypatch.setattr(lm, "_pathfind_error", lambda sid: None)
    lines = []
    res = _arm(tmp_path, repo_dir=str(tree), on_line=lines.append, case=OWASP_CASE)
    assert res.status == "ok" and model.calls == 1                  # one case, judged
    (task,) = seen
    assert "FLOW F0" in task and "[target] app.py:4-6 in handler" in task and "db.execute(x)" in task
    assert "sink_category=None source_uid=None sink_uid=None" in task   # no graph flow behind it
    assert "FLOW F1" not in task                                    # the scan's other flows never shown
    (f,) = normalize.load_arm(res.findings_path, arm="orion-lm")
    assert (f["file"], f["cwe"]) == ("app.py", "CWE-89")
    meta = json.loads((tmp_path / "run" / "case_meta.json").read_text())
    assert meta == {"case_id": "BenchmarkTest00001", "n_flows": 0, "mode": "entry_only"}
    assert any("mode entry_only" in l for l in lines)


def test_entry_only_case_whose_batch_fails_is_crashed(tmp_path, monkeypatch):
    """The F3 health checks still apply: the single entry-only batch failing is "crashed"."""
    import orion.graphdb
    monkeypatch.setattr(lm, "_case_flows", lambda scan_id, case: [])
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("def handler(q):\n    return q\n")
    monkeypatch.setattr(lm, "_build_graph", lambda repo_dir, on_event: "s1")
    monkeypatch.setattr(lm, "_load_model", lambda path, **kw: _Model(fail_calls="all"))
    monkeypatch.setattr(orion.graphdb, "GraphDB", lambda: _GraphStub(n=0))
    monkeypatch.setattr(lm, "_pathfind_error", lambda sid: None)
    res = _arm(tmp_path, repo_dir=str(tree), case=OWASP_CASE)
    assert res.status == "crashed" and res.findings_path is None


def test_case_whose_handler_is_missing_is_crashed(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)
    monkeypatch.setattr(lm, "_case_flows", lambda scan_id, case: [])
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("x = 1\n")
    lines = []
    res = _arm(tmp_path, repo_dir=str(tree), case=OWASP_CASE, on_line=lines.append)
    assert res.status == "crashed" and "load" not in rec["order"]
    assert any("crashed" in l and "handler" in l for l in lines)


def test_case_flow_load_failure_is_crashed_before_the_model_loads(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)

    def boom(scan_id, case):
        raise RuntimeError("CypherSyntaxError: bad query")
    monkeypatch.setattr(lm, "_case_flows", boom)
    lines = []
    res = _arm(tmp_path, case=OWASP_CASE, on_line=lines.append)
    assert res.status == "crashed" and res.findings_path is None
    assert "load" not in rec["order"]
    assert any("crashed" in l and "bad query" in l for l in lines)


def test_case_flow_read_with_neo4j_down_is_aborted_before_the_model_loads(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)

    def boom(scan_id, case):
        raise RuntimeError("ServiceUnavailable: Neo4j is down")
    monkeypatch.setattr(lm, "_case_flows", boom)
    lines = []
    res = _arm(tmp_path, case=OWASP_CASE, on_line=lines.append)
    assert res.status == "aborted" and res.findings_path is None and "load" not in rec["order"]
    assert any("aborted" in l and "Neo4j is down" in l for l in lines)


def test_default_case_flows_filters_the_scans_flows_by_the_case_file(monkeypatch):
    import orion.graphdb

    class Stub(_GraphStub):
        closed = False

        def run_cypher(self, scan_id, query, *, limit=None, **kw):
            res = super().run_cypher(scan_id, query, limit=limit, **kw)
            if "CpgCall" in query and "rows" in res:   # flow c1 in the case's file, flow c0 elsewhere
                for r in res["rows"]:
                    r["file"] = "app.py" if r["uid"] == "c1" else "lib/other.py"
            return res

        def close(self):
            Stub.closed = True
    monkeypatch.setattr(orion.graphdb, "GraphDB", lambda: Stub(n=2))
    flows = _REAL_CASE_FLOWS("s1", OWASP_CASE)
    assert [f["flow_id"] for f in flows] == ["F1"] and Stub.closed


# ---- I7: machine failures are "aborted" (not scored, re-attempted), never a terminal miss ---------

def test_neo4j_unavailable_during_the_build_is_aborted(tmp_path, monkeypatch):
    from neo4j.exceptions import ServiceUnavailable
    rec = _seams(monkeypatch)

    def build(repo_dir, on_event):
        rec["order"].append("build")
        try:
            raise ServiceUnavailable("Couldn't connect to localhost:7688")
        except ServiceUnavailable as e:
            raise RuntimeError("persist failed") from e         # wrapped: still a machine failure
    monkeypatch.setattr(lm, "_build_graph", build)
    cache, lines = {}, []
    res = _arm(tmp_path, graph_cache=cache, on_line=lines.append)
    assert res.status == "aborted" and res.findings_path is None
    assert rec["order"] == ["build"] and cache == {}               # no model, nothing cached
    assert any("aborted, machine failure" in l and "graph build" in l for l in lines)


def test_joern_missing_is_aborted(tmp_path, monkeypatch):
    rec = _seams(monkeypatch)

    def build(repo_dir, on_event):
        raise infra.InfraError("Joern binaries not found: /j/joern-parse")
    monkeypatch.setattr(lm, "_build_graph", build)
    assert _arm(tmp_path).status == "aborted" and "load" not in rec["order"]


def test_get_record_raising_is_aborted(tmp_path, monkeypatch):
    from neo4j.exceptions import SessionExpired
    from orion.graph import scans
    rec = _seams(monkeypatch)
    monkeypatch.setattr(lm, "_pathfind_error", _REAL_PATHFIND_ERROR)

    def get_record(sid):
        raise SessionExpired("bolt connection dropped")
    monkeypatch.setattr(scans, "get_record", get_record)
    lines = []
    res = _arm(tmp_path, on_line=lines.append)
    assert res.status == "aborted" and rec["order"] == ["build"]
    assert any("scan record" in l and "SessionExpired" in l for l in lines)


def test_a_genuine_build_failure_still_propagates(tmp_path, monkeypatch):
    _seams(monkeypatch)

    def build(repo_dir, on_event):
        raise RuntimeError("joern-parse failed (rc=1): unsupported syntax")
    monkeypatch.setattr(lm, "_build_graph", build)
    with pytest.raises(RuntimeError, match="joern-parse failed"):
        _arm(tmp_path)


def test_a_model_load_failure_still_propagates(tmp_path, monkeypatch):
    _seams(monkeypatch)

    def load(path, **kw):
        raise RuntimeError("[metal::malloc] Resource limit exceeded")
    monkeypatch.setattr(lm, "_load_model", load)
    with pytest.raises(RuntimeError, match="metal"):
        _arm(tmp_path)


def test_a_run_cypher_step_answering_neo4j_down_aborts_the_run(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        kw["on_step"](dict(STEP, kind="run_cypher", error="ServiceUnavailable: connection refused"))
        kw["on_step"](dict(STEP))                                 # the session still "finished"
        return [Lead(index=0, shape="LM", text="t", evidence="e", confidence="LOW", file="a.py", line=1)]
    _seams(monkeypatch, discover=fake_discover)
    res = _arm(tmp_path)
    assert res.status == "aborted" and res.findings_path is None
    assert len(res.steps) == 2 and len(res.usage) == 2          # the tokens it spent are still handed back


def test_a_query_error_that_merely_mentions_the_word_is_not_a_machine_failure(tmp_path, monkeypatch):
    def fake_discover(scan_id, repo, on_event, **kw):
        kw["on_step"](dict(STEP, kind="run_cypher",
                           error="CypherSyntaxError: Invalid input 'ServiceUnavailable: x'"))
        kw["on_step"](dict(STEP))
        return []
    _seams(monkeypatch, discover=fake_discover)
    assert _arm(tmp_path).status == "ok"


def test_discovery_raising_a_neo4j_error_is_aborted(tmp_path, monkeypatch):
    from neo4j.exceptions import ServiceUnavailable

    def fake_discover(scan_id, repo, on_event, **kw):
        raise ServiceUnavailable("gone")
    rec = _seams(monkeypatch, discover=fake_discover)
    assert _arm(tmp_path).status == "aborted" and rec["order"][-1] == "release"


def test_real_engine_batches_failing_on_neo4j_are_aborted(tmp_path, monkeypatch):
    """A session that raises SessionExpired (the bolt connection dropped mid-batch) becomes discover_lm's
    "batch N (...) failed: SessionExpired: ..." event; every batch failing that way is aborted, not crashed."""
    class NeoModel(_Model):
        def generate(self, messages):
            from neo4j.exceptions import SessionExpired
            self.calls += 1
            raise SessionExpired("dropped")
    res, lines = _real_engine(monkeypatch, tmp_path, db=_GraphStub(n=2), model=NeoModel())
    assert res.status == "aborted" and res.findings_path is None
    assert sum("[discover/error]" in l for l in lines) == 2
