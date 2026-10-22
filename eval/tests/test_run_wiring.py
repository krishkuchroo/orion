import os

import pytest

from eval import run
from eval.arms import ArmResult


def _meta(commit, **kw):
    return dict({"id": "r1", "commit_sha": commit, "commit_kind": "vulnerable",
                 "case_id": "", "run_no": 1, "attempt_no": 1, "mirror_dir": "/m"}, **kw)


def _launcher(tmp_path, **kw):
    base = dict(base_env={}, shim_dir="/s", graph_cache={}, tree_root=str(tmp_path / "trees"))
    base.update(kw)
    return run.build_launcher(**base)


def test_build_launcher_dispatches_exports_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    called = {"exports": [], "plain": []}

    def fake_export(mirror, sha, dest, **kw):
        called["exports"].append((mirror, sha, dest))
        os.makedirs(dest)
        open(os.path.join(dest, "a.js"), "w").write("x")

    def fake_plain(**kw):
        called["plain"].append(kw)
        assert os.path.exists(os.path.join(kw["repo_dir"], "a.js"))
        open(kw["json_out"], "w").write('{"findings": []}')
        return ArmResult(status="ok", findings_path=kw["json_out"],
                         usage=[{"uncached_in": 1, "cache_read": None, "cache_write": None,
                                 "out": 2, "reasoning": None}])
    launcher = _launcher(tmp_path, _plain=fake_plain, _export=fake_export)
    res1 = launcher("plain-opus5", _meta("c1"), "opus", lambda l: None, effort="xhigh", on_start=None)
    res3 = launcher("plain-gpt", _meta("c1", attempt_no=2), "gpt", lambda l: None, effort="", on_start=None)
    assert isinstance(res1, ArmResult) and res1.usage[0]["uncached_in"] == 1
    kw1, kw3 = called["plain"]
    assert kw1["arm"] == "plain-opus5" and kw3["arm"] == "plain-gpt"
    assert kw1["effort"] == "xhigh" and kw1["model_tag"] == "opus"
    assert "ollama_url" not in kw1
    run_dir = str(tmp_path / "eval/runs/plain-opus5/r1/c1/_/1")
    tree = str(tmp_path / "trees/plain-opus5/r1/c1/_/1/tree")
    assert called["exports"][0] == ("/m", "c1", tree)
    assert kw1["repo_dir"] == tree
    assert kw1["usage_log"] == f"{run_dir}/usage.jsonl"
    assert not os.path.exists(tree)                          # tree deleted
    assert res1.findings_path == f"{run_dir}/findings.json"  # findings kept in the run dir
    assert os.path.exists(res1.findings_path)
    assert res3.findings_path == str(tmp_path / "eval/runs/plain-gpt/r1/c1/_/1.a2/findings.json")
    for kw in called["plain"]:
        assert all(os.path.isabs(kw[k]) for k in ("repo_dir", "json_out", "usage_log"))
        assert not kw["repo_dir"].startswith(str(tmp_path / "eval"))


def test_build_launcher_forwards_on_start(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    marker = object()
    seen = {}

    def fake_plain(**kw):
        seen["on_start"] = kw["on_start"]
        return ArmResult(status="ok", findings_path=None, usage=[])
    launcher = _launcher(tmp_path, _plain=fake_plain, _export=lambda *a, **k: os.makedirs(a[2]))
    launcher("plain-opus5", _meta("c1"), "opus", lambda l: None, effort="xhigh", on_start=marker)
    assert seen["on_start"] is marker


def test_build_launcher_deletes_tree_on_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_export(mirror, sha, dest, **kw):
        os.makedirs(dest)

    def boom(**kw):
        raise RuntimeError("x")
    launcher = _launcher(tmp_path, _plain=boom, _export=fake_export)
    with pytest.raises(RuntimeError):
        launcher("plain-opus5", _meta("c1", case_id="k"), "opus", lambda l: None, effort="", on_start=None)
    assert not os.path.exists(tmp_path / "trees/plain-opus5/r1/c1/k/1/tree")


@pytest.mark.parametrize("arm", ["orion-lm", "orion-lm-base"])
def test_orion_lm_arms_dispatch_to_the_in_process_arm(tmp_path, monkeypatch, arm):
    """The default _lm seam runs eval.arms.lm.orion_lm_arm in-process (no `orion scan`, no plain)."""
    from eval.arms import lm
    monkeypatch.chdir(tmp_path)
    cache, seen = {}, {}

    def fake_arm(**kw):
        seen.update(kw)
        assert os.path.isdir(kw["repo_dir"])                 # the tree exists while the arm runs
        return ArmResult(status="ok", findings_path=None, usage=[], steps=[])
    monkeypatch.setattr(lm, "orion_lm_arm", fake_arm)
    launcher = _launcher(tmp_path, graph_cache=cache, _export=lambda *a, **k: os.makedirs(a[2]),
                         _plain=lambda **kw: pytest.fail("plain ran"))
    marker = object()
    res = launcher(arm, _meta("c1", run_no=3, case_id="k"), "/models/m", lambda l: None,
                   effort="", on_start=marker)
    assert res.status == "ok"
    assert seen["arm"] == arm and seen["model_tag"] == "/models/m" and seen["graph_cache"] is cache
    assert (seen["run_no"], seen["case_id"], seen["repo_id"], seen["commit_sha"]) == (3, "k", "r1", "c1")
    assert seen["on_start"] is marker
    assert seen["json_out"] == str(tmp_path / f"eval/runs/{arm}/r1/c1/k/3/findings.json")
    assert not os.path.exists(tmp_path / f"trees/{arm}/r1/c1/k/3/tree")   # tree still cleaned up


def test_unknown_orion_arm_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    launcher = _launcher(tmp_path, _export=lambda *a, **k: os.makedirs(a[2]),
                         _lm=lambda **kw: pytest.fail("lm ran"),
                         _plain=lambda **kw: pytest.fail("plain ran"))
    with pytest.raises(ValueError, match="orion-scan"):
        launcher("orion-scan", _meta("c1"), "m", lambda l: None, effort="", on_start=None)


def test_run_one_logs_an_lm_step_exactly_once(tmp_path, monkeypatch):
    """Full chain: run_one -> build_launcher -> _default_lm -> orion_lm_arm (heavy seams stubbed).
    The arm returns its steps; run_one is the only writer of the steps table."""
    from eval import db
    from eval.arms import lm
    monkeypatch.chdir(tmp_path)
    step = {"step_no": 1, "kind": "final", "query": None, "row_count": None, "prompt_tokens": 50,
            "completion_tokens": 5, "cached_tokens": 20, "wall_seconds": 0.1, "error": None}

    def fake_discover(scan_id, repo, on_event, **kw):
        kw["on_step"](dict(step))
        return []
    monkeypatch.setattr(lm, "_build_graph", lambda repo_dir, on_event: "s1")
    monkeypatch.setattr(lm, "_load_model", lambda path, **kw: object())
    monkeypatch.setattr(lm, "_discover", fake_discover)
    monkeypatch.setattr(lm, "_pathfind_error", lambda sid: None)
    model = tmp_path / "model"
    model.mkdir()
    conn = db.connect(str(tmp_path / "t.db"))
    launcher = _launcher(tmp_path, _export=lambda *a, **k: os.makedirs(a[2]))
    status = run.run_one(conn, arm="orion-lm", repo_meta=_meta("c1"), run_no=2,
                         model_tags={"orion-lm": str(model)}, base_env={}, orion_commit="c",
                         cli_versions="", launcher=launcher)
    assert status == "ok"
    rid, model_tag = conn.execute("SELECT id, model_tag FROM runs").fetchone()
    assert model_tag == str(model)
    assert conn.execute("SELECT run_id, step_no, prompt_tokens, cached_tokens FROM steps").fetchall() \
        == [(rid, 1, 50, 20)]
    assert conn.execute("SELECT input_tokens, cache_read, cache_write, output_tokens FROM agent_calls"
                        ).fetchall() == [(30, 20, 0, 5)]
    rss = conn.execute("SELECT peak_rss_mb FROM resources").fetchone()[0]
    assert rss is None or rss > 0       # sampled on this process (on_start), never a guessed 0
    findings = tmp_path / "eval/runs/orion-lm/r1/c1/_/2/findings.json"
    assert findings.read_text().strip() == "[]"


def test_lm_seam_receives_tree_and_graph_cache(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = {}
    seen = {}

    def fake_lm(**kw):
        seen.update(kw)
        return ArmResult(status="ok", findings_path=None, usage=[])
    launcher = _launcher(tmp_path, graph_cache=cache, _lm=fake_lm,
                         _export=lambda *a, **k: os.makedirs(a[2]))
    res = launcher("orion-lm", _meta("c1"), "m", lambda l: None, effort="", on_start=None)
    assert res.status == "ok"
    assert seen["arm"] == "orion-lm" and seen["graph_cache"] is cache
    assert seen["repo_dir"] == str(tmp_path / "trees/orion-lm/r1/c1/_/1/tree")
    assert seen["json_out"] == str(tmp_path / "eval/runs/orion-lm/r1/c1/_/1/findings.json")


def test_git_head_returns_string():
    assert isinstance(run.git_head("."), str)


def test_leak_guard_rejects_tree_under_repo_marker(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("x")
    launcher = _launcher(tmp_path, tree_root=str(tmp_path / "t"), _export=lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="CLAUDE.md"):
        launcher("plain-opus5", _meta("c1"), "opus", lambda l: None, effort="", on_start=None)


# ---- OWASP items (Task F2): answers stripped right after the export, for every arm -------------

OWASP_CASE = {"case_id": "BenchmarkTest00001", "category": "sqli", "real": True, "cwe": "CWE-89",
              "file": "testcode/BenchmarkTest00001.py",
              "entry": "POST /benchmark/sqli-00/BenchmarkTest00001 -> BenchmarkTest00001_post"}


def _owasp_meta(**kw):
    return _meta("pin1", id="owasp-python", commit_kind="owasp", tier="owasp",
                 case_id="BenchmarkTest00001", case=OWASP_CASE, **kw)


def _export_with_answers(mirror, sha, dest, **kw):
    os.makedirs(os.path.join(dest, "testcode"))
    open(os.path.join(dest, "expectedresults-0.1.csv"), "w").write("BenchmarkTest00001,sqli,true,89\n")
    open(os.path.join(dest, "testcode", "BenchmarkTest00001.py"), "w").write("x")


@pytest.mark.parametrize("arm", ["plain-opus5", "plain-sonnet5", "plain-gpt", "orion-lm", "orion-lm-base"])
def test_launcher_strips_answers_for_owasp_items_for_every_arm(tmp_path, monkeypatch, arm):
    monkeypatch.chdir(tmp_path)
    seen, lines = {}, []

    def arm_fn(**kw):
        tree = kw["repo_dir"]
        seen.update(kw, files=sorted(os.listdir(tree)))
        return ArmResult(status="ok", findings_path=None, usage=[])
    launcher = _launcher(tmp_path, _plain=arm_fn, _lm=arm_fn, _export=_export_with_answers)
    launcher(arm, _owasp_meta(), "m", lines.append, effort="", on_start=None)
    assert seen["files"] == ["testcode"]                     # the answer file is gone before the arm runs
    assert seen["case"] == OWASP_CASE                        # the case's fields reach the arm
    assert any("expectedresults-0.1.csv" in l for l in lines)


def test_launcher_never_strips_a_manifest_item(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = {}

    def arm_fn(**kw):
        seen.update(kw, files=sorted(os.listdir(kw["repo_dir"])))
        return ArmResult(status="ok", findings_path=None, usage=[])
    launcher = _launcher(tmp_path, _plain=arm_fn, _export=_export_with_answers,
                         _strip=lambda tree: pytest.fail("stripped a manifest item"))
    launcher("plain-opus5", _meta("c1"), "m", lambda l: None, effort="", on_start=None)
    assert "expectedresults-0.1.csv" in seen["files"] and seen["case"] is None


def test_launcher_calls_strip_right_after_the_export(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    order = []

    def export(*a, **k):
        order.append("export")
        os.makedirs(a[2])

    def strip(tree):
        order.append("strip")
        return []

    def arm_fn(**kw):
        order.append("arm")
        return ArmResult(status="ok", findings_path=None, usage=[])
    launcher = _launcher(tmp_path, _plain=arm_fn, _export=export, _strip=strip)
    launcher("plain-gpt", _owasp_meta(), "m", lambda l: None, effort="", on_start=None)
    assert order == ["export", "strip", "arm"]
