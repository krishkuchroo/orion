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


def test_orion_arms_raise_until_task_f3(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_export(mirror, sha, dest, **kw):
        os.makedirs(dest)
    launcher = _launcher(tmp_path, _export=fake_export, _plain=lambda **kw: pytest.fail("plain ran"))
    with pytest.raises(NotImplementedError, match="F3"):
        launcher("orion-lm", _meta("c1"), "m", lambda l: None, effort="", on_start=None)
    assert not os.path.exists(tmp_path / "trees/orion-lm/r1/c1/_/1/tree")   # tree still cleaned up


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
