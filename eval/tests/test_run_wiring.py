import os

import pytest

from eval import run


def _meta(commit, **kw):
    return dict({"id": "r1", "commit_sha": commit, "commit_kind": "vulnerable",
                 "case_id": "", "run_no": 1, "attempt_no": 1, "mirror_dir": "/m"}, **kw)


def test_build_launcher_dispatches_exports_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    called = {"orion_scan_ids": [], "exports": [], "repo_dirs": []}

    def fake_export(mirror, sha, dest, **kw):
        called["exports"].append((mirror, sha, dest))
        os.makedirs(dest)
        open(os.path.join(dest, "a.js"), "w").write("x")

    def fake_orion(**kw):
        called["orion_scan_ids"].append(kw["scan_id"])
        called["repo_dirs"].append(kw["repo_dir"])
        assert os.path.exists(os.path.join(kw["repo_dir"], "a.js"))
        open(kw["json_out"], "w").write("[]")
        return "ok", "built-" + os.path.basename(os.path.dirname(os.path.dirname(kw["repo_dir"])))

    def fake_plain(**kw):
        called["plain"] = kw["arm"]
        called["repo_dirs"].append(kw["repo_dir"])
        open(kw["json_out"], "w").write("[]")
        return "ok", "path"
    cache = {}
    launcher = run.build_launcher(ollama_url="u", base_env={}, shim_dir="/s", graph_cache=cache,
                                  _orion=fake_orion, _plain=fake_plain, _export=fake_export)
    s1, out1 = launcher("orion-gemma4", _meta("c1"), "gemma3:12b", lambda l: None)
    launcher("orion-gptoss20b", _meta("c1", run_no=2), "gptoss", lambda l: None)
    launcher("orion-gemma4", _meta("c2"), "gemma3:12b", lambda l: None)
    s3, out3 = launcher("plain-opus5", _meta("c1", attempt_no=2), "opus", lambda l: None)
    # c1 first run built, second reused; a different commit does not reuse
    assert called["orion_scan_ids"][1] == cache[("r1", "c1")]
    assert called["orion_scan_ids"][2] is None
    assert called["orion_scan_ids"][0] is None
    assert len(cache) == 2 and ("r1", "c1") in cache and ("r1", "c2") in cache
    assert called["plain"] == "plain-opus5"
    run_dir = "eval/runs/orion-gemma4/r1/c1/_/1"
    assert called["exports"][0] == ("/m", "c1", f"{run_dir}/tree")
    assert called["repo_dirs"][0] == f"{run_dir}/tree"
    assert not os.path.exists(f"{run_dir}/tree")            # tree deleted
    assert os.path.exists(f"{run_dir}/findings.orion.json")  # findings kept
    assert out1 == f"{run_dir}/findings.orion.json"
    assert out3 == "eval/runs/plain-opus5/r1/c1/_/1.a2/findings.json"
    assert os.path.exists(out3)


def test_build_launcher_deletes_tree_on_failure(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def fake_export(mirror, sha, dest, **kw):
        os.makedirs(dest)

    def boom(**kw):
        raise RuntimeError("x")
    launcher = run.build_launcher(ollama_url="u", base_env={}, shim_dir="/s", graph_cache={},
                                  _plain=boom, _export=fake_export)
    with pytest.raises(RuntimeError):
        launcher("plain-opus5", _meta("c1", case_id="k"), "opus", lambda l: None)
    assert not os.path.exists("eval/runs/plain-opus5/r1/c1/k/1/tree")


def test_git_head_returns_string():
    assert isinstance(run.git_head("."), str)
