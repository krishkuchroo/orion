from eval import run


def test_build_launcher_dispatches_and_reuses_graph():
    called = {}

    def fake_orion(**kw):
        called.setdefault("orion_scan_ids", []).append(kw["scan_id"])
        return "ok", "built-sid"        # returns (status, scan_id)

    def fake_plain(**kw):
        called["plain"] = kw["arm"]
        return "ok", "path"
    cache = {}
    launcher = run.build_launcher(ollama_url="u", base_env={}, shim_dir="/s",
                                  graph_cache=cache, _orion=fake_orion, _plain=fake_plain)
    launcher("orion-gemma4", {"id": "r1", "repo_dir": "/tmp/r1"}, "gemma3:12b", lambda l: None)
    launcher("orion-gptoss20b", {"id": "r1", "repo_dir": "/tmp/r1"}, "gptoss", lambda l: None)
    launcher("plain-opus5", {"id": "r1", "repo_dir": "/tmp/r1"}, "opus", lambda l: None)
    # first orion run built (scan_id None), second reused the cached "built-sid"
    assert called["orion_scan_ids"] == [None, "built-sid"]
    assert cache["r1"] == "built-sid"
    assert called["plain"] == "plain-opus5"


def test_git_head_returns_string():
    assert isinstance(run.git_head("."), str)
