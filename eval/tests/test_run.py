from eval import db, run


def test_run_one_records_status_from_launcher(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line):
        on_line('{"type":"result"}')
        return "ok", str(tmp_path / "f.json")
    status = run.run_one(conn, arm="plain-opus5",
                         repo_meta={"id": "r1", "tier": "headline"}, run_no=1,
                         model_tags={}, ollama_url="u", base_env={}, orion_commit="c",
                         cli_versions="claude=2.1.210", launcher=launcher)
    assert status == "ok"
    row = conn.execute("select status, cli_versions from runs where arm='plain-opus5'").fetchone()
    assert row[0] == "ok" and row[1] == "claude=2.1.210"


def test_run_one_catches_launcher_exception(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def boom(arm, repo_meta, model_tag, on_line):
        raise RuntimeError("launch failed")
    status = run.run_one(conn, arm="orion-gemma4",
                         repo_meta={"id": "r1", "tier": "headline"}, run_no=1,
                         model_tags={"orion-gemma4": "gemma3:12b"}, ollama_url="u",
                         base_env={}, orion_commit="c", cli_versions="", launcher=boom)
    assert status == "error"
    err = conn.execute("select message from events where level='error'").fetchone()
    assert "launch failed" in err[0]
