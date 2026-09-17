import sqlite3
from eval import db


def test_schema_and_run_lifecycle(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="orion-gemma4", repo="nocobase-1", tier="headline",
                       run_no=1, model_tag="gemma3:12b", cli_versions="ollama=0.30.11",
                       orion_commit="ec3e9d8")
    assert isinstance(rid, int)
    db.log_event(conn, rid, stage="build", level="info", message="graph done")
    db.log_agent_call(conn, rid, session_id="s1", stage="discover", input_tokens=100,
                      output_tokens=20, cache_read=0, cache_write=0, turns_used=5,
                      turn_limit=40, peak_context=1200, exit_reason="stop", error_head=None)
    db.log_resource(conn, rid, phase="build", wall_seconds=42.0, peak_rss_mb=493.0,
                    graph_nodes=1000, graph_edges=2000, loc=59000)
    db.finish_run(conn, rid, "ok")
    row = conn.execute("select status, ended from runs where id=?", (rid,)).fetchone()
    assert row[0] == "ok" and row[1] is not None


def test_failures_view_lists_only_bad_runs(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    ok = db.start_run(conn, arm="a", repo="r", tier="headline", run_no=1, model_tag="m",
                      cli_versions="", orion_commit="c")
    db.finish_run(conn, ok, "ok")
    bad = db.start_run(conn, arm="a", repo="r", tier="headline", run_no=2, model_tag="m",
                       cli_versions="", orion_commit="c")
    db.log_event(conn, bad, stage="verify", level="error", message="boom")
    db.finish_run(conn, bad, "crashed")
    rows = conn.execute("select distinct run_id from failures").fetchall()
    assert [r[0] for r in rows] == [bad]
