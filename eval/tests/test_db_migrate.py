import sqlite3
from eval import db

def test_fresh_db_has_commit_cols_steps_matches(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
    assert {"commit_kind", "commit_sha", "case_id", "attempt_no", "effort"} <= cols
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"steps", "matches"} <= names
    assert conn.execute("PRAGMA user_version").fetchone()[0] >= 2

def test_start_run_records_commit_and_unique(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    db.start_run(conn, arm="orion-lm", repo="r", tier="headline", run_no=1, model_tag="m",
                 cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="deadbeef")
    import pytest
    with pytest.raises(sqlite3.IntegrityError):  # same (arm,repo,commit_sha,case_id,run_no,attempt_no) rejected
        db.start_run(conn, arm="orion-lm", repo="r", tier="headline", run_no=1, model_tag="m",
                     cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="deadbeef")
    # a different OWASP case on the same commit, or a retry attempt, is allowed
    db.start_run(conn, arm="orion-lm", repo="r", tier="headline", run_no=1, model_tag="m",
                 cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="deadbeef",
                 case_id="BenchmarkTest00001")
    assert db.next_attempt(conn, arm="orion-lm", repo="r", commit_sha="deadbeef", case_id="", run_no=1) == 2

def test_log_step_roundtrips(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="orion-lm", repo="r", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind="patched", commit_sha="abc")
    db.log_step(conn, rid, step_no=0, kind="run_cypher", query="MATCH (n) RETURN n", row_count=3,
                prompt_tokens=100, completion_tokens=20, cached_tokens=0, wall_seconds=0.5, error=None)
    row = conn.execute("SELECT kind, row_count FROM steps WHERE run_id=?", (rid,)).fetchone()
    assert row == ("run_cypher", 3)

def _make_v1(p):
    raw = sqlite3.connect(p)
    raw.executescript(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY, arm TEXT, repo TEXT, tier TEXT,"
        " run_no INTEGER, model_tag TEXT, cli_versions TEXT, orion_commit TEXT,"
        " started TEXT, ended TEXT, status TEXT);"
        "CREATE TABLE events (id INTEGER PRIMARY KEY, run_id INTEGER, ts TEXT, stage TEXT,"
        " level TEXT, message TEXT, FOREIGN KEY(run_id) REFERENCES runs(id));"
        "CREATE VIEW failures AS SELECT r.id AS run_id, r.arm, r.repo, r.run_no, r.status,"
        " e.stage, e.level, e.message FROM runs r LEFT JOIN events e ON e.run_id = r.id"
        " AND e.level = 'error' WHERE r.status != 'ok';")
    for i, st in enumerate(["ok", "crashed", "hung"], 1):
        raw.execute("INSERT INTO runs(arm,repo,run_no,status) VALUES('legacy','r',?,?)", (i, st))
    raw.execute("INSERT INTO events(run_id,ts,stage,level,message) VALUES(2,'t','s','error','boom')")
    raw.commit(); raw.close()


def test_v1_db_upgrades_in_place(tmp_path):
    import pytest
    p = str(tmp_path / "old.db")
    _make_v1(p)
    conn = db.connect(p)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db._CURRENT_VERSION == 3
    assert conn.execute("SELECT count(*) FROM runs").fetchone()[0] == 3
    assert {"commit_kind", "commit_sha"} <= {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    assert {r[0] for r in conn.execute("SELECT run_id FROM failures")} == {2, 3}
    assert conn.execute("SELECT DISTINCT case_id, attempt_no FROM runs").fetchall() == [("", 1)]
    kw = dict(arm="n", repo="r", tier="t", run_no=1, model_tag="m", cli_versions="",
              orion_commit="c", commit_sha="s")
    db.start_run(conn, **kw)
    with pytest.raises(sqlite3.IntegrityError):
        db.start_run(conn, **kw)
    # second connect is a no-op
    conn.close()
    conn2 = db.connect(p)
    assert conn2.execute("PRAGMA user_version").fetchone()[0] == 3
    assert conn2.execute("SELECT count(*) FROM runs").fetchone()[0] == 4


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    import pytest
    p = str(tmp_path / "old.db")
    _make_v1(p)
    monkeypatch.setattr(db, "_FAILURES_VIEW", "CREATE VIEW broken AS SELECT nope FROM nothing")
    with pytest.raises(sqlite3.Error):
        db.connect(p)
    raw = sqlite3.connect(p)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 0
    names = {r[0] for r in raw.execute("SELECT name FROM sqlite_master")}
    assert "runs_new" not in names and "failures" in names
    assert "commit_kind" not in {r[1] for r in raw.execute("PRAGMA table_info(runs)")}


def _make_v2(p):
    """A v2 DB as the harness wrote it before resources.mlx_peak_mb (I8), with one resources row."""
    raw = sqlite3.connect(p)
    raw.executescript(db._SCHEMA.replace(" mlx_peak_mb REAL,", ""))
    raw.execute("INSERT INTO runs(arm,repo,run_no,status,commit_sha) VALUES('orion-lm','r',1,'ok','s')")
    raw.execute("INSERT INTO resources(run_id,phase,wall_seconds,peak_rss_mb) VALUES(1,'run',12.5,800.0)")
    raw.execute("PRAGMA user_version = 2")
    raw.commit()
    assert "mlx_peak_mb" not in {r[1] for r in raw.execute("PRAGMA table_info(resources)")}
    raw.close()


def test_v2_db_gains_resources_mlx_peak_mb(tmp_path):
    p = str(tmp_path / "v2.db")
    _make_v2(p)
    conn = db.connect(p)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    assert "mlx_peak_mb" in {r[1] for r in conn.execute("PRAGMA table_info(resources)")}
    assert conn.execute("SELECT phase, wall_seconds, peak_rss_mb, mlx_peak_mb FROM resources").fetchall() \
        == [("run", 12.5, 800.0, None)]                 # old rows kept; the new column is missing, not 0
    db.log_resource(conn, 1, phase="run", wall_seconds=1.0, peak_rss_mb=None, graph_nodes=None,
                    graph_edges=None, loc=None, mlx_peak_mb=512.0)
    assert conn.execute("SELECT mlx_peak_mb FROM resources ORDER BY id").fetchall() == [(None,), (512.0,)]


def test_fresh_db_has_mlx_peak_mb_and_old_callers_still_log(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    assert "mlx_peak_mb" in {r[1] for r in conn.execute("PRAGMA table_info(resources)")}
    db.log_resource(conn, 1, phase="build", wall_seconds=3.0, peak_rss_mb=900.0, graph_nodes=None,
                    graph_edges=None, loc=None)
    assert conn.execute("SELECT phase, mlx_peak_mb FROM resources").fetchall() == [("build", None)]
