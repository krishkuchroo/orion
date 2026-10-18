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

def test_v1_db_upgrades_in_place(tmp_path):
    # Simulate a v1 DB (no commit cols, no steps/matches), then connect() upgrades it.
    p = str(tmp_path / "old.db")
    raw = sqlite3.connect(p)
    raw.executescript("CREATE TABLE runs (id INTEGER PRIMARY KEY, arm TEXT, repo TEXT, tier TEXT,"
                       " run_no INTEGER, model_tag TEXT, cli_versions TEXT, orion_commit TEXT,"
                       " started TEXT, ended TEXT, status TEXT);")
    raw.execute("INSERT INTO runs(arm) VALUES('legacy')"); raw.commit(); raw.close()
    conn = db.connect(p)
    assert conn.execute("SELECT arm FROM runs").fetchone()[0] == "legacy"  # data preserved
    assert {"commit_kind", "commit_sha"} <= {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
