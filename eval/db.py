import sqlite3
from datetime import datetime, timezone


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


_RUNS_DDL = """CREATE TABLE {name} (
  id INTEGER PRIMARY KEY, arm TEXT, repo TEXT, tier TEXT, run_no INTEGER,
  model_tag TEXT, cli_versions TEXT, orion_commit TEXT,
  started TEXT, ended TEXT, status TEXT,
  commit_kind TEXT, commit_sha TEXT, case_id TEXT DEFAULT '',
  attempt_no INTEGER DEFAULT 1, effort TEXT DEFAULT '',
  UNIQUE(arm, repo, commit_sha, case_id, run_no, attempt_no))"""

_FAILURES_VIEW = """CREATE VIEW IF NOT EXISTS failures AS
  SELECT r.id AS run_id, r.arm, r.repo, r.run_no, r.status, e.stage, e.level, e.message
  FROM runs r LEFT JOIN events e ON e.run_id = r.id AND e.level = 'error'
  WHERE r.status != 'ok';"""

_SCHEMA = """
{runs_ddl};
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, run_id INTEGER, ts TEXT, stage TEXT, level TEXT, message TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(id));
CREATE TABLE IF NOT EXISTS agent_calls (
  id INTEGER PRIMARY KEY, run_id INTEGER, session_id TEXT, stage TEXT,
  input_tokens INTEGER, output_tokens INTEGER, cache_read INTEGER, cache_write INTEGER,
  turns_used INTEGER, turn_limit INTEGER, peak_context INTEGER,
  exit_reason TEXT, error_head TEXT, FOREIGN KEY(run_id) REFERENCES runs(id));
CREATE TABLE IF NOT EXISTS resources (
  id INTEGER PRIMARY KEY, run_id INTEGER, phase TEXT, wall_seconds REAL,
  peak_rss_mb REAL, graph_nodes INTEGER, graph_edges INTEGER, loc INTEGER,
  FOREIGN KEY(run_id) REFERENCES runs(id));
CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY, run_id INTEGER, step_no INTEGER, kind TEXT, query TEXT,
  row_count INTEGER, prompt_tokens INTEGER, completion_tokens INTEGER, cached_tokens INTEGER,
  wall_seconds REAL, error TEXT, FOREIGN KEY(run_id) REFERENCES runs(id));
CREATE TABLE IF NOT EXISTS matches (
  id INTEGER PRIMARY KEY, run_id INTEGER, vuln_id TEXT, finding_idx INTEGER, level TEXT,
  cwe_family TEXT, path_level TEXT, FOREIGN KEY(run_id) REFERENCES runs(id));
{failures_view}
"""
_SCHEMA = (_SCHEMA
          .replace("{runs_ddl}", _RUNS_DDL.format(name="IF NOT EXISTS runs"))
          .replace("{failures_view}", _FAILURES_VIEW))


_CURRENT_VERSION = 2

_NEW_RUN_COLS = (
    ("commit_kind", "TEXT"),
    ("commit_sha", "TEXT"),
    ("case_id", "TEXT DEFAULT ''"),
    ("attempt_no", "INTEGER DEFAULT 1"),
    ("effort", "TEXT DEFAULT ''"),
)

_RUN_COLS = ("id, arm, repo, tier, run_no, model_tag, cli_versions, orion_commit, started, ended,"
             " status, commit_kind, commit_sha, case_id, attempt_no, effort")


def _migrate(conn) -> None:
    """Upgrade an older DB in place (PRAGMA user_version ladder); a fresh DB just gets stamped.
    All-or-nothing: one explicit transaction (sqlite3 would otherwise autocommit the DDL)."""
    if conn.execute("PRAGMA user_version").fetchone()[0] >= _CURRENT_VERSION:
        return
    old_iso = conn.isolation_level
    conn.isolation_level = None
    conn.execute("BEGIN")
    try:
        have = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
        for name, decl in _NEW_RUN_COLS:
            if name not in have:
                conn.execute(f"ALTER TABLE runs ADD COLUMN {name} {decl}")
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='runs'").fetchone()[0]
        if "UNIQUE" not in sql.upper():
            # SQLite can't add a UNIQUE constraint in place: rebuild runs, keeping the old rows.
            conn.execute("DROP VIEW IF EXISTS failures")
            conn.execute("DROP TABLE IF EXISTS runs_new")
            conn.execute(_RUNS_DDL.format(name="runs_new"))
            conn.execute(f"INSERT INTO runs_new({_RUN_COLS}) SELECT {_RUN_COLS} FROM runs")
            conn.execute("DROP TABLE runs")
            conn.execute("ALTER TABLE runs_new RENAME TO runs")
            conn.execute(_FAILURES_VIEW)
        conn.execute(f"PRAGMA user_version = {_CURRENT_VERSION}")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.isolation_level = old_iso


def connect(path: str = "eval/runs.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    conn.commit()
    _migrate(conn)
    return conn


def start_run(conn, *, arm, repo, tier, run_no, model_tag, cli_versions, orion_commit,
              commit_kind: str = "", commit_sha: str = "", case_id: str = "",
              attempt_no: int = 1, effort: str = "") -> int:
    cur = conn.execute(
        "INSERT INTO runs(arm,repo,tier,run_no,model_tag,cli_versions,orion_commit,started,status,"
        "commit_kind,commit_sha,case_id,attempt_no,effort)"
        " VALUES(?,?,?,?,?,?,?,?,'running',?,?,?,?,?)",
        (arm, repo, tier, run_no, model_tag, cli_versions, orion_commit, _utc(),
         commit_kind, commit_sha, case_id, attempt_no, effort))
    conn.commit()
    return cur.lastrowid


def finish_run(conn, run_id, status) -> None:
    conn.execute("UPDATE runs SET ended=?, status=? WHERE id=?", (_utc(), status, run_id))
    conn.commit()


def log_event(conn, run_id, *, stage, level, message) -> None:
    conn.execute("INSERT INTO events(run_id,ts,stage,level,message) VALUES(?,?,?,?,?)",
                 (run_id, _utc(), stage, level, message))
    conn.commit()


def log_agent_call(conn, run_id, *, session_id, stage, input_tokens, output_tokens,
                   cache_read, cache_write, turns_used, turn_limit, peak_context,
                   exit_reason, error_head) -> None:
    conn.execute(
        "INSERT INTO agent_calls(run_id,session_id,stage,input_tokens,output_tokens,cache_read,"
        "cache_write,turns_used,turn_limit,peak_context,exit_reason,error_head)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (run_id, session_id, stage, input_tokens, output_tokens, cache_read, cache_write,
         turns_used, turn_limit, peak_context, exit_reason, error_head))
    conn.commit()


def log_resource(conn, run_id, *, phase, wall_seconds, peak_rss_mb, graph_nodes,
                 graph_edges, loc) -> None:
    conn.execute(
        "INSERT INTO resources(run_id,phase,wall_seconds,peak_rss_mb,graph_nodes,graph_edges,loc)"
        " VALUES(?,?,?,?,?,?,?)",
        (run_id, phase, wall_seconds, peak_rss_mb, graph_nodes, graph_edges, loc))
    conn.commit()


def log_step(conn, run_id, *, step_no, kind, query, row_count, prompt_tokens,
             completion_tokens, cached_tokens, wall_seconds, error) -> None:
    conn.execute(
        "INSERT INTO steps(run_id,step_no,kind,query,row_count,prompt_tokens,completion_tokens,"
        "cached_tokens,wall_seconds,error) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (run_id, step_no, kind, query, row_count, prompt_tokens, completion_tokens,
         cached_tokens, wall_seconds, error))
    conn.commit()


def next_attempt(conn, *, arm, repo, commit_sha, case_id, run_no) -> int:
    row = conn.execute(
        "SELECT MAX(attempt_no) FROM runs WHERE arm=? AND repo=? AND commit_sha=? AND case_id=?"
        " AND run_no=?", (arm, repo, commit_sha, case_id, run_no)).fetchone()
    return (row[0] or 0) + 1
