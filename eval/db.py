import sqlite3
from datetime import datetime, timezone


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY, arm TEXT, repo TEXT, tier TEXT, run_no INTEGER,
  model_tag TEXT, cli_versions TEXT, orion_commit TEXT,
  started TEXT, ended TEXT, status TEXT);
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
CREATE VIEW IF NOT EXISTS failures AS
  SELECT r.id AS run_id, r.arm, r.repo, r.run_no, r.status, e.stage, e.level, e.message
  FROM runs r LEFT JOIN events e ON e.run_id = r.id AND e.level = 'error'
  WHERE r.status != 'ok';
"""


def connect(path: str = "eval/runs.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def start_run(conn, *, arm, repo, tier, run_no, model_tag, cli_versions, orion_commit) -> int:
    cur = conn.execute(
        "INSERT INTO runs(arm,repo,tier,run_no,model_tag,cli_versions,orion_commit,started,status)"
        " VALUES(?,?,?,?,?,?,?,?,'running')",
        (arm, repo, tier, run_no, model_tag, cli_versions, orion_commit, _utc()))
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
