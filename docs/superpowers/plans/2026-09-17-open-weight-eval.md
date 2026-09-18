# Open-weight Study Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the data-capture harness that runs the 6 study arms over the CVE dataset and records findings, tokens, timing, memory and failures into a queryable log — with no scoring.

**Architecture:** A new top-level `eval/` Python package, separate from `orion/` (Orion source is not modified). A SQLite run log (`eval/runs.db`) is the index; raw artifacts live on disk under `eval/runs/`. Each arm is a small module behind one interface; a resumable runner drives them sequentially through the 16 GB memory phases. Open-weight arms reuse Orion unchanged by setting environment variables (`ANTHROPIC_BASE_URL`, `ORION_MODEL`, `ANTHROPIC_DEFAULT_*_MODEL`) before invoking `orion scan`.

**Tech Stack:** Python 3.12, stdlib `sqlite3`, `subprocess`, `psutil` (peak RSS), `requests`/`gh` for the GitHub Advisory API, `cloc` for LOC, Ollama, Claude Code CLI, Codex CLI, Joern, Neo4j (Orion's existing Docker container).

**Spec:** `docs/superpowers/specs/2026-09-17-open-weight-eval-design.md`

## Global Constraints

- **Never fabricate, estimate, or backfill a measured value.** If a tool does not report a field machine-readably, store `NULL` and mark the run, never a guess. (spec §1, §7)
- **Orion source (`orion/`) is not modified by this study.** All new code lives under `eval/`. (spec §5)
- **Study machine: MacBook Pro, Apple M4, 16 GB.** Joern and a local model are never resident at the same time; each Orion run is phased build→reason. (spec §4)
- **Six arms, fixed ids:** `orion-gemma4`, `orion-gptoss20b`, `plain-gemma4`, `plain-sonnet5`, `plain-opus5`, `plain-gpt`. Orion only with open-weight models; Codex only with GPT. (spec §2)
- **3 runs per arm per repo**, sequential order arms 1→2→3 then 4→5→6. No time/token budget; a run is `hung` only after 60 min with no progress event. (spec §2, §5.4)
- **Dataset headline rule:** advisory date AND fix-commit date both after 2026-05-31; localized fix (≤10 non-test files, one bug); vulnerable code in JS/TS, Python, or Java. (spec §3.1)
- **No exploits.** `candidates.tsv`/`manifest.json` are the vulnerability catalog only. (spec §8a)
- **Nothing here scores.** Matching, cost-per-bug, intervals and labeling are a separate session. (spec §8)
- **Commit attribution:** NONE. Never add `Co-Authored-By: Claude` or a "Generated with Claude Code" line to commits or PRs (repo rule, CLAUDE.md top).
- Work on branch `eval/open-weight-study`. Run Python via `./.venv/bin/python`; run tests with `./.venv/bin/pytest`.

---

### Task 1: `eval/` package + SQLite run-log schema

**Files:**
- Create: `eval/__init__.py`
- Create: `eval/db.py`
- Test: `eval/tests/test_db.py`
- Create: `eval/tests/__init__.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `db.connect(path: str = "eval/runs.db") -> sqlite3.Connection` — opens and creates schema if absent (idempotent).
  - `db.start_run(conn, *, arm: str, repo: str, tier: str, run_no: int, model_tag: str, cli_versions: str, orion_commit: str) -> int` — inserts a `runs` row with `status='running'`, `started=<utc iso>`, returns `run_id`.
  - `db.finish_run(conn, run_id: int, status: str) -> None` — sets `ended`, `status` (`ok`/`hung`/`crashed`/`error`).
  - `db.log_event(conn, run_id: int, *, stage: str, level: str, message: str) -> None`
  - `db.log_agent_call(conn, run_id: int, *, session_id: str, stage: str, input_tokens: int|None, output_tokens: int|None, cache_read: int|None, cache_write: int|None, turns_used: int|None, turn_limit: int|None, peak_context: int|None, exit_reason: str|None, error_head: str|None) -> None`
  - `db.log_resource(conn, run_id: int, *, phase: str, wall_seconds: float, peak_rss_mb: float|None, graph_nodes: int|None, graph_edges: int|None, loc: int|None) -> None`
  - Schema includes a `failures` view: `runs` with `status != 'ok'` joined to their error events.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_db.py
import sqlite3
from eval import db

def test_schema_and_run_lifecycle(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="orion-gemma4", repo="nocobase-1", tier="headline",
                       run_no=1, model_tag="gemma4:latest", cli_versions="ollama=0.30.11",
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_db.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.db'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/db.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_db.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/__init__.py eval/db.py eval/tests/__init__.py eval/tests/test_db.py
git commit -m "eval: SQLite run-log schema (runs/events/agent_calls/resources + failures view)"
```

---

### Task 2: Claude Code / Codex usage parsers

**Files:**
- Create: `eval/usage.py`
- Test: `eval/tests/test_usage.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `usage.parse_claude_result(final: dict) -> dict` — from a Claude Code `{"type":"result"}` object, returns `{"input_tokens","output_tokens","cache_read","cache_write","total_cost_usd","exit_reason"}`, each key present with `None` when the field is absent. Reads `usage.input_tokens`, `usage.output_tokens`, `usage.cache_read_input_tokens`, `usage.cache_creation_input_tokens`, `total_cost_usd`, `subtype`.
  - `usage.parse_codex_event(event: dict) -> dict|None` — from a Codex `--json` line, returns the same dict shape for a `turn.completed` event (mapping `input_tokens`,`cached_input_tokens`,`output_tokens`; cost `None`), else `None`.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_usage.py
from eval import usage

def test_parse_claude_result_reads_usage_and_cost():
    final = {"type": "result", "subtype": "success", "total_cost_usd": 0.42,
             "usage": {"input_tokens": 1000, "output_tokens": 200,
                       "cache_read_input_tokens": 50, "cache_creation_input_tokens": 10}}
    out = usage.parse_claude_result(final)
    assert out == {"input_tokens": 1000, "output_tokens": 200, "cache_read": 50,
                   "cache_write": 10, "total_cost_usd": 0.42, "exit_reason": "success"}

def test_parse_claude_result_missing_fields_are_none():
    out = usage.parse_claude_result({"type": "result"})
    assert out["input_tokens"] is None and out["total_cost_usd"] is None

def test_parse_codex_turn_completed():
    ev = {"type": "turn.completed", "input_tokens": 300, "cached_input_tokens": 20,
          "output_tokens": 40, "reasoning_output_tokens": 15}
    out = usage.parse_codex_event(ev)
    assert out["input_tokens"] == 300 and out["cache_read"] == 20
    assert out["output_tokens"] == 40 and out["total_cost_usd"] is None

def test_parse_codex_ignores_other_events():
    assert usage.parse_codex_event({"type": "item.completed"}) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_usage.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.usage'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/usage.py
def parse_claude_result(final: dict) -> dict:
    u = final.get("usage") or {}
    return {
        "input_tokens": u.get("input_tokens"),
        "output_tokens": u.get("output_tokens"),
        "cache_read": u.get("cache_read_input_tokens"),
        "cache_write": u.get("cache_creation_input_tokens"),
        "total_cost_usd": final.get("total_cost_usd"),
        "exit_reason": final.get("subtype"),
    }

def parse_codex_event(event: dict):
    if event.get("type") != "turn.completed":
        return None
    return {
        "input_tokens": event.get("input_tokens"),
        "output_tokens": event.get("output_tokens"),
        "cache_read": event.get("cached_input_tokens"),
        "cache_write": None,
        "total_cost_usd": None,
        "exit_reason": "turn.completed",
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_usage.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/usage.py eval/tests/test_usage.py
git commit -m "eval: token/cost parsers for Claude Code result and Codex turn.completed"
```

---

### Task 3: Peak-RSS resource sampler

**Files:**
- Create: `eval/resources.py`
- Test: `eval/tests/test_resources.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `resources.PhaseSampler(pid: int, interval: float = 1.0)` — context manager; on exit exposes `.peak_rss_mb: float` and `.wall_seconds: float`. Samples the process tree RSS (the pid and its children) via `psutil` on a background thread. If `psutil` is unavailable or the process exits, `.peak_rss_mb` is `None` and the sampler never raises.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_resources.py
import os, time
from eval.resources import PhaseSampler

def test_sampler_measures_own_process_and_wall():
    with PhaseSampler(os.getpid(), interval=0.05) as s:
        blob = [0] * 1_000_000  # allocate to move RSS
        time.sleep(0.2)
        del blob
    assert s.wall_seconds >= 0.15
    assert s.peak_rss_mb is None or s.peak_rss_mb > 0

def test_sampler_survives_dead_pid():
    with PhaseSampler(2_000_000_000, interval=0.05) as s:  # pid that cannot exist
        pass
    assert s.peak_rss_mb is None or s.peak_rss_mb >= 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_resources.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.resources'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/resources.py
import threading, time

class PhaseSampler:
    def __init__(self, pid: int, interval: float = 1.0):
        self.pid = pid
        self.interval = interval
        self.peak_rss_mb = None
        self.wall_seconds = 0.0
        self._stop = threading.Event()
        self._t = None
        self._start = None

    def _sample_once(self):
        try:
            import psutil
            p = psutil.Process(self.pid)
            total = p.memory_info().rss
            for c in p.children(recursive=True):
                try:
                    total += c.memory_info().rss
                except psutil.Error:
                    pass
            mb = total / (1024 * 1024)
            if self.peak_rss_mb is None or mb > self.peak_rss_mb:
                self.peak_rss_mb = mb
        except Exception:
            pass  # psutil missing or process gone; leave peak as-is

    def _loop(self):
        while not self._stop.is_set():
            self._sample_once()
            self._stop.wait(self.interval)

    def __enter__(self):
        self._start = time.monotonic()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._t:
            self._t.join(timeout=2.0)
        self.wall_seconds = time.monotonic() - self._start
        return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_resources.py -v`
Expected: PASS (2 passed). If `psutil` is missing, install it: `./.venv/bin/pip install psutil` and re-run.

- [ ] **Step 5: Commit**

```bash
git add eval/resources.py eval/tests/test_resources.py
git commit -m "eval: background peak-RSS + wall-clock sampler over a process tree"
```

---

### Task 4: Dataset inclusion checker → manifest

**Files:**
- Create: `eval/dataset/check.py`
- Create: `eval/dataset/__init__.py`
- Test: `eval/tests/test_dataset_check.py`

**Interfaces:**
- Consumes: `eval/dataset/candidates.tsv` (already committed).
- Produces:
  - `check.classify(row: dict, *, cutoff: str = "2026-05-31") -> tuple[str, list[str]]` — pure function. Returns `(tier, reasons)` where tier ∈ `{"headline","control","scale","excluded"}` and `reasons` explains it. Rules (spec §3.1/§3.2): excluded if `status` starts with `excluded:`; control if `advisory_published <= cutoff` OR `fix_commit_date <= cutoff`; scale if `loc_first_party` is set and `> 1_000_000`; headline otherwise. `language` not in `{js,ts,py,java}` ⇒ excluded.
  - `check.load_candidates(path: str) -> list[dict]` — parse the TSV (skipping `#` comment lines) into dict rows.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_dataset_check.py
from eval.dataset import check

BASE = {"row":"1","repo":"r","lang":"py","ghsa":"G","cve":"C","advisory_published":"2026-08-01",
        "cwe":"CWE-89","summary":"s","fix_commit":"abc","status":"candidate",
        "fix_commit_date":"2026-08-01","loc_first_party":"90000"}

def test_headline_when_both_dates_after_cutoff():
    tier, _ = check.classify(BASE)
    assert tier == "headline"

def test_control_when_fix_commit_before_cutoff():
    r = dict(BASE, fix_commit_date="2025-08-28")
    tier, reasons = check.classify(r)
    assert tier == "control" and any("fix_commit_date" in x for x in reasons)

def test_scale_when_repo_over_one_million_loc():
    r = dict(BASE, loc_first_party="1500000")
    assert check.classify(r)[0] == "scale"

def test_excluded_status_passthrough():
    r = dict(BASE, status="excluded:bundled-fix")
    assert check.classify(r)[0] == "excluded"

def test_excluded_unsupported_language():
    r = dict(BASE, lang="go")
    assert check.classify(r)[0] == "excluded"

def test_load_candidates_skips_comments(tmp_path):
    p = tmp_path / "c.tsv"
    p.write_text("# a comment\nrow\trepo\tlang\n1\tr\tpy\n")
    rows = check.load_candidates(str(p))
    assert rows == [{"row": "1", "repo": "r", "lang": "py"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_dataset_check.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.dataset'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/dataset/check.py
_SUPPORTED = {"js", "ts", "py", "java"}

def load_candidates(path: str) -> list[dict]:
    rows = []
    header = None
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if header is None:
                header = parts
                continue
            rows.append(dict(zip(header, parts)))
    return rows

def _le(date_a: str, cutoff: str) -> bool:
    return bool(date_a) and date_a <= cutoff

def classify(row: dict, *, cutoff: str = "2026-05-31") -> tuple[str, list[str]]:
    status = row.get("status", "")
    if status.startswith("excluded:"):
        return "excluded", [status]
    if row.get("lang") not in _SUPPORTED:
        return "excluded", [f"unsupported language: {row.get('lang')}"]
    if status.startswith("control:"):
        return "control", [status]
    reasons = []
    if _le(row.get("advisory_published", ""), cutoff):
        reasons.append(f"advisory_published {row.get('advisory_published')} <= {cutoff}")
    if _le(row.get("fix_commit_date", ""), cutoff):
        reasons.append(f"fix_commit_date {row.get('fix_commit_date')} <= {cutoff}")
    if reasons:
        return "control", reasons
    loc = row.get("loc_first_party", "")
    if loc.isdigit() and int(loc) > 1_000_000:
        return "scale", [f"loc {loc} > 1000000"]
    return "headline", ["passes all rules"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_dataset_check.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/dataset/__init__.py eval/dataset/check.py eval/tests/test_dataset_check.py
git commit -m "eval: pure dataset tier classifier (headline/control/scale/excluded)"
```

---

### Task 5: Fix-commit metadata enricher (GitHub API)

**Files:**
- Create: `eval/dataset/enrich.py`
- Test: `eval/tests/test_dataset_enrich.py`

**Interfaces:**
- Consumes: `check.load_candidates`, a `gh api` command runner injected for testing.
- Produces:
  - `enrich.commit_meta(repo: str, sha: str, *, run=<subprocess wrapper>) -> dict` — calls `gh api repos/{repo}/commits/{sha}` and returns `{"fix_commit_date": "<YYYY-MM-DD>", "files": [<non-test paths>], "n_files": int}`. `run(cmd: list[str]) -> str` returns stdout; injected in tests. Test files (`/test`, `/tests`, `.test.`, `_test.`, `spec.`) are excluded from `files`/`n_files`.
  - `enrich.enrich_all(candidates: list[dict], *, run) -> list[dict]` — returns candidate rows with `fix_commit_date`, `n_files` merged in; on a `run` error for a row, sets `fix_commit_date=""`, `n_files=None` and adds `enrich_error`.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_dataset_enrich.py
import json
from eval.dataset import enrich

def fake_run_ok(cmd):
    return json.dumps({"commit": {"author": {"date": "2026-08-20T18:00:00Z"}},
                       "files": [{"filename": "src/app.ts"},
                                 {"filename": "src/app.test.ts"},
                                 {"filename": "lib/util.ts"}]})

def test_commit_meta_parses_date_and_filters_tests():
    m = enrich.commit_meta("o/r", "abc", run=fake_run_ok)
    assert m["fix_commit_date"] == "2026-08-20"
    assert m["files"] == ["src/app.ts", "lib/util.ts"]
    assert m["n_files"] == 2

def test_enrich_all_records_error_without_raising():
    def boom(cmd):
        raise RuntimeError("gh failed")
    out = enrich.enrich_all([{"row": "1", "repo": "o/r", "fix_commit": "abc"}], run=boom)
    assert out[0]["fix_commit_date"] == "" and out[0]["n_files"] is None
    assert "enrich_error" in out[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_dataset_enrich.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.dataset.enrich'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/dataset/enrich.py
import json, subprocess

_TEST_MARKERS = ("/test/", "/tests/", ".test.", "_test.", "spec.")

def _default_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

def _is_test(path: str) -> bool:
    p = "/" + path
    return any(m in p for m in _TEST_MARKERS)

def commit_meta(repo: str, sha: str, *, run=_default_run) -> dict:
    raw = run(["gh", "api", f"repos/{repo}/commits/{sha}"])
    data = json.loads(raw)
    date = data["commit"]["author"]["date"][:10]
    files = [f["filename"] for f in data.get("files", []) if not _is_test(f["filename"])]
    return {"fix_commit_date": date, "files": files, "n_files": len(files)}

def enrich_all(candidates: list[dict], *, run=_default_run) -> list[dict]:
    out = []
    for row in candidates:
        r = dict(row)
        try:
            m = commit_meta(row["repo"], row["fix_commit"], run=run)
            r["fix_commit_date"] = m["fix_commit_date"]
            r["n_files"] = m["n_files"]
        except Exception as e:
            r["fix_commit_date"] = ""
            r["n_files"] = None
            r["enrich_error"] = str(e)
        out.append(r)
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_dataset_enrich.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/dataset/enrich.py eval/tests/test_dataset_enrich.py
git commit -m "eval: enrich candidates with fix-commit date and non-test file count via gh api"
```

---

### Task 6: Plain-agent prompt + output schema (frozen text)

**Files:**
- Create: `eval/arms/__init__.py`
- Create: `eval/arms/prompt.py`
- Create: `eval/arms/findings.schema.json`
- Test: `eval/tests/test_prompt.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `prompt.TASK_PROMPT: str` — the one security-audit instruction used verbatim by all plain arms (arms 3–6). Names the required output file `findings.json` and the exact object shape.
  - `prompt.FINDINGS_SCHEMA: dict` — loaded from `findings.schema.json`; the JSON Schema for `{"findings":[{file,function,line_start,line_end,cwe,title,explanation}]}`.
  - `prompt.validate_findings(obj: dict) -> list[str]` — returns a list of human-readable problems (empty = valid): `findings` present and a list, each item has the 7 keys with correct primitive types.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_prompt.py
from eval.arms import prompt

def test_prompt_mentions_output_file_and_is_frozen_nonempty():
    assert "findings.json" in prompt.TASK_PROMPT
    assert len(prompt.TASK_PROMPT) > 200  # a real instruction, not a stub

def test_schema_has_the_seven_fields():
    props = prompt.FINDINGS_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert set(props) == {"file", "function", "line_start", "line_end", "cwe", "title", "explanation"}

def test_validate_accepts_good_and_rejects_bad():
    good = {"findings": [{"file": "a.py", "function": "f", "line_start": 1, "line_end": 2,
                          "cwe": "CWE-89", "title": "t", "explanation": "e"}]}
    assert prompt.validate_findings(good) == []
    bad = {"findings": [{"file": "a.py"}]}
    assert prompt.validate_findings(bad)  # non-empty problem list
    assert prompt.validate_findings({}) == ["missing 'findings' list"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_prompt.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.arms'`

- [ ] **Step 3: Write minimal implementation**

Create `eval/arms/findings.schema.json`:

```json
{
  "type": "object",
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["file", "function", "line_start", "line_end", "cwe", "title", "explanation"],
        "properties": {
          "file": {"type": "string"},
          "function": {"type": "string"},
          "line_start": {"type": "integer"},
          "line_end": {"type": "integer"},
          "cwe": {"type": "string"},
          "title": {"type": "string"},
          "explanation": {"type": "string"}
        }
      }
    }
  }
}
```

Create `eval/arms/prompt.py`:

```python
import json
from pathlib import Path

FINDINGS_SCHEMA = json.loads((Path(__file__).parent / "findings.schema.json").read_text())

TASK_PROMPT = """You are a security auditor. Review the source code in the current repository \
for exploitable security vulnerabilities in its own first-party code (ignore third-party \
dependencies). Look for injection (SQL, command, code, template), path traversal, SSRF, \
cross-site scripting, insecure deserialization, authentication and authorization bypasses, \
and XML external entity processing.

Report every vulnerability you find by writing a file named findings.json in the repository \
root. It must be a JSON object of this exact shape and nothing else:

{"findings": [{"file": "<path from repo root>", "function": "<enclosing function or method>", \
"line_start": <int>, "line_end": <int>, "cwe": "CWE-<number>", "title": "<short label>", \
"explanation": "<why it is exploitable>"}]}

Report only vulnerabilities you can point to a specific location for. If you find none, write \
{"findings": []}. Do not modify any source file other than writing findings.json."""

_TYPES = {"file": str, "function": str, "line_start": int, "line_end": int,
          "cwe": str, "title": str, "explanation": str}

def validate_findings(obj: dict) -> list[str]:
    problems = []
    items = obj.get("findings")
    if not isinstance(items, list):
        return ["missing 'findings' list"]
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            problems.append(f"finding {i} is not an object")
            continue
        for k, t in _TYPES.items():
            if k not in it:
                problems.append(f"finding {i} missing '{k}'")
            elif not isinstance(it[k], t) or (t is int and isinstance(it[k], bool)):
                problems.append(f"finding {i} field '{k}' wrong type")
    return problems
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_prompt.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/arms/__init__.py eval/arms/prompt.py eval/arms/findings.schema.json eval/tests/test_prompt.py
git commit -m "eval: frozen plain-agent security-audit prompt + findings schema + validator"
```

---

### Task 7: Orion-verdict capture (REAL schema — no invented fields)

**Files:**
- Create: `eval/convert.py`
- Test: `eval/tests/test_convert.py`

**CRITICAL — verified against `orion/contracts.py:18-45` and `examples/apex/findings.json`:** Orion's
`--json` output is `[dataclasses.asdict(Verdict)…]`. A `Verdict` has `decision` (NOT `verdict`),
`reason` (NOT `verdict_reason`), `evidence`, `sink_centrality`, and a nested `lead`. A `Lead` has
`index, shape, text, evidence, confidence, source_uid, sink_uid` — **there is NO `file`, `function`,
`line_start`, `line_end`, `cwe`, or `title`.** Location/CWE live only as prose in `lead.text`. This
task therefore preserves the real fields and never fabricates structured ones. Extracting location from
the prose is the separate scoring session's job (spec §5.2, §8).

**Interfaces:**
- Consumes: Orion's real `--json` verdict list.
- Produces:
  - `convert.confirmed_verdicts(verdicts: list[dict]) -> list[dict]` — returns the items with
    `decision == "CONFIRM"`, each as `{"decision","reason","evidence","sink_centrality","text",
    "text_evidence"}` where `text` = `lead.text`, `text_evidence` = `lead.evidence`. Nothing invented;
    missing keys become `""`/`0.0`.
  - `convert.load(path: str) -> list[dict]` — reads the `--json` file; returns `[]` if it is absent
    (a crashed/hung Orion run may never write it) rather than raising.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_convert.py
import json
from eval import convert

REAL = [  # shape of dataclasses.asdict(Verdict), as examples/apex/findings.json shows
    {"lead": {"index": 0, "shape": "A", "text": "cmd injection in run() at createFile.ts:116",
              "evidence": "MATCH ...", "confidence": "high", "source_uid": "s", "sink_uid": "k"},
     "decision": "CONFIRM", "reason": "tainted path reaches exec", "evidence": "read src",
     "sink_centrality": 0.4},
    {"lead": {"index": 1, "shape": "B", "text": "maybe", "evidence": "", "confidence": "low",
              "source_uid": None, "sink_uid": None},
     "decision": "REJECT", "reason": "no flow", "evidence": "", "sink_centrality": 0.0},
]

def test_keeps_only_confirms_with_real_fields():
    out = convert.confirmed_verdicts(REAL)
    assert len(out) == 1
    f = out[0]
    assert f["decision"] == "CONFIRM"
    assert f["reason"] == "tainted path reaches exec"
    assert "createFile.ts:116" in f["text"]
    assert f["sink_centrality"] == 0.4
    # no invented structured fields
    assert "file" not in f and "line_start" not in f

def test_load_missing_file_returns_empty(tmp_path):
    assert convert.load(str(tmp_path / "nope.json")) == []

def test_load_reads_real_json(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(REAL))
    assert len(convert.load(str(p))) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_convert.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.convert'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/convert.py
import json, os

def load(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    try:
        return json.loads(open(path).read())
    except Exception:
        return []

def confirmed_verdicts(verdicts: list[dict]) -> list[dict]:
    out = []
    for v in verdicts:
        if v.get("decision") != "CONFIRM":
            continue
        lead = v.get("lead") or {}
        out.append({
            "decision": "CONFIRM",
            "reason": v.get("reason") or "",
            "evidence": v.get("evidence") or "",
            "sink_centrality": float(v.get("sink_centrality") or 0.0),
            "text": lead.get("text") or "",
            "text_evidence": lead.get("evidence") or "",
        })
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_convert.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/convert.py eval/tests/test_convert.py
git commit -m "eval: capture Orion CONFIRM verdicts using the REAL contract (decision/reason/lead.text)"
```

---

### Task 8: Arm environment builder

**Files:**
- Create: `eval/arms/env.py`
- Test: `eval/tests/test_arms_env.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `env.orion_env(base, *, ollama_url, model_tag, usage_log, shim_dir, joern_heap_gb="7") -> dict` — returns a copy of `base` with: `ANTHROPIC_BASE_URL=ollama_url`; `ORION_MODEL=model_tag` and `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL=model_tag` (so fp-check subagents stay on the local model); `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1`; `EVAL_USAGE_LOG=usage_log` and `PATH` prefixed with `shim_dir` (so the `claude` usage shim from Task 8b runs); `ORION_JOERN_HEAP_GB=joern_heap_gb` and `OLLAMA_KEEP_ALIVE=0` (memory plan, spec §4).
  - `env.plain_claude_env(base, *, usage_log, shim_dir, ollama_url=None, model_tag=None) -> dict` — for the plain Claude Code arms (3/4/5). Sets `EVAL_USAGE_LOG` + `PATH` shim; when `ollama_url`/`model_tag` are given (arm 3, `plain-gemma4`) also sets `ANTHROPIC_BASE_URL` + the default-model overrides.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_arms_env.py
from eval.arms import env

def test_orion_env_sets_wiring_usage_and_memory_knobs():
    out = env.orion_env({"PATH": "/bin"}, ollama_url="http://127.0.0.1:11434",
                        model_tag="gemma4:q4", usage_log="/r/usage.jsonl", shim_dir="/shim")
    assert out["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:11434"
    assert out["ORION_MODEL"] == "gemma4:q4"
    for k in ("ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
              "ANTHROPIC_DEFAULT_HAIKU_MODEL"):
        assert out[k] == "gemma4:q4"
    assert out["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] == "1"
    assert out["EVAL_USAGE_LOG"] == "/r/usage.jsonl"
    assert out["PATH"].startswith("/shim:")  # shim resolves `claude` first
    assert out["ORION_JOERN_HEAP_GB"] == "7"
    assert out["OLLAMA_KEEP_ALIVE"] == "0"

def test_plain_claude_env_frontier_has_no_base_url():
    out = env.plain_claude_env({"PATH": "/bin"}, usage_log="/r/u.jsonl", shim_dir="/shim")
    assert "ANTHROPIC_BASE_URL" not in out
    assert out["PATH"].startswith("/shim:")

def test_env_builders_do_not_mutate_base():
    base = {"PATH": "/bin"}
    env.orion_env(base, ollama_url="u", model_tag="m", usage_log="l", shim_dir="s")
    assert "ANTHROPIC_BASE_URL" not in base
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_arms_env.py -v`
Expected: FAIL with `ImportError: cannot import name 'env'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/arms/env.py
def _model_defaults(env: dict, model_tag: str) -> None:
    env["ORION_MODEL"] = model_tag
    env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = model_tag
    env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = model_tag
    env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = model_tag

def _with_shim(env: dict, usage_log: str, shim_dir: str) -> None:
    env["EVAL_USAGE_LOG"] = usage_log
    env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"

def orion_env(base, *, ollama_url, model_tag, usage_log, shim_dir, joern_heap_gb="7") -> dict:
    env = dict(base)
    env["ANTHROPIC_BASE_URL"] = ollama_url
    env["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] = "1"
    env["ORION_JOERN_HEAP_GB"] = joern_heap_gb
    env["OLLAMA_KEEP_ALIVE"] = "0"
    _model_defaults(env, model_tag)
    _with_shim(env, usage_log, shim_dir)
    return env

def plain_claude_env(base, *, usage_log, shim_dir, ollama_url=None, model_tag=None) -> dict:
    env = dict(base)
    env["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] = "1"
    if ollama_url:
        env["ANTHROPIC_BASE_URL"] = ollama_url
    if model_tag:
        _model_defaults(env, model_tag)
    _with_shim(env, usage_log, shim_dir)
    return env
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_arms_env.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/arms/env.py eval/tests/test_arms_env.py
git commit -m "eval: env builders (Ollama wiring, usage-shim PATH, Joern heap + keep-alive)"
```

---

### Task 8b: `claude` usage-capture shim

**Files:**
- Create: `eval/shim/claude` (executable shell wrapper)
- Create: `eval/shim_setup.py`
- Test: `eval/tests/test_shim.py`

**Why:** Orion's `--json` output carries no token usage (it parses Claude's stream-json internally and
discards it, `orion/claude_cli.py`). Orion invokes bare `claude ... --output-format stream-json`, so a
`claude` wrapper placed first on `PATH` sees every call's stream-json — including the `result` object's
usage — and `tee`s it to the per-run `EVAL_USAGE_LOG`, passing stdout through unchanged so Orion is
unaffected. Same shim captures the plain-Claude arms.

**Interfaces:**
- Consumes: `EVAL_USAGE_LOG` env var (per-run path).
- Produces:
  - `eval/shim/claude` — the wrapper. Finds the real `claude` (via `EVAL_REAL_CLAUDE`, else the first
    `claude` on `PATH` after removing the shim dir), runs it with all args, and appends its stdout to
    `$EVAL_USAGE_LOG` while streaming stdout on. Uses `set -o pipefail` so the real `claude` exit code
    is returned, not `tee`'s.
  - `shim_setup.shim_dir() -> str` — absolute path to `eval/shim`, and asserts the wrapper is
    executable (chmod +x on first call).

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_shim.py
import os, stat, subprocess
from eval import shim_setup

def test_shim_dir_is_executable():
    d = shim_setup.shim_dir()
    wrapper = os.path.join(d, "claude")
    assert os.path.isfile(wrapper)
    assert os.stat(wrapper).st_mode & stat.S_IXUSR

def test_shim_tees_stdout_to_usage_log(tmp_path):
    # a fake "real claude" that prints a stream-json-ish result line
    fake = tmp_path / "realclaude"
    fake.write_text('#!/bin/bash\necho \'{"type":"result","usage":{"input_tokens":7}}\'\n')
    fake.chmod(0o755)
    log = tmp_path / "usage.jsonl"
    env = dict(os.environ, EVAL_USAGE_LOG=str(log), EVAL_REAL_CLAUDE=str(fake))
    wrapper = os.path.join(shim_setup.shim_dir(), "claude")
    out = subprocess.run([wrapper, "-p", "hi"], capture_output=True, text=True, env=env)
    assert '"input_tokens":7' in out.stdout          # passed through to caller
    assert '"input_tokens":7' in log.read_text()      # AND captured to the log
    assert out.returncode == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_shim.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.shim_setup'`

- [ ] **Step 3: Write minimal implementation**

Create `eval/shim/claude` (mode will be set by `shim_setup`):

```bash
#!/bin/bash
# Usage-capture shim: tee claude's stdout to $EVAL_USAGE_LOG, pass it through unchanged.
set -o pipefail
if [ -n "$EVAL_REAL_CLAUDE" ]; then
  REAL="$EVAL_REAL_CLAUDE"
else
  # first `claude` on PATH that is not this shim
  SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
  REAL=""
  IFS=':' read -ra DIRS <<< "$PATH"
  for d in "${DIRS[@]}"; do
    if [ "$d" != "$SELF_DIR" ] && [ -x "$d/claude" ]; then REAL="$d/claude"; break; fi
  done
fi
if [ -z "$REAL" ]; then echo "usage-shim: real claude not found" >&2; exit 127; fi
if [ -n "$EVAL_USAGE_LOG" ]; then
  "$REAL" "$@" | tee -a "$EVAL_USAGE_LOG"
else
  "$REAL" "$@"
fi
```

Create `eval/shim_setup.py`:

```python
import os, stat

def shim_dir() -> str:
    d = os.path.abspath(os.path.join(os.path.dirname(__file__), "shim"))
    wrapper = os.path.join(d, "claude")
    if os.path.isfile(wrapper):
        st = os.stat(wrapper)
        if not st.st_mode & stat.S_IXUSR:
            os.chmod(wrapper, st.st_mode | 0o755)
    return d
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_shim.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/shim/claude eval/shim_setup.py eval/tests/test_shim.py
git commit -m "eval: claude usage-capture shim (tee stream-json to per-run usage log)"
```

---

### Task 9: Repo checkout helper

**Files:**
- Create: `eval/repo.py`
- Test: `eval/tests/test_repo.py`

**Interfaces:**
- Consumes: a git command runner injected for testing.
- Produces:
  - `repo.vulnerable_commit(fix_sha: str, *, run) -> str` — returns `fix_sha + "^"` resolved to a full SHA via `git rev-parse` (the parent of the fix = the vulnerable state). `run(cmd) -> str`.
  - `repo.prepare(repo_url: str, dest: str, commit: str, *, run) -> None` — clones `repo_url` into `dest` if absent, then `git -C dest checkout --detach <commit>`. Idempotent: an existing `dest` is fetched, not re-cloned.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_repo.py
from eval import repo

def test_vulnerable_commit_resolves_parent():
    calls = []
    def run(cmd):
        calls.append(cmd)
        return "PARENTSHA\n"
    out = repo.vulnerable_commit("FIXSHA", run=run)
    assert out == "PARENTSHA"
    assert calls[0] == ["git", "rev-parse", "FIXSHA^"]

def test_prepare_clones_when_absent(tmp_path):
    dest = tmp_path / "nope"
    seen = []
    def run(cmd):
        seen.append(cmd)
        return ""
    repo.prepare("https://x/y.git", str(dest), "SHA", run=run)
    assert ["git", "clone", "https://x/y.git", str(dest)] in seen
    assert ["git", "-C", str(dest), "checkout", "--detach", "SHA"] in seen
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_repo.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.repo'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/repo.py
import os, subprocess

def _default_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

def vulnerable_commit(fix_sha: str, *, run=_default_run) -> str:
    return run(["git", "rev-parse", f"{fix_sha}^"]).strip()

def prepare(repo_url: str, dest: str, commit: str, *, run=_default_run) -> None:
    if not os.path.isdir(dest):
        run(["git", "clone", repo_url, dest])
    else:
        run(["git", "-C", dest, "fetch", "--all"])
    run(["git", "-C", dest, "checkout", "--detach", commit])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_repo.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/repo.py eval/tests/test_repo.py
git commit -m "eval: repo checkout helper (vulnerable = parent of fix commit)"
```

---

### Task 10: Run queue (sequential, resumable)

**Files:**
- Create: `eval/queue.py`
- Test: `eval/tests/test_queue.py`

**Interfaces:**
- Consumes: `db.connect`.
- Produces:
  - `queue.plan(arms: list[str], repos: list[str], runs: int) -> list[tuple[str,str,int]]` — the full `(arm, repo, run_no)` list in the spec's order: for each arm in `arms` order, for each repo, run_no `1..runs`.
  - `queue.pending(conn, plan: list[tuple]) -> list[tuple]` — filters out `(arm,repo,run_no)` triples already present in `runs` with `status='ok'`, so a restart resumes without re-running good runs.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_queue.py
from eval import db, queue

def test_plan_orders_by_arm_then_repo_then_run():
    p = queue.plan(["orion-gemma4", "plain-opus5"], ["r1", "r2"], 2)
    assert p[0] == ("orion-gemma4", "r1", 1)
    assert p[:4] == [("orion-gemma4","r1",1),("orion-gemma4","r1",2),
                     ("orion-gemma4","r2",1),("orion-gemma4","r2",2)]
    assert p[-1] == ("plain-opus5", "r2", 2)

def test_pending_skips_completed_ok_runs(tmp_path):
    conn = db.connect(str(tmp_path/"t.db"))
    rid = db.start_run(conn, arm="a", repo="r1", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c")
    db.finish_run(conn, rid, "ok")
    plan = [("a","r1",1), ("a","r1",2)]
    assert queue.pending(conn, plan) == [("a","r1",2)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_queue.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.queue'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/queue.py
def plan(arms, repos, runs):
    out = []
    for arm in arms:
        for repo in repos:
            for n in range(1, runs + 1):
                out.append((arm, repo, n))
    return out

def pending(conn, plan):
    done = {(a, r, n) for a, r, n in conn.execute(
        "SELECT arm, repo, run_no FROM runs WHERE status='ok'").fetchall()}
    return [t for t in plan if t not in done]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_queue.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/queue.py eval/tests/test_queue.py
git commit -m "eval: sequential resumable run queue (skip completed ok runs)"
```

---

### Task 11: Phase-0 preflight report

**Files:**
- Create: `eval/preflight.py`
- Test: `eval/tests/test_preflight.py`

**Interfaces:**
- Consumes: a command runner injected for testing.
- Produces:
  - `preflight.check(*, run) -> list[dict]` — returns one `{"tool","ok","detail"}` row per prerequisite: `ollama` (`ollama --version`), `ollama-serve` (`curl -s localhost:11434/api/tags`), `codex` (`codex --version`), `claude` (`claude --version`), `docker` (`docker ps`), `joern` (`~/joern/joern-cli/joern-parse --version`), `neo4j` (`curl -s localhost:7475`), `cloc` (`cloc --version`). `ok` is False (never raises) when the command errors. `run(cmd) -> str` raises on failure.
  - `preflight.render(rows) -> str` — a plain-text table; a final line `MISSING: <tools>` when any `ok` is False, else `ALL PRESENT`.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_preflight.py
from eval import preflight

def test_check_marks_missing_tools_without_raising():
    def run(cmd):
        if cmd[0] == "codex":
            raise FileNotFoundError("codex")
        return "ok"
    rows = preflight.check(run=run)
    codex = [r for r in rows if r["tool"] == "codex"][0]
    assert codex["ok"] is False
    assert any(r["ok"] for r in rows)

def test_render_flags_missing():
    rows = [{"tool": "codex", "ok": False, "detail": "not found"},
            {"tool": "claude", "ok": True, "detail": "2.1.210"}]
    out = preflight.render(rows)
    assert "MISSING: codex" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_preflight.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.preflight'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/preflight.py
import os, subprocess

_CHECKS = [
    ("ollama", ["ollama", "--version"]),
    ("ollama-serve", ["curl", "-sf", "http://localhost:11434/api/tags"]),
    ("codex", ["codex", "--version"]),
    ("claude", ["claude", "--version"]),
    ("docker", ["docker", "ps"]),
    ("joern", [os.path.expanduser("~/joern/joern-cli/joern-parse"), "--version"]),
    ("neo4j", ["curl", "-sf", "http://localhost:7475"]),
    ("cloc", ["cloc", "--version"]),
]

def _default_run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

def check(*, run=_default_run) -> list[dict]:
    rows = []
    for tool, cmd in _CHECKS:
        try:
            detail = (run(cmd) or "").strip().splitlines()[:1]
            rows.append({"tool": tool, "ok": True, "detail": detail[0] if detail else "ok"})
        except Exception as e:
            rows.append({"tool": tool, "ok": False, "detail": str(e)})
    return rows

def render(rows) -> str:
    lines = [f"{'OK ' if r['ok'] else 'MISS'}  {r['tool']:<14} {r['detail']}" for r in rows]
    missing = [r["tool"] for r in rows if not r["ok"]]
    lines.append("MISSING: " + ", ".join(missing) if missing else "ALL PRESENT")
    return "\n".join(lines)

if __name__ == "__main__":
    print(render(check()))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_preflight.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/preflight.py eval/tests/test_preflight.py
git commit -m "eval: Phase-0 preflight checker for the 8 prerequisites"
```

---

### Task 12: Arm launchers (subprocess drivers, injected)

**Files:**
- Create: `eval/arms/launch.py`
- Test: `eval/tests/test_arms_launch.py`

**Interfaces:**
- Consumes: `env.orion_env`, `env.plain_ollama_env`, `resources.PhaseSampler`, `usage`, `convert`, `prompt`.
- Produces:
  - `launch.HUNG_SECONDS = 3600`.
  - `launch.stream_subprocess(cmd, *, env, cwd, on_line, hung_seconds=HUNG_SECONDS, popen=subprocess.Popen) -> str` — runs `cmd`, calls `on_line(line)` for each stdout line, returns final status `"ok"`/`"hung"`/`"crashed"`. `hung` when no line arrives for `hung_seconds`. `popen` is injected in tests. (Progress events are stdout lines, matching Orion's `stream-json` and Codex `--json`.)
  - `launch.orion_arm(*, repo_dir, ollama_url, model_tag, json_out, usage_log, shim_dir, base_env, on_line, scan_id=None, popen) -> tuple[str, str|None]` — builds the Orion env (Task 8 `env.orion_env`), creates `json_out`'s parent dir, and runs Orion via its **real** flags. When `scan_id` is None it builds: `orion scan <repo_dir> --json <json_out> --quiet`; when `scan_id` is given it reuses the graph: `orion scan --scan-id <scan_id> --json <json_out> --quiet`. It scrapes the `scan_id: <id>` line Orion prints (`cli.py:79`) from `on_line`, and returns `(status, scan_id_seen)`. **There is no `--output-format` flag on `orion scan`** (verified `orion/cli.py:215-234`); progress arrives as stdout lines regardless, which is all the hang detector needs.

Note: real model execution is not unit-tested; tests inject a fake `popen` that yields canned lines (including a `scan_id:` line). The launcher's job is process control, scan_id capture, and status.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_arms_launch.py
import io
from eval.arms import launch

class FakePopen:
    def __init__(self, lines, cmd=None, **kw):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.returncode = 0
        self._lines = lines
    def wait(self, timeout=None):
        return self.returncode
    def poll(self):
        return self.returncode
    def kill(self):
        self.returncode = -9

def test_stream_calls_on_line_and_returns_ok():
    seen = []
    def fake_popen(cmd, **kw):
        return FakePopen(["a", "b", "c"])
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=seen.append,
                                      popen=fake_popen)
    assert status == "ok"
    assert seen == ["a", "b", "c"]

def test_crashed_when_returncode_nonzero():
    class Bad(FakePopen):
        def __init__(self, *a, **k):
            super().__init__(["oops"])
            self.returncode = 1
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=lambda l: None,
                                      popen=lambda cmd, **kw: Bad())
    assert status == "crashed"

def test_orion_arm_uses_real_flags_and_captures_scan_id(tmp_path):
    captured = {}
    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        return FakePopen(["scan_id: abc123", '{"type":"result"}'])
    status, sid = launch.orion_arm(
        repo_dir=str(tmp_path/"repo"), ollama_url="u", model_tag="gemma4",
        json_out=str(tmp_path/"out/findings.json"), usage_log=str(tmp_path/"u.jsonl"),
        shim_dir="/shim", base_env={"PATH": "/bin"}, on_line=lambda l: None,
        popen=fake_popen)
    assert status == "ok" and sid == "abc123"
    assert "--output-format" not in captured["cmd"]      # the flag Orion does NOT have
    assert "--json" in captured["cmd"]
    assert (tmp_path/"out").is_dir()                       # parent dir was created

def test_orion_arm_reuses_graph_with_scan_id(tmp_path):
    captured = {}
    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        return FakePopen(["scan_id: abc123"])
    launch.orion_arm(repo_dir="r", ollama_url="u", model_tag="m",
                     json_out=str(tmp_path/"f.json"), usage_log="u", shim_dir="/s",
                     base_env={}, on_line=lambda l: None, scan_id="abc123", popen=fake_popen)
    assert "--scan-id" in captured["cmd"] and "abc123" in captured["cmd"]
    assert "r" not in captured["cmd"]  # no repo positional when reusing
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_arms_launch.py -v`
Expected: FAIL with `ImportError: cannot import name 'launch'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/arms/launch.py
import subprocess, threading, queue as _q
from .env import orion_env

HUNG_SECONDS = 3600

def stream_subprocess(cmd, *, env, cwd, on_line, hung_seconds=HUNG_SECONDS,
                      popen=subprocess.Popen) -> str:
    proc = popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                 env=env, cwd=cwd)
    lines = _q.Queue()

    def _reader():
        for line in proc.stdout:
            lines.put(line.rstrip("\n"))
        lines.put(None)  # sentinel: stream ended

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    hung = False
    while True:
        try:
            line = lines.get(timeout=hung_seconds)
        except _q.Empty:
            hung = True
            try:
                proc.kill()
            except Exception:
                pass
            break
        if line is None:
            break
        on_line(line)
    proc.wait()
    if hung:
        return "hung"
    return "ok" if proc.returncode == 0 else "crashed"

import os, re
_SCAN_ID_RE = re.compile(r"^scan_id:\s*(\S+)")

def orion_arm(*, repo_dir, ollama_url, model_tag, json_out, usage_log, shim_dir, base_env,
              on_line, scan_id=None, popen=subprocess.Popen):
    env = orion_env(base_env, ollama_url=ollama_url, model_tag=model_tag,
                    usage_log=usage_log, shim_dir=shim_dir)
    os.makedirs(os.path.dirname(json_out), exist_ok=True)  # Orion's write_text won't mkdir
    if scan_id:
        cmd = ["orion", "scan", "--scan-id", scan_id, "--json", json_out, "--quiet"]
    else:
        cmd = ["orion", "scan", repo_dir, "--json", json_out, "--quiet"]
    seen = {"sid": scan_id}
    def _on_line(line):
        m = _SCAN_ID_RE.match(line)
        if m:
            seen["sid"] = m.group(1)
        on_line(line)
    status = stream_subprocess(cmd, env=env, cwd=".", on_line=_on_line, popen=popen)
    return status, seen["sid"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_arms_launch.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/arms/launch.py eval/tests/test_arms_launch.py
git commit -m "eval: subprocess launcher with hang detection + Orion arm driver"
```

---

### Task 13: Top-level runner CLI

**Files:**
- Create: `eval/run.py`
- Test: `eval/tests/test_run.py`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `run.ARMS = ["orion-gemma4","orion-gptoss20b","plain-gemma4","plain-sonnet5","plain-opus5","plain-gpt"]`.
  - `run.run_one(conn, *, arm, repo_meta, run_no, model_tags, ollama_url, base_env, orion_commit, cli_versions, launcher) -> str` — starts a `runs` row (recording `model_tag`, `cli_versions`, `orion_commit`), dispatches to the arm via `launcher` (injected; wraps Task 12), records the final status, and returns it. `launcher(arm, repo_meta, model_tag, on_line) -> (status, json_findings_path)`. On any exception the run is finished `error` and the exception head is logged, never raised.
  - `run.git_head(path: str = ".") -> str` — `git -C <path> rev-parse HEAD`, `""` on failure. Supplies `orion_commit`.
  - `run.main(argv)` — argparse CLI: `--arm` (repeatable, default all), `--manifest`, `--db`, `--runs 3`, `--ollama-url`; loads the manifest, reads versions via `preflight.check`, computes `orion_commit` via `git_head`, builds the launcher (Task 14), and iterates `queue.pending` calling `run_one`. Resumable.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_run.py
from eval import db, run

def test_run_one_records_status_from_launcher(tmp_path):
    conn = db.connect(str(tmp_path/"t.db"))
    def launcher(arm, repo_meta, model_tag, on_line):
        on_line('{"type":"result"}')
        return "ok", str(tmp_path/"f.json")
    status = run.run_one(conn, arm="plain-opus5",
                         repo_meta={"id": "r1", "tier": "headline"}, run_no=1,
                         model_tags={}, ollama_url="u", base_env={}, orion_commit="c",
                         cli_versions="claude=2.1.210", launcher=launcher)
    assert status == "ok"
    row = conn.execute("select status, cli_versions from runs where arm='plain-opus5'").fetchone()
    assert row[0] == "ok" and row[1] == "claude=2.1.210"

def test_run_one_catches_launcher_exception(tmp_path):
    conn = db.connect(str(tmp_path/"t.db"))
    def boom(arm, repo_meta, model_tag, on_line):
        raise RuntimeError("launch failed")
    status = run.run_one(conn, arm="orion-gemma4",
                         repo_meta={"id": "r1", "tier": "headline"}, run_no=1,
                         model_tags={"orion-gemma4": "gemma3:12b"}, ollama_url="u",
                         base_env={}, orion_commit="c", cli_versions="", launcher=boom)
    assert status == "error"
    err = conn.execute("select message from events where level='error'").fetchone()
    assert "launch failed" in err[0]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_run.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'eval.run'`

- [ ] **Step 3: Write minimal implementation**

```python
# eval/run.py
import argparse, os
from . import db, queue

ARMS = ["orion-gemma4", "orion-gptoss20b", "plain-gemma4",
        "plain-sonnet5", "plain-opus5", "plain-gpt"]

def git_head(path: str = ".") -> str:
    import subprocess
    try:
        return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""

def run_one(conn, *, arm, repo_meta, run_no, model_tags, ollama_url, base_env,
            orion_commit, cli_versions, launcher) -> str:
    model_tag = model_tags.get(arm, arm)
    rid = db.start_run(conn, arm=arm, repo=repo_meta["id"], tier=repo_meta.get("tier", ""),
                       run_no=run_no, model_tag=model_tag, cli_versions=cli_versions,
                       orion_commit=orion_commit)
    def on_line(line):
        db.log_event(conn, rid, stage="run", level="info", message=line[:2000])
    try:
        status, _findings = launcher(arm, repo_meta, model_tag, on_line)
    except Exception as e:
        db.log_event(conn, rid, stage="run", level="error", message=str(e)[:2000])
        db.finish_run(conn, rid, "error")
        return "error"
    db.finish_run(conn, rid, status)
    return status
```

`main()` is completed in Task 14 (it needs `build_launcher`); its argparse and loop are shown there.
Do not leave a stub — Task 14 Step 3 replaces this file's `main` with the full version.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_run.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add eval/run.py eval/tests/test_run.py
git commit -m "eval: top-level runner (run_one records status; catches launcher errors)"
```

---

### Task 14: Wire the runner end-to-end + Phase-0 smoke doc

**Files:**
- Modify: `eval/run.py` (build the real launcher and manifest loading)
- Create: `eval/README.md`
- Test: `eval/tests/test_run_wiring.py`

**Interfaces:**
- Consumes: `arms.launch`, `arms.env`, `resources`, `usage`, `convert`, `repo`, `db`, `queue`.
- Produces:
  - `run.build_launcher(*, ollama_url, base_env, shim_dir, graph_cache, _orion, _plain) -> callable` — returns a `launcher(arm, repo_meta, model_tag, on_line)` that dispatches `orion-*` arms to `_orion` and `plain-*` arms to `_plain`. `graph_cache` is a dict keyed by `repo_meta["id"]`: the launcher passes `scan_id=graph_cache.get(repo_id)` into `_orion` and stores the returned scan_id back, so the first Orion run of a repo builds and the rest reuse the graph (spec §4). Per-run `json_out` and `usage_log` paths are derived under `eval/runs/<arm>/<repo>/`. Keep it thin; the wiring test injects `_orion`/`_plain`.
  - `run.main(argv)` — the completed CLI (replaces Task 13's note): argparse (`--arm`, `--manifest`, `--db`, `--runs`, `--ollama-url`), loads the manifest to repo metas, `versions = "; ".join(f"{r['tool']}={r['detail']}" for r in preflight.check())`, `orion_commit = git_head()`, `graph_cache = {}`, `launcher = build_launcher(...)`, then `for arm, repo, n in queue.pending(conn, queue.plan(arms, repo_ids, runs)): run_one(...)`.

- [ ] **Step 1: Write the failing test**

```python
# eval/tests/test_run_wiring.py
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
    launcher("orion-gemma4", {"id": "r1", "repo_dir": "/tmp/r1"}, "gemma4", lambda l: None)
    launcher("orion-gptoss20b", {"id": "r1", "repo_dir": "/tmp/r1"}, "gptoss", lambda l: None)
    launcher("plain-opus5", {"id": "r1", "repo_dir": "/tmp/r1"}, "opus", lambda l: None)
    # first orion run built (scan_id None), second reused the cached "built-sid"
    assert called["orion_scan_ids"] == [None, "built-sid"]
    assert cache["r1"] == "built-sid"
    assert called["plain"] == "plain-opus5"

def test_git_head_returns_string():
    assert isinstance(run.git_head("."), str)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/pytest eval/tests/test_run_wiring.py -v`
Expected: FAIL with `AttributeError: module 'eval.run' has no attribute 'build_launcher'`

- [ ] **Step 3: Write minimal implementation**

Replace `eval/run.py`'s deferred `main` note with the real launcher and CLI:

```python
def _default_orion(**kw):
    from .arms.launch import orion_arm
    return orion_arm(**kw)

def _default_plain(**kw):
    from .arms.plain import plain_arm  # runs Claude Code / Codex with TASK_PROMPT
    return plain_arm(**kw)

def build_launcher(*, ollama_url, base_env, shim_dir, graph_cache,
                   _orion=_default_orion, _plain=_default_plain):
    def launcher(arm, repo_meta, model_tag, on_line):
        rid = repo_meta["id"]
        run_dir = f"eval/runs/{arm}/{rid}"
        usage_log = f"{run_dir}/usage.jsonl"
        if arm.startswith("orion-"):
            json_out = f"{run_dir}/findings.orion.json"
            status, sid = _orion(repo_dir=repo_meta["repo_dir"], ollama_url=ollama_url,
                                 model_tag=model_tag, json_out=json_out, usage_log=usage_log,
                                 shim_dir=shim_dir, base_env=base_env, on_line=on_line,
                                 scan_id=graph_cache.get(rid))
            if sid:
                graph_cache[rid] = sid
            return status, json_out
        json_out = f"{run_dir}/findings.json"
        status, _ = _plain(arm=arm, repo_dir=repo_meta["repo_dir"], ollama_url=ollama_url,
                           model_tag=model_tag, json_out=json_out, usage_log=usage_log,
                           shim_dir=shim_dir, base_env=base_env, on_line=on_line)
        return status, json_out
    return launcher

def main(argv=None):
    import json as _json, os
    from . import preflight
    from .shim_setup import shim_dir as _shim_dir
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", action="append", choices=ARMS)
    ap.add_argument("--manifest", default="eval/dataset/manifest.json")
    ap.add_argument("--db", default="eval/runs.db")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    args = ap.parse_args(argv)
    arms = args.arm or ARMS
    repos = _json.loads(open(args.manifest).read())["repos"]  # [{id, repo_dir, tier, ...}]
    repo_ids = [r["id"] for r in repos]
    meta_by_id = {r["id"]: r for r in repos}
    conn = db.connect(args.db)
    versions = "; ".join(f"{r['tool']}={r['detail']}" for r in preflight.check())
    orion_commit = git_head()
    graph_cache = {}
    launcher = build_launcher(ollama_url=args.ollama_url, base_env=dict(os.environ),
                              shim_dir=_shim_dir(), graph_cache=graph_cache)
    todo = queue.pending(conn, queue.plan(arms, repo_ids, args.runs))
    for arm, repo_id, n in todo:
        run_one(conn, arm=arm, repo_meta=meta_by_id[repo_id], run_no=n,
                model_tags=MODEL_TAGS, ollama_url=args.ollama_url, base_env=dict(os.environ),
                orion_commit=orion_commit, cli_versions=versions, launcher=launcher)
    return 0
```

Add near the top of `eval/run.py`: `MODEL_TAGS = {"orion-gemma4": "gemma3:12b", "orion-gptoss20b": "gpt-oss:20b", "plain-gemma4": "gemma3:12b", "plain-sonnet5": "claude-sonnet-5", "plain-opus5": "claude-opus-5", "plain-gpt": "gpt-5.6-sol"}` (exact tags confirmed in Phase 0; frozen at pre-registration).

Create `eval/README.md` documenting: the Phase-0 smoke procedure (`ollama serve`, `ollama pull` the two model tags, `./.venv/bin/python -m eval.preflight`, then a NodeGoat mini-scan with `env.orion_env` to confirm `run_cypher` executes, `--json-schema` parses, the `claude` usage shim writes `usage.jsonl`, and Joern build fits with `ORION_JOERN_HEAP_GB=7`), how to run the study (`./.venv/bin/python -m eval.run --runs 3`), and how to query failures (`sqlite3 eval/runs.db "select * from failures"`).

Also create `eval/arms/plain.py` with `plain_arm(*, arm, repo_dir, ollama_url, model_tag, json_out, usage_log, shim_dir, base_env, on_line, popen=subprocess.Popen) -> tuple[str,str|None]`: creates `json_out`'s parent dir; for `plain-gpt` runs Codex (`codex exec --json` with `prompt.TASK_PROMPT`, cwd=`repo_dir`, no shim); for the Claude arms runs `claude -p <TASK_PROMPT> --output-format stream-json --add-dir <repo_dir>` under `env.plain_claude_env` (passing `ollama_url`/`model_tag` only for `plain-gemma4`). Returns `(status, json_out)`. Cover command construction with one test (`eval/tests/test_plain.py`) asserting the Claude argv contains the model default env and the Codex argv uses `codex exec --json`, injecting `popen`.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/pytest eval/tests/test_run_wiring.py eval/tests/test_plain.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add eval/run.py eval/arms/plain.py eval/README.md eval/tests/test_run_wiring.py eval/tests/test_plain.py
git commit -m "eval: wire runner launcher (Orion vs plain arms) + Phase-0 smoke README"
```

---

### Task 15: Pre-registration freeze

**Files:**
- Create: `eval/CHANGELOG.md`
- Create: `eval/PREREGISTRATION.md`
- Modify: `eval/dataset/candidates.tsv` → replace with the finished `eval/dataset/manifest.json` (produced by running Tasks 4–5 tooling over the expanded sweep; answer keys hand-written and reviewed per spec §3.4)

**Interfaces:**
- Consumes: the whole harness (all tests green) and the completed dataset.
- Produces: a tagged, frozen study definition.

- [ ] **Step 1: Confirm the full suite is green**

Run: `./.venv/bin/pytest eval/tests -v`
Expected: all tasks' tests PASS.

- [ ] **Step 2: Write `eval/PREREGISTRATION.md`**

Copy verbatim from the spec (§9): the arms table with exact model tags and effort; a pointer to `eval/dataset/manifest.json` (the locked dataset + answer keys); the frozen prompt (`eval/arms/prompt.py::TASK_PROMPT`) and schema; the "caught" / "caught, right type" matching rule agreed with the user; and the hypotheses (§1) with the deciding metric each. Include a line: "Frozen at tag `eval-prereg-v1` on <date>. Changes require a new tag and a `CHANGELOG.md` entry."

- [ ] **Step 3: Start `eval/CHANGELOG.md`**

```markdown
# Study changelog

## eval-prereg-v1 (<date>)
Initial pre-registration. Arms, dataset manifest + answer keys, plain-agent prompt/schema,
matching rule, and hypotheses frozen before any scored run.
```

- [ ] **Step 4: Commit and tag**

```bash
git add eval/PREREGISTRATION.md eval/CHANGELOG.md eval/dataset/manifest.json
git rm eval/dataset/candidates.tsv
git commit -m "eval: pre-registration v1 — freeze arms, dataset, prompt, matching rule, hypotheses"
git tag eval-prereg-v1
```

- [ ] **Step 5: Verify the tag**

Run: `git show eval-prereg-v1 --stat | head -20`
Expected: the tag points at the pre-registration commit.

---

## Self-Review

This plan was revised after two independent reviews against the real Orion source. The six blockers
they found are fixed and noted below.

**Spec coverage:**
- §1 hypotheses → PREREGISTRATION (Task 15) + captured data enabling each (Tasks 1, 2, 7, 8b).
- §2 arms/order/runs → `run.ARMS`/`MODEL_TAGS` (Tasks 13/14), `queue.plan` order (Task 10), 3 runs default.
- §3 dataset rules/tiers/manifest → Tasks 4, 5, 15.
- §4 memory + graph reuse → Joern heap cap + `OLLAMA_KEEP_ALIVE=0` in `env.orion_env` (Task 8); graph built once per repo and reused via `--scan-id` through `build_launcher`'s `graph_cache` (Task 14) — **fixes reviewer blocker #3** (was rebuilding 3× per repo). `PhaseSampler` (Task 3) records peak RSS. Joern runs as a subprocess that exits before reasoning, so no in-process unload seam is needed — **corrects the "structurally unautomatable" concern (#4)**; the residual risk (build peak on 16 GB) is bounded by the heap cap and the scale-tier cutoff.
- §5 harness (Ollama wiring, usage shim, plain-agent task, runner, hang detection) → Tasks 8, 8b, 6, 12, 13, 14.
- §5.1 Phase-0 gate → `preflight` (Task 11) + smoke procedure in `eval/README.md` (Task 14).
- §6 run log + failures view → Task 1.
- §7 recorded fields → Tasks 1, 2, 3, **8b** (per-call token usage via the `claude` shim — **fixes blocker #5**: Orion's `--json` carries no usage; the shim tees the stream-json that does). `cli_versions` now comes from `preflight.check()` and `orion_commit` from `git_head()` (**fixes should-fix #7, #9**).
- §8 scoring out of scope → nothing here scores; Task 7 captures Orion's **real** verdict fields (`decision`/`reason`/`lead.text`) and invents nothing — **fixes blocker #2** (the old converter read `verdict`/`lead.file`/`lead.cwe`, which do not exist, and would have zeroed every Orion finding).
- §8a exploits deferred → no exploit code; catalog kept (Task 4/15).
- §9 pre-registration → Task 15.

**Blocker #1 (fixed):** the Orion command dropped the non-existent `--output-format` flag (Task 12); it now runs `orion scan <repo> --json <out> --quiet` (build) or `--scan-id <id> --json <out> --quiet` (reuse), verified against `orion/cli.py:215-234`. A Task 12 test asserts `--output-format` is absent and `--json` present.

**Blocker #6 (fixed):** `run.main` is fully written in Task 14 (manifest load → versions → commit → `build_launcher` → `queue.pending` loop), not a stub. `eval/README.md`'s `python -m eval.run` command runs the study.

**Reviewer nit #10 (fixed):** Task 7's test now uses Orion's real `dataclasses.asdict(Verdict)` shape, so the TDD loop can no longer go green on a fictional schema.

**Placeholder scan:** `eval/arms/plain.py` is specified in Task 14 with its full signature and a required test. No "TODO"/"handle edge cases" left in code.

**Type consistency:** `on_line(line: str)` is consistent across Tasks 12–14. `orion_arm(...) -> (status, scan_id)` and `plain_arm(...) -> (status, path)` both match `build_launcher`'s use (Task 14) and `run_one`'s `launcher(...) -> (status, path)` (Task 13). Task 7 no longer claims to produce the plain-agent `findings.json` shape — the two arm families are captured in their own shapes (spec §5.2), reconciled only in the scoring session.

**Known open item (not a plan defect):** the exact "caught" matching rule is a pre-registration input the user and I finalize before Task 15; the harness captures both arm families' raw output either way, so no code depends on the rule.
