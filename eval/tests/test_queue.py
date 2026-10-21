import json
from pathlib import Path

from eval import db, queue

FIX = Path(__file__).parent / "fixtures"


def _start(conn, st, sha, attempt=1, run_no=1, case=""):
    rid = db.start_run(conn, arm="a", repo="r", tier="h", run_no=run_no, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind="vulnerable",
                       commit_sha=sha, case_id=case, attempt_no=attempt)
    if st != "running":
        db.finish_run(conn, rid, st)
    return rid


def test_plan_includes_commit_kind_and_case():
    p = queue.plan(["orion-lm"], {"r1": [("vsha", "vulnerable", ""), ("psha", "patched", "")]}, 2)
    assert p[0] == ("orion-lm", "r1", "vsha", "", 1)
    assert ("orion-lm", "r1", "psha", "", 2) in p
    assert len(p) == 4


def test_plan_orders_by_arm_then_repo_then_commit_then_run():
    p = queue.plan(["x", "y"], {"r1": [("s", "vulnerable", "")], "r2": [("t", "vulnerable", "c")]}, 2)
    assert p[:4] == [("x", "r1", "s", "", 1), ("x", "r1", "s", "", 2),
                     ("x", "r2", "t", "c", 1), ("x", "r2", "t", "c", 2)]
    assert p[-1] == ("y", "r2", "t", "c", 2)


def test_pending_skips_terminal_but_returns_aborted(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    sts = ("ok", "crashed", "hung", "error", "aborted")
    for st in sts:
        _start(conn, st, st)
    plan = [("a", "r", st, "", 1) for st in sts] + [("a", "r", "new", "", 1)]
    assert queue.pending(conn, plan) == [("a", "r", "aborted", "", 1), ("a", "r", "new", "", 1)]


def test_pending_uses_latest_attempt(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    _start(conn, "error", "s", attempt=2)  # newer attempt inserted first: ORDER BY must decide
    _start(conn, "aborted", "s", attempt=1)
    _start(conn, "aborted", "t", attempt=2)
    _start(conn, "ok", "t", attempt=1)
    assert queue.pending(conn, [("a", "r", "s", "", 1), ("a", "r", "t", "", 1)]) == [("a", "r", "t", "", 1)]


def test_pending_distinguishes_commit_and_case(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    _start(conn, "ok", "v", case="c1")
    plan = [("a", "r", "v", "c1", 1), ("a", "r", "v", "c2", 1), ("a", "r", "p", "c1", 1)]
    assert queue.pending(conn, plan) == plan[1:]


def test_pending_reconciles_stale_running_to_crashed(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = _start(conn, "running", "s")
    assert queue.pending(conn, [("a", "r", "s", "", 1)]) == []  # crashed is terminal: not retried
    assert conn.execute("select status, ended from runs where id=?", (rid,)).fetchone()[0] == "crashed"
    assert conn.execute("select ended from runs where id=?", (rid,)).fetchone()[0]


def test_fixtures_are_labeled_uncaptured():
    for name in ("limit_claude.json", "limit_codex.json"):
        assert json.loads((FIX / name).read_text())["captured"] is False


def test_classify_exit_marks_usage_limit_aborted():
    from eval import run
    lim = json.loads((FIX / "limit_claude.json").read_text())
    assert run.classify_exit("error", [json.dumps(lim)], source="claude") == "aborted"
    assert run.classify_exit("error", ["Traceback ..."], source="claude") == "error"
    cx = json.loads((FIX / "limit_codex.json").read_text())
    assert run.classify_exit("crashed", [json.dumps(cx)], source="codex") == "aborted"
    assert run.classify_exit("error", ['{"type":"result","subtype":"error_rate_limit"}'],
                             source="claude") == "aborted"
    assert run.classify_exit("error", ["HTTP 429 Too Many Requests"], source="codex") == "aborted"


def test_classify_exit_never_overrides_ok_or_model_text():
    from eval import run
    assert run.classify_exit("ok", ['{"type":"result","result":"usage limit reached"}'],
                             source="claude") == "ok"
    # the model's own prose about rate limits is not a CLI limit signal
    line = json.dumps({"type": "assistant", "message": {"content": [{"type": "text",
                       "text": "this endpoint lacks a rate limit"}]}})
    assert run.classify_exit("error", [line], source="claude") == "error"


def test_classify_exit_generic_limit_text_stays_error():
    from eval import run
    for txt in ("context limit reached", "memory limit reached", "max turns limit reached",
                "neo4j: transaction memory limit exceeded"):
        assert run.classify_exit("error", [txt], source="claude") == "error"
    assert run.classify_exit("error", ["plan usage limit reached"], source="claude") == "aborted"


def test_classify_exit_only_for_claude_and_codex():
    from eval import run
    for src in ("lm", "lm-base", ""):
        assert run.classify_exit("error", ["Claude AI usage limit reached|1", "HTTP 429"],
                                 source=src) == "error"
