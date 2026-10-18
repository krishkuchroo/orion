import os

from eval import db, run
from eval.arms import ArmResult

META = {"id": "r1", "tier": "headline", "commit_sha": "c1"}


class FakeProc:
    def __init__(self, pid):
        self.pid = pid


def _run_one(conn, launcher, arm="plain-opus5", **over):
    kw = dict(arm=arm, repo_meta=META, run_no=1, model_tags={}, base_env={},
              orion_commit="c", cli_versions="claude=2.1.210", launcher=launcher)
    kw.update(over)
    return run.run_one(conn, **kw)


def test_run_one_records_status_from_launcher(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        on_line('{"type":"result"}')
        return ArmResult(status="ok", findings_path=str(tmp_path / "f.json"), usage=[])
    status = _run_one(conn, launcher)
    assert status == "ok"
    row = conn.execute("select status, cli_versions, effort from runs where arm='plain-opus5'").fetchone()
    assert row[0] == "ok" and row[1] == "claude=2.1.210" and row[2] == "xhigh"


def test_run_one_catches_launcher_exception(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def boom(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        raise RuntimeError("launch failed")
    status = _run_one(conn, boom, arm="plain-gpt")
    assert status == "error"
    err = conn.execute("select message from events where level='error'").fetchone()
    assert "launch failed" in err[0]


def test_run_one_logs_agent_call_per_usage_block(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    blocks = [{"uncached_in": 5, "cache_read": 50, "cache_write": 10, "out": 1, "reasoning": None},
              {"uncached_in": 7, "cache_read": None, "cache_write": None, "out": 2, "reasoning": 1}]

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        return ArmResult(status="ok", findings_path=None, usage=blocks)
    _run_one(conn, launcher)
    rows = conn.execute("select input_tokens, output_tokens, cache_read, cache_write, turns_used,"
                        " peak_context, stage from agent_calls order by id").fetchall()
    assert rows == [(5, 1, 50, 10, None, None, "run"), (7, 2, None, None, None, None, "run")]


def test_run_one_logs_resource_from_sampler_attached_via_on_start(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        on_start(FakeProc(os.getpid()))          # sampler attaches to a live process
        return ArmResult(status="ok", findings_path=None, usage=[])
    _run_one(conn, launcher)
    row = conn.execute("select phase, wall_seconds, peak_rss_mb, graph_nodes, graph_edges, loc"
                       " from resources").fetchone()
    assert row[0] == "run" and row[1] >= 0
    assert row[2] is None or row[2] > 0          # measured, or missing; never a guessed 0
    assert row[3:] == (None, None, None)
    assert conn.execute("select count(*) from resources").fetchone()[0] == 1


def test_run_one_without_on_start_records_no_rss(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        return ArmResult(status="ok", findings_path=None, usage=[])   # never spawned a process
    _run_one(conn, launcher)
    row = conn.execute("select wall_seconds, peak_rss_mb from resources").fetchone()
    assert row[0] >= 0 and row[1] is None


def test_run_one_logs_resource_even_when_launcher_raises(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def boom(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        on_start(FakeProc(os.getpid()))
        raise RuntimeError("x")
    assert _run_one(conn, boom) == "error"
    assert conn.execute("select phase from resources").fetchone() == ("run",)


def test_run_one_logs_steps_when_present(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    steps = [dict(step_no=1, kind="cypher", query="MATCH (n) RETURN n", row_count=3,
                  prompt_tokens=10, completion_tokens=5, cached_tokens=None,
                  wall_seconds=0.5, error=None)]

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        return ArmResult(status="ok", findings_path=None, usage=[], steps=steps)
    _run_one(conn, launcher)
    assert conn.execute("select step_no, kind, row_count from steps").fetchall() == [(1, "cypher", 3)]


def test_run_one_notes_missing_findings_as_a_miss(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        return ArmResult(status="ok", findings_path=None, usage=[])
    assert _run_one(conn, launcher) == "ok"
    msgs = [r[0] for r in conn.execute("select message from events where level='warn'")]
    assert any("miss" in m for m in msgs)
    assert conn.execute("select status from runs").fetchone() == ("ok",)


def test_run_one_passes_effort_to_launcher(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seen = {}

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        seen["effort"] = effort
        return ArmResult(status="ok", findings_path=None, usage=[])
    _run_one(conn, launcher, arm="plain-gpt")
    assert seen["effort"] == run.EFFORT.get("plain-gpt", "")


def test_run_one_finishes_run_when_post_launch_logging_fails(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        # a steps entry that does not match db.log_step's keyword fields
        return ArmResult(status="ok", findings_path=None, usage=[], steps=[{"bogus": 1}])
    assert _run_one(conn, launcher) == "error"
    assert conn.execute("select status, ended from runs").fetchone()[0] == "error"
    assert conn.execute("select ended from runs").fetchone()[0] is not None   # never left 'running'
    err = conn.execute("select message from events where level='error'").fetchone()
    assert err is not None and "bogus" in err[0]


def test_run_one_marks_usage_limit_aborted_and_takes_next_attempt(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        on_line('{"type":"result","is_error":true,"result":"Claude AI usage limit reached|1"}')
        return ArmResult(status="error", findings_path=None, usage=[])
    assert _run_one(conn, launcher) == "aborted"

    seen = {}

    def launcher2(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        seen["attempt"] = repo_meta["attempt_no"]
        return ArmResult(status="ok", findings_path=str(tmp_path / "f.json"), usage=[])
    assert _run_one(conn, launcher2) == "ok"
    rows = conn.execute("select attempt_no, status from runs order by attempt_no").fetchall()
    assert rows == [(1, "aborted"), (2, "ok")] and seen["attempt"] == 2


def _patch_main(monkeypatch, tmp_path, statuses, calls):
    import json
    from eval import preflight, shim_setup
    man = tmp_path / "m.json"
    man.write_text(json.dumps({"repos": [{"id": "r1", "repo_url": "u", "tier": "headline",
                                          "vulnerable_commit": "v1", "patched_commit": "p1"}]}))
    monkeypatch.setattr(run.repo, "mirror", lambda *a, **k: None)
    monkeypatch.setattr(preflight, "check", lambda: [])
    monkeypatch.setattr(shim_setup, "shim_dir", lambda: str(tmp_path))
    monkeypatch.setattr(run, "build_launcher", lambda **k: None)
    monkeypatch.setattr(run, "git_head", lambda *a: "c")
    it = iter(statuses)

    def fake_run_one(conn, *, arm, repo_meta, run_no, **kw):
        st = next(it)
        calls.append((arm, repo_meta["commit_sha"], repo_meta["commit_kind"], run_no, st))
        a = db.next_attempt(conn, arm=arm, repo="r1", commit_sha=repo_meta["commit_sha"],
                            case_id="", run_no=run_no)
        rid = db.start_run(conn, arm=arm, repo="r1", tier="h", run_no=run_no, model_tag="m",
                           cli_versions="", orion_commit="c", commit_sha=repo_meta["commit_sha"],
                           attempt_no=a)
        db.finish_run(conn, rid, st)
        return st
    monkeypatch.setattr(run, "run_one", fake_run_one)
    return ["--arm", "plain-opus5", "--runs", "1", "--manifest", str(man),
            "--db", str(tmp_path / "t.db"), "--resume-wait", "7"]


def test_main_plans_both_commits_and_resumes_after_abort(tmp_path, monkeypatch):
    calls, sleeps = [], []
    argv = _patch_main(monkeypatch, tmp_path, ["aborted", "ok", "ok"], calls)
    assert run.main(argv, sleep=sleeps.append) == 0
    assert sleeps == [7]
    assert calls == [("plain-opus5", "v1", "vulnerable", 1, "aborted"),
                     ("plain-opus5", "v1", "vulnerable", 1, "ok"),
                     ("plain-opus5", "p1", "patched", 1, "ok")]


def test_run_one_logs_matched_line_and_ignores_limit_text_for_local_arm(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        on_line("Claude AI usage limit reached|1")
        return ArmResult(status="error", findings_path=None, usage=[])
    assert _run_one(conn, launcher, arm="orion-lm") == "error"
    assert _run_one(conn, launcher) == "aborted"
    msg = conn.execute("select message from events where message like '%matched:%'").fetchone()[0]
    assert "usage limit reached" in msg


def test_run_one_keyboard_interrupt_finishes_aborted_and_reraises(tmp_path):
    import pytest
    conn = db.connect(str(tmp_path / "t.db"))

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        _run_one(conn, launcher)
    assert conn.execute("select status from runs").fetchone()[0] == "aborted"
