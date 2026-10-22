import os

import pytest

from eval import db, run
from eval.arms import ArmResult

META = {"id": "r1", "tier": "headline", "commit_sha": "c1"}
SITE = [{"file": "a.js", "line": 3, "end_line": 4, "function": "f", "method_full_name": "a.js::program:f"}]
# a labeled, keyed row: what run.main accepts without --unlabeled-ok
LABELED = {"id": "r1", "repo_url": "u", "tier": "headline", "vulnerable_commit": "v1",
           "patched_commit": "p1", "cwe": "CWE-89", "fix_sites": SITE, "fix_sites_patched": SITE,
           "accepted_entry_points": [], "labelers": ["k"]}


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
    man.write_text(json.dumps({"repos": [LABELED]}))
    from eval import manifest
    monkeypatch.setattr(manifest, "split_repos", lambda *a, **k: set())
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


@pytest.mark.parametrize("arm,flag", [("orion-lm", "--lm-model"), ("orion-lm-base", "--lm-base-model")])
@pytest.mark.parametrize("given", [None, "missing"])
def test_main_refuses_lm_arm_without_an_existing_model_path(tmp_path, monkeypatch, capsys, arm, flag,
                                                            given):
    """A misconfigured model path is a usage error (exit 2) before any run row or mirror exists,
    never a terminal, scored 'error' run."""
    calls, mirrored = [], []
    argv = _patch_main(monkeypatch, tmp_path, [], calls)
    monkeypatch.setattr(run.repo, "mirror", lambda *a, **k: mirrored.append(a))
    argv[argv.index("plain-opus5")] = arm
    if given:
        argv += [flag, str(tmp_path / "no-such-model")]
    assert run.main(argv) == 2
    assert calls == [] and mirrored == []
    assert not os.path.exists(tmp_path / "t.db")
    assert flag in capsys.readouterr().out


def test_main_passes_lm_model_paths_as_model_tags(tmp_path, monkeypatch):
    seen = []
    argv = _patch_main(monkeypatch, tmp_path, ["ok", "ok"], [])
    inner = run.run_one

    def spy(conn, **kw):
        seen.append((kw["arm"], kw["model_tags"].get(kw["arm"])))
        return inner(conn, **kw)
    monkeypatch.setattr(run, "run_one", spy)
    (tmp_path / "mdl").mkdir()
    argv[argv.index("plain-opus5")] = "orion-lm"
    monkeypatch.chdir(tmp_path)
    assert run.main(argv + ["--lm-model", "mdl"]) == 0
    assert seen == [("orion-lm", str(tmp_path / "mdl"))] * 2   # absolute path -> runs.model_tag


def test_main_plain_arms_need_no_lm_model(tmp_path, monkeypatch):
    calls = []
    argv = _patch_main(monkeypatch, tmp_path, ["ok", "ok"], calls)
    assert run.main(argv) == 0 and len(calls) == 2


def test_main_refuses_invalid_manifest_before_mirroring(tmp_path, monkeypatch, capsys):
    import json
    from eval import manifest
    calls = []
    argv = _patch_main(monkeypatch, tmp_path, [], calls)
    man = argv[argv.index("--manifest") + 1]
    open(man, "w").write(json.dumps({"repos": [{"id": "r1", "repo_url": "u", "tier": "headline",
                                                "vulnerable_commit": "v1"}]}))  # no patched_commit
    mirrored = []
    monkeypatch.setattr(run.repo, "mirror", lambda *a, **k: mirrored.append(a))
    monkeypatch.setattr(manifest, "split_repos", lambda *a, **k: set())
    assert run.main(argv) == 2
    assert mirrored == [] and calls == []
    assert "patched_commit" in capsys.readouterr().out


# ---- OWASP items (Task F2) ---------------------------------------------------------------------

def _owasp_case(n, cat="sqli", real=True, lang="python"):
    file = (f"testcode/BenchmarkTest{n:05d}.py" if lang == "python"
            else f"src/main/java/org/owasp/benchmark/testcode/BenchmarkTest{n:05d}.java")
    return {"case_id": f"BenchmarkTest{n:05d}", "category": cat, "real": real, "cwe": "CWE-89",
            "file": file, "entry": f"POST /{cat}-00/BenchmarkTest{n:05d} -> h"}


def _owasp_file(tmp_path, **over):
    import json
    data = {"version": 1, "seed": 0, "n_per_lang": 2, "benchmarks": [
        {"id": "owasp-java", "language": "java", "benchmark_version": "1.2",
         "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkJava", "pinned_sha": "a" * 40,
         "cases": [_owasp_case(1, lang="java"), _owasp_case(7, real=False, lang="java")]},
        {"id": "owasp-python", "language": "python", "benchmark_version": "0.1",
         "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkPython", "pinned_sha": "b" * 40,
         "cases": [_owasp_case(1), _owasp_case(3, real=False)]}]}
    data.update(over)
    p = tmp_path / "owasp_sample.json"
    p.write_text(json.dumps(data))
    return str(p)


def _spy_main(monkeypatch, tmp_path):
    from eval import manifest, preflight, shim_setup
    seen, mirrored = [], []
    monkeypatch.setattr(manifest, "split_repos", lambda *a, **k: set())
    monkeypatch.setattr(run.repo, "mirror", lambda url, d, **k: mirrored.append((url, d)))
    monkeypatch.setattr(preflight, "check", lambda: [])
    monkeypatch.setattr(shim_setup, "shim_dir", lambda: str(tmp_path))
    monkeypatch.setattr(run, "build_launcher", lambda **k: None)
    monkeypatch.setattr(run, "git_head", lambda *a: "c")

    def fake_run_one(conn, *, arm, repo_meta, run_no, **kw):
        seen.append((arm, repo_meta, run_no))
        a = db.next_attempt(conn, arm=arm, repo=repo_meta["id"], commit_sha=repo_meta["commit_sha"],
                            case_id=repo_meta["case_id"], run_no=run_no)
        rid = db.start_run(conn, arm=arm, repo=repo_meta["id"], tier=repo_meta["tier"], run_no=run_no,
                           model_tag="m", cli_versions="", orion_commit="c",
                           commit_sha=repo_meta["commit_sha"], case_id=repo_meta["case_id"], attempt_no=a)
        db.finish_run(conn, rid, "ok")
        return "ok"
    monkeypatch.setattr(run, "run_one", fake_run_one)
    return seen, mirrored


def test_main_queues_owasp_items_with_distinct_case_ids(tmp_path, monkeypatch):
    seen, mirrored = _spy_main(monkeypatch, tmp_path)
    argv = ["--arm", "plain-opus5", "--runs", "3", "--manifest", "", "--owasp", _owasp_file(tmp_path),
            "--db", str(tmp_path / "t.db"), "--mirror-root", str(tmp_path / "mirrors")]
    assert run.main(argv) == 0
    # one mirror per benchmark repo, not one per case
    assert mirrored == [("https://github.com/OWASP-Benchmark/BenchmarkJava", str(tmp_path / "mirrors/owasp-java")),
                        ("https://github.com/OWASP-Benchmark/BenchmarkPython", str(tmp_path / "mirrors/owasp-python"))]
    keys = [(m["id"], m["commit_sha"], m["case_id"], n) for _, m, n in seen]
    assert keys == [("owasp-java", "a" * 40, "BenchmarkTest00001", 1), ("owasp-java", "a" * 40, "BenchmarkTest00007", 1),
                    ("owasp-python", "b" * 40, "BenchmarkTest00001", 1), ("owasp-python", "b" * 40, "BenchmarkTest00003", 1)]
    assert len(set(keys)) == 4                                  # each case is its own queue item, R = 1
    for _, m, _ in seen:
        assert (m["tier"], m["commit_kind"]) == ("owasp", "owasp")
        assert m["case"]["case_id"] == m["case_id"] and m["case"]["file"]
        assert m["mirror_dir"] == str(tmp_path / "mirrors" / m["id"])
    conn = db.connect(str(tmp_path / "t.db"))
    assert sorted(conn.execute("SELECT repo, case_id FROM runs").fetchall()) == \
        [("owasp-java", "BenchmarkTest00001"), ("owasp-java", "BenchmarkTest00007"),
         ("owasp-python", "BenchmarkTest00001"), ("owasp-python", "BenchmarkTest00003")]
    assert run.main(argv) == 0 and len(seen) == 4               # all terminal: nothing requeued


def test_main_runs_manifest_rows_and_owasp_items_in_one_invocation(tmp_path, monkeypatch):
    seen, _ = _spy_main(monkeypatch, tmp_path)
    import json
    m = tmp_path / "m.json"
    m.write_text(json.dumps({"repos": [LABELED]}))
    argv = ["--arm", "plain-opus5", "--runs", "2", "--manifest", str(m), "--owasp", _owasp_file(tmp_path),
            "--owasp-runs", "1", "--db", str(tmp_path / "t.db")]
    assert run.main(argv) == 0
    kinds = [(meta["commit_kind"], n) for _, meta, n in seen]
    assert kinds.count(("vulnerable", 1)) == kinds.count(("vulnerable", 2)) == 1
    assert kinds.count(("patched", 1)) == kinds.count(("patched", 2)) == 1
    assert kinds.count(("owasp", 1)) == 4 and ("owasp", 2) not in kinds


@pytest.mark.parametrize("bad", ["duplicate", "no_sha"])
def test_main_refuses_an_invalid_owasp_sample_before_mirroring(tmp_path, monkeypatch, capsys, bad):
    import json
    seen, mirrored = _spy_main(monkeypatch, tmp_path)
    path = _owasp_file(tmp_path)
    data = json.loads(open(path).read())
    if bad == "duplicate":
        data["benchmarks"][1]["cases"].append(_owasp_case(3))
    else:
        data["benchmarks"][0]["pinned_sha"] = ""
    open(path, "w").write(json.dumps(data))
    argv = ["--arm", "plain-opus5", "--manifest", "", "--owasp", path, "--db", str(tmp_path / "t.db")]
    assert run.main(argv) == 2
    assert mirrored == [] and seen == []
    out = capsys.readouterr().out
    assert ("duplicate case_id" in out) if bad == "duplicate" else ("pinned_sha" in out)


# ---- I5: the test set cannot be run before it is labeled -------------------------------------------

@pytest.mark.parametrize("unlabeled", [dict(labelers=[]), dict(fix_sites=[]), dict(fix_sites_patched=[])])
def test_main_refuses_an_unlabeled_manifest_by_default(tmp_path, monkeypatch, capsys, unlabeled):
    import json
    calls, mirrored = [], []
    argv = _patch_main(monkeypatch, tmp_path, [], calls)
    monkeypatch.setattr(run.repo, "mirror", lambda *a, **k: mirrored.append(a))
    open(argv[argv.index("--manifest") + 1], "w").write(json.dumps({"repos": [dict(LABELED, **unlabeled)]}))
    assert run.main(argv) == 2
    assert calls == [] and mirrored == [] and not os.path.exists(tmp_path / "t.db")
    out = capsys.readouterr().out
    assert "require_labels" in out and "--unlabeled-ok" in out


def test_unlabeled_ok_runs_a_dev_manifest_with_a_loud_warning(tmp_path, monkeypatch, capsys):
    import json
    calls = []
    argv = _patch_main(monkeypatch, tmp_path, ["ok", "ok"], calls)
    dev = dict(LABELED, labelers=[], fix_sites=[])
    dev.pop("fix_sites_patched")
    open(argv[argv.index("--manifest") + 1], "w").write(json.dumps({"repos": [dev]}))
    assert run.main(argv + ["--unlabeled-ok"]) == 0 and len(calls) == 2
    out = capsys.readouterr().out
    assert "WARNING --unlabeled-ok" in out and "NOT checked" in out


def test_unlabeled_ok_still_refuses_a_broken_or_training_row(tmp_path, monkeypatch, capsys):
    import json
    from eval import manifest
    argv = _patch_main(monkeypatch, tmp_path, [], [])
    monkeypatch.setattr(manifest, "split_repos", lambda *a, **k: {"o/trained"})
    open(argv[argv.index("--manifest") + 1], "w").write(
        json.dumps({"repos": [dict(LABELED, labelers=[], repo="o/trained")]}))
    assert run.main(argv + ["--unlabeled-ok"]) == 2
    assert "training" in capsys.readouterr().out


def test_labeled_manifest_runs_without_the_flag_or_a_warning(tmp_path, monkeypatch, capsys):
    calls = []
    argv = _patch_main(monkeypatch, tmp_path, ["ok", "ok"], calls)
    assert run.main(argv) == 0 and len(calls) == 2
    assert "WARNING" not in capsys.readouterr().out


# ---- m14: a skipped row or benchmark is not a clean exit ------------------------------------------

def test_a_skipped_row_runs_the_rest_then_exits_nonzero_with_a_summary(tmp_path, monkeypatch, capsys):
    import json
    seen, _ = _spy_main(monkeypatch, tmp_path)

    def mirror(url, d, **k):
        if url == "bad-url":
            raise RuntimeError("clone failed: repository not found")
    monkeypatch.setattr(run.repo, "mirror", mirror)
    m = tmp_path / "m.json"
    m.write_text(json.dumps({"repos": [LABELED, dict(LABELED, id="r2", repo_url="bad-url")]}))
    argv = ["--arm", "plain-opus5", "--runs", "1", "--manifest", str(m), "--db", str(tmp_path / "t.db")]
    assert run.main(argv) == 1
    assert sorted(meta["id"] for _, meta, _ in seen) == ["r1", "r1"]        # r1 still ran, both commits
    out = capsys.readouterr().out
    assert "INCOMPLETE: skipped 1 item(s)" in out and "manifest row r2: clone failed" in out


def test_a_skipped_benchmark_exits_nonzero(tmp_path, monkeypatch, capsys):
    seen, _ = _spy_main(monkeypatch, tmp_path)

    def mirror(url, d, **k):
        if url.endswith("BenchmarkJava"):
            raise RuntimeError("network down")
    monkeypatch.setattr(run.repo, "mirror", mirror)
    argv = ["--arm", "plain-opus5", "--manifest", "", "--owasp", _owasp_file(tmp_path),
            "--db", str(tmp_path / "t.db")]
    assert run.main(argv) == 1
    assert {meta["id"] for _, meta, _ in seen} == {"owasp-python"}
    assert "OWASP benchmark (2 cases) owasp-java: network down" in capsys.readouterr().out
