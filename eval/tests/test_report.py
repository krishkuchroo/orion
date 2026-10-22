import json
import math
import os

from eval import db, report


def seed(conn, arm, repo, sha, caught, tokens):
    rid = db.start_run(conn, arm=arm, repo=repo, tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha=sha)
    db.finish_run(conn, rid, "ok")
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=tokens, output_tokens=0,
                      cache_read=0, cache_write=0, turns_used=1, turn_limit=None, peak_context=None,
                      exit_reason="ok", error_head=None)
    if caught:
        conn.execute("INSERT INTO matches(run_id, vuln_id, finding_idx, level, cwe_family, path_level)"
                     " VALUES(?,?,?,?,?,?)", (rid, repo, 0, "L1", 1, None)); conn.commit()
    return rid

def test_efficiency_is_caught_over_tokens(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=600_000)
    seed(conn, "orion-lm", "r2", "v2", caught=False, tokens=400_000)
    assert abs(report.efficiency(conn, "orion-lm") - 1.0) < 1e-6        # 1 caught / 1e6 tokens

def test_far_counts_l1_on_patched(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="orion-lm", repo="r1", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind="patched", commit_sha="p1")
    db.finish_run(conn, rid, "ok")
    conn.execute("INSERT INTO matches(run_id, vuln_id, finding_idx, level, cwe_family, path_level)"
                 " VALUES(?,?,?,?,?,?)", (rid, "r1", 0, "L1", 1, None)); conn.commit()
    assert report.far(conn, "orion-lm") == 1.0                          # 1 patched run, 1 false alarm

def test_bootstrap_ci_brackets_a_known_ratio(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    for i in range(8):                       # 8 repos; lm is exactly 2× as efficient everywhere
        seed(conn, "orion-lm", f"r{i}", f"v{i}", caught=True, tokens=500_000)
        seed(conn, "plain-opus5", f"r{i}", f"v{i}", caught=True, tokens=1_000_000)
    out = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=200)
    import math
    assert out["low"] <= math.log(2.0) <= out["high"] and out["low"] > 0

def test_aborted_runs_are_excluded(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=1_000_000)
    rid = db.start_run(conn, arm="orion-lm", repo="r1", tier="headline", run_no=2, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="v1")
    db.finish_run(conn, rid, "aborted")
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=9_000_000, output_tokens=0,
                      cache_read=0, cache_write=0, turns_used=1, turn_limit=None, peak_context=None,
                      exit_reason="limit", error_head=None)
    assert abs(report.efficiency(conn, "orion-lm") - 1.0) < 1e-6        # aborted tokens never count


# ---- beyond the brief -------------------------------------------------------------------------

def _run(conn, arm, repo, sha, *, kind="vulnerable", run_no=1, status="ok", case_id=""):
    rid = db.start_run(conn, arm=arm, repo=repo, tier="headline", run_no=run_no, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind=kind, commit_sha=sha,
                       case_id=case_id)
    db.finish_run(conn, rid, status)
    return rid


def _match(conn, rid, vuln, level="L1", path_level=None):
    conn.execute("INSERT INTO matches(run_id, vuln_id, finding_idx, level, cwe_family, path_level)"
                 " VALUES(?,?,?,?,?,?)", (rid, vuln, 0, level, int(level == "L2"), path_level))
    conn.commit()


def test_lm_arm_tokens_come_from_steps(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = _run(conn, "orion-lm", "r1", "v1")
    db.log_step(conn, rid, step_no=0, kind="cypher", query="MATCH", row_count=3, prompt_tokens=300_000,
                completion_tokens=100_000, cached_tokens=250_000, wall_seconds=1.0, error=None)
    db.log_step(conn, rid, step_no=1, kind="judge", query=None, row_count=None, prompt_tokens=500_000,
                completion_tokens=100_000, cached_tokens=0, wall_seconds=1.0, error=None)
    _match(conn, rid, "r1")
    assert report._tokens(conn, rid) == 1_000_000            # cached tokens are inside prompt_tokens
    assert abs(report.efficiency(conn, "orion-lm") - 1.0) < 1e-6


def test_frontier_tokens_include_cache_read_and_write(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = _run(conn, "plain-opus5", "r1", "v1")
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=100, output_tokens=50,
                      cache_read=1000, cache_write=200, turns_used=1, turn_limit=None,
                      peak_context=None, exit_reason="ok", error_head=None)
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=10, output_tokens=5,
                      cache_read=0, cache_write=0, turns_used=1, turn_limit=None,
                      peak_context=None, exit_reason="ok", error_head=None)
    assert report._tokens(conn, rid) == 1365


def test_run_without_token_data_is_counted_missing_not_zero(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=1_000_000)
    rid = _run(conn, "orion-lm", "r2", "v2")                 # scored, caught, but no steps/agent_calls
    _match(conn, rid, "r2")
    assert report._tokens(conn, rid) is None
    d = report.efficiency_detail(conn, "orion-lm")
    assert d["n_no_token_data"] == 1 and d["n_runs"] == 2
    assert d["caught"] == 1 and d["tokens"] == 1_000_000     # the token-less run is in neither sum
    assert abs(d["E"] - 1.0) < 1e-6
    assert report.efficiency(conn, "orion-lm") == d["E"]


def test_efficiency_is_none_with_no_token_data_at_all(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = _run(conn, "orion-lm", "r1", "v1")
    _match(conn, rid, "r1")
    assert report.efficiency(conn, "orion-lm") is None
    assert report.efficiency_detail(conn, "orion-lm")["n_no_token_data"] == 1


def test_running_runs_are_excluded(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=1_000_000)
    rid = db.start_run(conn, arm="orion-lm", repo="r2", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="v2")
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=5_000_000, output_tokens=0,
                      cache_read=0, cache_write=0, turns_used=1, turn_limit=None, peak_context=None,
                      exit_reason=None, error_head=None)                  # still 'running'
    assert abs(report.efficiency(conn, "orion-lm") - 1.0) < 1e-6
    assert report.efficiency_detail(conn, "orion-lm")["n_runs"] == 1


def test_crashed_and_hung_runs_are_scored(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=500_000)
    for i, st in enumerate(("crashed", "hung", "error")):
        rid = _run(conn, "orion-lm", f"x{i}", f"v{i}", status=st)
        db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=500_000, output_tokens=0,
                          cache_read=0, cache_write=0, turns_used=1, turn_limit=None, peak_context=None,
                          exit_reason=st, error_head=None)
    assert abs(report.efficiency(conn, "orion-lm") - 0.5) < 1e-6         # 1 caught / 2M tokens


def test_far_excludes_owasp_case_rows_and_aborted(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = _run(conn, "orion-lm", "r1", "p1", kind="patched")
    _match(conn, rid, "r1")
    _run(conn, "orion-lm", "r2", "p2", kind="patched")                     # clean patched run
    ow = _run(conn, "orion-lm", "owasp", "o1", kind="patched", case_id="BenchmarkTest00001")
    _match(conn, ow, "BenchmarkTest00001")
    ab = _run(conn, "orion-lm", "r3", "p3", kind="patched", status="aborted")
    _match(conn, ab, "r3")
    assert report.far(conn, "orion-lm") == 0.5
    d = report.far_detail(conn, "orion-lm")
    assert (d["FAR"], d["false_alarms"], d["n_runs"]) == (0.5, 1, 2)
    assert d["status_counts"] == {"ok": 2, "hung": 0, "crashed": 0, "error": 0, "aborted": 1}


def test_far_is_none_without_patched_runs(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=1)
    assert report.far(conn, "orion-lm") is None


def test_pass_at_k_three_runs_one_hit():
    assert report.pass_at_k([True, False, False], 3) == 1.0
    assert report.pass_pow_k([True, False, False], 3) == 0.0
    assert report.pass_at_k([True, True, True], 3) == 1.0
    assert report.pass_pow_k([True, True, True], 3) == 1.0
    assert report.pass_at_k([False, False, False], 3) == 0.0
    assert report.pass_at_k([True, False], 3) is None                       # fewer runs than k


def test_pass_at_k_unbiased_estimator_with_more_runs_than_k():
    # n=4, c=2, k=2: pass@2 = 1 - C(2,2)/C(4,2) = 1 - 1/6 ; pass^2 = C(2,2)/C(4,2) = 1/6
    assert abs(report.pass_at_k([1, 1, 0, 0], 2) - (1 - 1 / 6)) < 1e-12
    assert abs(report.pass_pow_k([1, 1, 0, 0], 2) - 1 / 6) < 1e-12


def test_holm_known_three_pvalue_example():
    adj = report.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert abs(adj["a"] - 0.03) < 1e-12
    assert abs(adj["b"] - 0.06) < 1e-12                                     # monotone: max(0.04*1, 0.06)
    assert abs(adj["c"] - 0.06) < 1e-12
    assert report.holm({"only": 0.2}) == {"only": 0.2}
    assert report.holm({"x": 0.9, "y": 0.8}) == {"x": 1.0, "y": 1.0}        # capped at 1
    assert report.holm({}) == {}


def test_wilson_interval():
    lo, hi = report.wilson(0, 10)
    assert lo == 0.0 and 0.25 < hi < 0.35
    lo, hi = report.wilson(5, 10)
    assert abs((lo + hi) / 2 - 0.5) < 1e-12 and lo < 0.5 < hi
    assert report.wilson(0, 0) == (None, None)


def test_bootstrap_output_fields_and_reproducibility(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    for i in range(6):
        seed(conn, "orion-lm", f"r{i}", f"v{i}", caught=(i % 2 == 0), tokens=100_000 * (i + 1))
        seed(conn, "plain-opus5", f"r{i}", f"v{i}", caught=True, tokens=900_000)
    a = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=300, seed=7)
    b = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=300, seed=7)
    assert a == b
    assert a["B"] == 300 and a["seed"] == 7 and a["n_repos"] == 6
    assert set(a) >= {"low", "high", "point", "B", "seed", "n_repos", "n_undefined", "frac_undefined",
                      "p_value"}
    assert a["low"] <= a["point"] <= a["high"]
    assert report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=300, seed=8) != a


def test_bootstrap_undefined_draws_are_reported_not_dropped(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    for i in range(4):
        seed(conn, "orion-lm", f"r{i}", f"v{i}", caught=True, tokens=100_000)
        seed(conn, "plain-opus5", f"r{i}", f"v{i}", caught=False, tokens=100_000)   # never catches
    out = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=50)
    assert out["n_undefined"] == 50 and out["frac_undefined"] == 1.0
    assert out["point"] == math.inf and out["high"] == math.inf and out["low"] == math.inf


def test_bootstrap_needs_two_paired_repos(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    seed(conn, "orion-lm", "r1", "v1", caught=True, tokens=1)
    out = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=10)
    assert out["n_repos"] == 0 and out["n_unmatched_repos"] == 1 and out["unmatched_repos"] == ["r1"]
    assert out["low"] is None and out["high"] is None and math.isnan(out["point"])


def test_bootstrap_pairs_on_repo_intersection(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    for i in range(6):                       # 6 paired repos, exact 2x everywhere
        seed(conn, "orion-lm", f"r{i}", f"v{i}", caught=True, tokens=500_000)
        seed(conn, "plain-opus5", f"r{i}", f"v{i}", caught=True, tokens=1_000_000)
    seed(conn, "orion-lm", "only-lm", "vx", caught=False, tokens=50_000_000)      # lm-only repo
    seed(conn, "plain-opus5", "only-opus", "vy", caught=True, tokens=1)           # opus-only repo
    out = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=100)
    assert out["n_repos"] == 6 and out["n_unmatched_repos"] == 2
    assert out["unmatched_repos"] == ["only-lm", "only-opus"]
    assert out["point"] == math.log(2.0) and out["low"] == out["high"] == math.log(2.0)
    assert out["n_undefined"] == 0
    d = report.decisions(conn, "orion-lm", ["plain-opus5"], B=100)["comparisons"]["plain-opus5"]
    assert d["efficiency_ci"]["n_repos"] == 6 and d["efficiency_ci"]["unmatched_repos"] == ["only-lm", "only-opus"]


def test_only_highest_attempt_is_scored(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    # attempt 1 aborted (usage limit) with a catch logged, attempt 2 ok: the slot counts once
    a1 = db.start_run(conn, arm="orion-lm", repo="r1", tier="headline", run_no=1, model_tag="m",
                      cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="v1", attempt_no=1)
    db.finish_run(conn, a1, "aborted")
    _match(conn, a1, "r1")
    a2 = db.start_run(conn, arm="orion-lm", repo="r1", tier="headline", run_no=1, model_tag="m",
                      cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="v1", attempt_no=2)
    db.finish_run(conn, a2, "ok")
    db.log_agent_call(conn, a2, session_id="s", stage="run", input_tokens=1_000_000, output_tokens=0,
                      cache_read=0, cache_write=0, turns_used=1, turn_limit=None, peak_context=None,
                      exit_reason="ok", error_head=None)
    _match(conn, a2, "r1")
    assert [r["id"] for r in report._runs(conn, "orion-lm", "vulnerable")] == [a2]
    assert report.efficiency_detail(conn, "orion-lm")["n_runs"] == 1
    assert abs(report.efficiency(conn, "orion-lm") - 1.0) < 1e-6
    # defensive: even two scored attempts (should not happen) count once, the latest
    a3 = db.start_run(conn, arm="orion-lm", repo="r1", tier="headline", run_no=1, model_tag="m",
                      cli_versions="", orion_commit="c", commit_kind="vulnerable", commit_sha="v1", attempt_no=3)
    db.finish_run(conn, a3, "crashed")
    assert [r["id"] for r in report._runs(conn, "orion-lm", "vulnerable")] == [a3]


def test_pair_correct_scores_each_cve_against_its_own_patched_commit(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    # two CVE rows A and B of one repo (runs.repo = the row id), one run each; both caught; only B's
    # patched run has a false alarm
    va = _run(conn, "orion-lm", "A", "va")
    vb = _run(conn, "orion-lm", "B", "vb")
    _match(conn, va, "A")
    _match(conn, vb, "B")
    _run(conn, "orion-lm", "A", "pa", kind="patched")
    pb = _run(conn, "orion-lm", "B", "pb", kind="patched")
    _match(conn, pb, "B")
    pairs = [("A", "va", "pa"), ("B", "vb", "pb")]
    pc = report.pair_correct(conn, "orion-lm", pairs)
    assert pc == {"pair_correct": 0.5, "n_vulns": 2, "n_pairs": 2, "n_unpaired": 0, "n_vulns_without_runs": 0}
    # a pair naming ANOTHER row's commit finds no run of this row there: unpaired, never a catch
    assert report.pair_correct(conn, "orion-lm", [("A", "vb", "pa")]) == {
        "pair_correct": None, "n_vulns": 0, "n_pairs": 0, "n_unpaired": 1, "n_vulns_without_runs": 0}
    # missing side -> unpaired, never 0; unknown pair -> no runs
    pc = report.pair_correct(conn, "orion-lm", [("A", "va", "nope"), ("Z", "zz", "zz")])
    assert pc["pair_correct"] is None and pc["n_unpaired"] == 1 and pc["n_vulns_without_runs"] == 1
    sec = report.secondary(conn, pairs=pairs)["arms"]["orion-lm"]
    assert sec["pair_correct"] == 0.5 and sec["pair_correct_detail"]["n_pairs"] == 2
    assert report.secondary(conn)["arms"]["orion-lm"]["pair_correct"] is None     # no pairs -> None, not 0


def test_pair_correct_keys_runs_by_row_and_sha_for_a_shared_commit(tmp_path):
    """m8: two rows share a vulnerable commit (netflix/lemur) and a chain shares a commit between one
    row's patched and another's vulnerable side. Each row is scored on ITS runs, never last-write-wins."""
    conn = db.connect(str(tmp_path / "t.db"))
    c = _run(conn, "orion-lm", "C", "shared")          # row C on the shared vulnerable commit: caught
    _match(conn, c, "C")
    _run(conn, "orion-lm", "D", "shared")              # row D on the SAME commit: missed
    _run(conn, "orion-lm", "C", "pc", kind="patched")
    _run(conn, "orion-lm", "D", "pd", kind="patched")
    e = _run(conn, "orion-lm", "E", "ve")               # chain: E's patched commit is F's vulnerable one
    _match(conn, e, "E")
    _run(conn, "orion-lm", "E", "chain", kind="patched")
    f = _run(conn, "orion-lm", "F", "chain")
    _match(conn, f, "F")
    pf = _run(conn, "orion-lm", "F", "pf", kind="patched")
    _match(conn, pf, "F")
    pairs = [("C", "shared", "pc"), ("D", "shared", "pd"), ("E", "ve", "chain"), ("F", "chain", "pf")]
    pc = report.pair_correct(conn, "orion-lm", pairs)
    assert (pc["pair_correct"], pc["n_vulns"], pc["n_pairs"]) == (0.5, 4, 4)   # C 1, D 0, E 1, F 0 (its FA)


def test_open_readonly_never_creates_a_db(tmp_path):
    import pytest, sqlite3
    with pytest.raises(FileNotFoundError):
        report.open_readonly(str(tmp_path / "absent.db"))
    assert not (tmp_path / "absent.db").exists()
    db.connect(str(tmp_path / "t.db")).close()
    conn = report.open_readonly(str(tmp_path / "t.db"))
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO events(run_id) VALUES (1)")
    assert report.efficiency(conn, "orion-lm") is None


def test_beats_combines_ci_and_far_margin(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    for i in range(8):
        seed(conn, "orion-lm", f"r{i}", f"v{i}", caught=True, tokens=500_000)
        seed(conn, "plain-opus5", f"r{i}", f"v{i}", caught=True, tokens=1_000_000)
        _run(conn, "orion-lm", f"r{i}", f"p{i}", kind="patched")
        _run(conn, "plain-opus5", f"r{i}", f"p{i}", kind="patched")
    out = report.beats(conn, "orion-lm", "plain-opus5", B=200)
    assert out["efficiency_ci_above_zero"] is True
    assert out["far_lm"] == 0.0 and out["far_other"] == 0.0 and out["far_ok"] is True
    assert out["beats"] is True and out["far_margin"] == 0.05
    # a false alarm on every lm patched run breaks non-inferiority
    for rid, in conn.execute("SELECT id FROM runs WHERE arm='orion-lm' AND commit_kind='patched'"):
        _match(conn, rid, "x")
    out = report.beats(conn, "orion-lm", "plain-opus5", B=200)
    assert out["far_ok"] is False and out["beats"] is False


def test_decisions_holm_adjusts_across_comparators(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    for i in range(8):
        seed(conn, "orion-lm", f"r{i}", f"v{i}", caught=True, tokens=500_000)
        seed(conn, "plain-opus5", f"r{i}", f"v{i}", caught=True, tokens=1_000_000)
        seed(conn, "plain-gpt", f"r{i}", f"v{i}", caught=True, tokens=500_000)   # equal to lm
        for arm in ("orion-lm", "plain-opus5", "plain-gpt"):
            _run(conn, arm, f"r{i}", f"p{i}", kind="patched")
    out = report.decisions(conn, "orion-lm", ["plain-opus5", "plain-gpt"], B=200)
    assert set(out["comparisons"]) == {"plain-opus5", "plain-gpt"}
    assert out["comparisons"]["plain-opus5"]["beats"] is True
    assert out["comparisons"]["plain-gpt"]["beats"] is False                 # log ratio = 0 everywhere
    for c in out["comparisons"].values():
        assert c["holm_p"] >= c["p_value"]
        assert c["holm_alpha"] <= out["alpha"]


def test_secondary_metrics(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    pl = json.dumps({"fix_traversal": True, "entry_hit": False, "edge_validity": None, "waypoint_f1": 0.5})
    # vuln v1: 3 runs, caught in 2 (one L2); patched runs clean except run 2
    for r in (1, 2, 3):
        rid = _run(conn, "orion-lm", "r1", "v1", run_no=r)
        if r == 1:
            _match(conn, rid, "r1", "L2", pl)
        if r == 2:
            _match(conn, rid, "r1", "L1")
        prid = _run(conn, "orion-lm", "r1", "p1", kind="patched", run_no=r)
        if r == 2:
            _match(conn, prid, "r1", "L1")
        db.log_resource(conn, rid, phase="run", wall_seconds=10.0 * r, peak_rss_mb=100.0 * r,
                        graph_nodes=None, graph_edges=None, loc=None)
    db.log_resource(conn, rid, phase="build", wall_seconds=99.0, peak_rss_mb=900.0,
                    graph_nodes=1, graph_edges=1, loc=1)
    sec = report.secondary(conn, pairs=[("r1", "v1", "p1")])
    s = sec["arms"]["orion-lm"]
    assert abs(s["recall_l1"] - 2 / 3) < 1e-12
    assert abs(s["recall_l2"] - 1 / 3) < 1e-12
    assert abs(s["pair_correct"] - 1 / 3) < 1e-12           # run1: caught+clean; run2: caught+FA; run3: miss
    assert s["pair_correct_detail"]["n_pairs"] == 3
    assert s["pass_at_3"] == 1.0 and s["pass_pow_3"] == 0.0
    assert s["n_vulns"] == 1 and s["n_vuln_runs"] == 3 and s["n_patched_runs"] == 3
    assert s["path_levels"]["fix_traversal"] == 1.0 and s["path_levels"]["entry_hit"] == 0.0
    assert s["path_levels"]["waypoint_f1"] == 0.5 and s["path_levels"]["edge_validity"] is None
    assert s["path_levels"]["n"] == 1
    assert s["wall_seconds"]["mean"] == 20.0 and s["peak_rss_mb"]["max"] == 300.0
    assert s["wall_seconds"]["n_missing"] == 3                 # the 3 patched runs logged nothing
    assert s["graph_build"] == {"wall_seconds_total": 99.0, "wall_seconds_mean": 99.0, "peak_rss_mb": 900.0, "n": 1}
    assert s["dollars"] is None and s["n_no_token_data"] == 3
    assert s["youden_j"] is None and s["ppi_precision"] is None
    assert sec["seed"] == 0


def test_secondary_dollars_only_with_price_table(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = _run(conn, "plain-opus5", "r1", "v1")
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=1_000_000, output_tokens=500_000,
                      cache_read=2_000_000, cache_write=1_000_000, turns_used=1, turn_limit=None,
                      peak_context=None, exit_reason="ok", error_head=None)
    assert report.secondary(conn)["arms"]["plain-opus5"]["dollars"] is None
    prices = {"plain-opus5": {"uncached_in": 15.0, "cache_read": 1.5, "cache_write": 18.75, "out": 75.0}}
    d = report.secondary(conn, prices=prices)["arms"]["plain-opus5"]["dollars"]
    assert abs(d - (15.0 + 3.0 + 18.75 + 37.5)) < 1e-9
    assert report.secondary(conn, prices={"other": {}})["arms"]["plain-opus5"]["dollars"] is None


def test_pareto_table_and_svg(tmp_path):
    rows = [{"arm": "orion-lm", "cost": 1.0, "accuracy": 0.6},
            {"arm": "plain-opus5", "cost": 4.0, "accuracy": 0.8},
            {"arm": "plain-gpt", "cost": 5.0, "accuracy": 0.7},          # dominated by opus5
            {"arm": "no-data", "cost": None, "accuracy": 0.5}]
    out = report.pareto(rows, svg_path=str(tmp_path / "p.svg"))
    assert "| arm |" in out and "orion-lm" in out and "<svg" in out
    assert report.pareto_frontier(rows) == ["orion-lm", "plain-opus5"]
    svg = (tmp_path / "p.svg").read_text()
    assert svg.startswith("<svg") and "plain-gpt" in svg and "no-data" not in svg
    assert "no-data" in out                                   # table still lists it, as missing


def test_mde_is_an_honest_stub():
    assert report.mde() is None
    assert "Miller" in report.mde.__doc__


# ---- I1: clusters are repos (from the manifest), not row ids --------------------------------------

def _man(*rows):
    base = {"repo_url": "u", "tier": "headline", "kind": "dataflow", "vulnerable_commit": "v",
            "patched_commit": "p", "cwe": "CWE-89"}
    return {"repos": [dict(base, **r) for r in rows]}


def test_two_rows_of_one_repo_are_one_bootstrap_cluster(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    # rows CVE-a1 and CVE-a2 are both in repo acme/a; CVE-b and CVE-c in their own repos
    man = _man({"id": "CVE-a1", "repo": "Acme/A"}, {"id": "CVE-a2", "repo_canonical": "acme/a"},
               {"id": "CVE-b", "repo_url": "https://github.com/acme/b"}, {"id": "CVE-c", "repo": "acme/c"})
    for rid in ("CVE-a1", "CVE-a2", "CVE-b", "CVE-c"):
        seed(conn, "orion-lm", rid, "v-" + rid, caught=True, tokens=500_000)
        seed(conn, "plain-opus5", rid, "v-" + rid, caught=True, tokens=1_000_000)
    with_m = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=50, manifest=man)
    without = report.paired_bootstrap(conn, "orion-lm", "plain-opus5", B=50)
    assert with_m["n_repos"] == 3 and without["n_repos"] == 4       # repos, not CVEs
    assert report.manifest_index(man)["CVE-a1"]["repo"] == report.manifest_index(man)["CVE-a2"]["repo"] == "acme/a"
    d = report.efficiency_detail(conn, "orion-lm", manifest=man)
    assert (d["n_repos"], d["n_rows"], d["n_runs"]) == (3, 4, 4)
    seed(conn, "orion-lm", "CVE-x", "vx", caught=True, tokens=1)    # a row the manifest does not have
    assert report.unknown_rows(conn, man) == ["CVE-x"]
    assert report.efficiency_detail(conn, "orion-lm", manifest=man)["n_rows"] == 4   # in no table


# ---- I2: partitions (headline dataflow primary; access-control and scale separate) + statuses -------

def test_partitions_split_headline_access_control_and_scale(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    man = _man({"id": "H", "repo": "o/h"}, {"id": "AC", "repo": "o/ac", "kind": "access_control"},
               {"id": "S", "repo": "o/s", "tier": "scale"}, {"id": "SAC", "repo": "o/s2", "tier": "scale",
                                                              "kind": "access_control"})
    assert [report.partition_of(r) for r in man["repos"]] == ["headline", "access_control", "scale", "scale"]
    seed(conn, "orion-lm", "H", "vh", caught=True, tokens=1_000_000)
    seed(conn, "orion-lm", "AC", "vac", caught=True, tokens=100)
    seed(conn, "orion-lm", "S", "vs", caught=False, tokens=100)
    _run(conn, "orion-lm", "S", "vs2", run_no=2, status="error")
    _run(conn, "orion-lm", "H", "ph", kind="patched")
    _match(conn, _run(conn, "orion-lm", "AC", "pac", kind="patched"), "AC")
    _run(conn, "orion-lm", "S", "ps", kind="patched", status="crashed")
    _run(conn, "orion-lm", "S", "ps2", kind="patched", run_no=2, status="aborted")
    h = report.efficiency_detail(conn, "orion-lm", manifest=man)               # PRIMARY = headline
    assert (h["caught"], h["tokens"], h["n_runs"]) == (1, 1_000_000, 1) and h["E"] == 1.0
    assert report.far(conn, "orion-lm", manifest=man) == 0.0                  # the AC false alarm is not here
    ac = report.far_detail(conn, "orion-lm", manifest=man, partition="access_control")
    assert (ac["FAR"], ac["n_runs"]) == (1.0, 1)
    sc = report.far_detail(conn, "orion-lm", manifest=man, partition="scale")
    assert sc["n_runs"] == 1 and sc["status_counts"] == {"ok": 0, "hung": 0, "crashed": 1, "error": 0, "aborted": 1}
    sv = report.efficiency_detail(conn, "orion-lm", manifest=man, partition="scale")
    assert sv["status_counts"]["error"] == 1 and sv["status_counts"]["ok"] == 1 and sv["n_runs"] == 2
    allr = report.efficiency_detail(conn, "orion-lm", manifest=man, partition=None)
    assert allr["n_runs"] == 4
    sec = report.secondary(conn, manifest=man)["arms"]["orion-lm"]
    assert sec["status_counts"]["patched"]["ok"] == 1 and sec["n_vulns"] == 1
    assert sec["pair_correct_detail"] is not None                             # pairs from the manifest


def test_render_reports_partitions_separately_and_flags_a_missing_manifest(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    man = _man({"id": "H", "repo": "o/h"}, {"id": "AC", "repo": "o/ac", "kind": "access_control"},
               {"id": "S", "repo": "o/s", "tier": "scale"})
    for arm in ("orion-lm", "plain-opus5"):
        for rid in ("H", "AC", "S"):
            seed(conn, arm, rid, "v" + rid, caught=True, tokens=1000)
    out = report.render(conn, "orion-lm", ["plain-opus5"], manifest=man, B=20)
    assert "## Primary: headline dataflow rows" in out
    assert "## Access-control rows (reported separately)" in out and "## Scale tier (reported separately)" in out
    assert "ok 1 / hung 0 / crashed 0 / error 0 / aborted 0" in out
    assert "headline 1 rows in 1 repos" in out
    assert "NOT the pre-registered" in report.render(conn, "orion-lm", ["plain-opus5"], B=20)


# ---- m12: Youden J from the OWASP runs' findings ------------------------------------------------------

def _owasp_run(conn, tmp_path, arm, bench, case_id, findings, *, status="ok", write=True):
    from eval.run import run_dir_for
    rid = db.start_run(conn, arm=arm, repo=bench, tier="owasp", run_no=1, model_tag="m", cli_versions="",
                       orion_commit="c", commit_kind="owasp", commit_sha="pin", case_id=case_id)
    db.finish_run(conn, rid, status)
    if write:
        d = run_dir_for(arm, {"id": bench, "commit_sha": "pin", "case_id": case_id, "run_no": 1},
                        root=str(tmp_path / "runs"))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "findings.json"), "w") as f:
            json.dump({"findings": findings}, f)


def test_youden_j_is_wired_from_the_owasp_runs(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    case = lambda n, real: {"case_id": f"BenchmarkTest0000{n}", "category": "sqli", "real": real,
                            "cwe": "CWE-89", "file": f"testcode/BenchmarkTest0000{n}.py", "entry": "x"}
    sample = {"benchmarks": [{"id": "owasp-python", "cases": [case(1, True), case(2, True), case(3, False),
                                                               case(4, False)]}]}
    hit = lambda n: [{"file": f"testcode/BenchmarkTest0000{n}.py", "line_start": 3, "cwe": "CWE-89"}]
    _owasp_run(conn, tmp_path, "plain-opus5", "owasp-python", "BenchmarkTest00001", hit(1))     # TP
    _owasp_run(conn, tmp_path, "plain-opus5", "owasp-python", "BenchmarkTest00002", [])         # FN
    _owasp_run(conn, tmp_path, "plain-opus5", "owasp-python", "BenchmarkTest00003", hit(3))     # FP
    _owasp_run(conn, tmp_path, "plain-opus5", "owasp-python", "BenchmarkTest00004", [], status="crashed",
               write=False)                                                                     # TN, no file
    _owasp_run(conn, tmp_path, "plain-opus5", "owasp-python", "BenchmarkTest00009", hit(9))     # not in sample
    y = report.youden_detail(conn, "plain-opus5", sample, runs_root=str(tmp_path / "runs"))
    assert (y["tp"], y["fn"], y["fp"], y["tn"]) == (1, 1, 1, 1) and y["youden_j"] == 0.0
    assert (y["tpr"], y["fpr"], y["n_cases"]) == (0.5, 0.5, 4)
    assert y["n_no_findings_file"] == 1 and y["n_unknown_case"] == 1
    assert y["status_counts"]["crashed"] == 1 and y["by_benchmark"]["owasp-python"]["n_cases"] == 4
    sec = report.secondary(conn, owasp_sample=sample, runs_root=str(tmp_path / "runs"))
    assert sec["arms"]["plain-opus5"]["youden_j"] == 0.0
    assert report.secondary(conn)["arms"]["plain-opus5"]["youden_j"] is None       # no sample -> None
    # the OWASP rows never enter efficiency / FAR
    assert report.efficiency_detail(conn, "plain-opus5")["n_runs"] == 0


def test_youden_j_is_none_when_undefined(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    sample = {"benchmarks": [{"id": "owasp-java", "cases": [
        {"case_id": "BenchmarkTest00001", "real": True, "file": "A.java"}]}]}
    _owasp_run(conn, tmp_path, "orion-lm", "owasp-java", "BenchmarkTest00001", [])
    y = report.youden_detail(conn, "orion-lm", sample, runs_root=str(tmp_path / "runs"))
    assert y["youden_j"] is None and y["fpr"] is None and y["n_cases"] == 1         # no trap case: undefined
