import json

import pytest

from train import fixmap
from train.tests._git import GitRepo, bare_mirror


class StubDB:
    """Canned graph per scan_id. Same call shape as GraphDB.run_cypher (accepts **kw, answers EXPLAIN
    with query_type 'r'); dispatches on the label the query reads."""

    def __init__(self, scans, errors=None):
        self.scans, self.errors, self.queries = scans, errors or {}, []

    def run_cypher(self, scan_id, query, limit=50, **kw):
        self.queries.append((scan_id, query))
        if query.lstrip().upper().startswith("EXPLAIN"):
            return {"rows": [], "row_count": 0, "query_type": "r"}
        key = "flows" if "CandidateFlow" in query else "methods" if "CpgMethod" in query else "calls"
        if (scan_id, key) in self.errors:
            return {"error": self.errors[(scan_id, key)]}
        rows = self.scans.get(scan_id, {}).get(key, [])
        return {"rows": rows, "row_count": len(rows), "query_type": "r"}


def call(uid, f, line, name="c"):
    return {"uid": uid, "f": f, "l": line, "name": name}


def meth(fn, f, line):
    return {"fn": fn, "f": f, "l": line}


def flow(uid, path, rank, cat="code_exec"):
    return {"uid": uid, "source_uid": path[0], "sink_uid": path[-1], "sink_category": cat,
            "path_uids": json.dumps(path), "rank": rank}


# ───────────────────────────── fix_sites ─────────────────────────────

def test_fix_sites_vulnerable_uses_old_range_patched_uses_new_range():
    """The vulnerable scan is searched at the diff's OLD lines and the patched scan at the NEW lines;
    guards against looking up shifted line numbers on the wrong commit."""
    h = {"file": "a.js", "old_file": "a.js", "old_start": 10, "old_end": 11, "new_start": 20, "new_end": 21}
    db = StubDB({
        "v": {"calls": [call("v10", "a.js", 10), call("v11", "a.js", 11), call("v20", "a.js", 20)],
              "methods": [meth("m", "a.js", 1)]},
        "p": {"calls": [call("p10", "a.js", 10), call("p20", "a.js", 20), call("p21", "a.js", 21)],
              "methods": [meth("m", "a.js", 1)]}})
    (sv,) = fixmap.fix_sites(db, "v", [h], side="vulnerable")
    (sp,) = fixmap.fix_sites(db, "p", [h], side="patched")
    assert sv["call_uids"] == ["v10", "v11"] and (sv["start"], sv["end"]) == (10, 11)
    assert sp["call_uids"] == ["p20", "p21"] and (sp["start"], sp["end"]) == (20, 21)
    assert sv["method_full_name"] == sp["method_full_name"] == "m"
    assert sv["add_only"] is False and sv["windowed"] is False


def test_fix_sites_add_only_uses_enclosing_method_and_three_line_window():
    """An add-only hunk (empty old range, inserted after old line 10) maps on the vulnerable side to the
    calls within +-3 lines of the insertion point that sit in the SAME enclosing method; guards against
    an empty site for every 'added a sanitizer' fix and against grabbing the next method's calls."""
    h = {"file": "a.js", "old_file": "a.js", "old_start": 10, "old_end": 9, "new_start": 11, "new_end": 12}
    db = StubDB({"v": {"calls": [call("c6", "a.js", 6), call("c8", "a.js", 8), call("c10", "a.js", 10),
                                 call("c12", "a.js", 12), call("c13", "a.js", 13)],
                       "methods": [meth("f", "a.js", 1), meth("g", "a.js", 12)]}})
    (s,) = fixmap.fix_sites(db, "v", [h], side="vulnerable")
    assert s["add_only"] is True and s["windowed"] is True and s["line"] == 10
    assert s["method_full_name"] == "f"
    assert s["call_uids"] == ["c10", "c8"]     # c6 outside the window, c12/c13 belong to g


def test_fix_sites_normalises_graph_paths_and_excludes_test_files():
    """Graph paths with a leading './' or the absolute tree root match the diff's repo-relative path,
    and hunks in test files (same _is_test rule as D1) produce no site; guards against zero matches from
    a path-format mismatch and against test edits posing as fix sites."""
    hunks = [{"file": "src/a.js", "old_file": "src/a.js", "old_start": 5, "old_end": 5, "new_start": 5, "new_end": 5},
             {"file": "test/a.test.js", "old_file": "test/a.test.js", "old_start": 1, "old_end": 1,
              "new_start": 1, "new_end": 1}]
    db = StubDB({"v": {"calls": [call("c5", "./src/a.js", 5), call("t1", "test/a.test.js", 1)],
                       "methods": [meth("m", "/abs/tree/src/a.js", 2)]}})
    sites = fixmap.fix_sites(db, "v", hunks, side="vulnerable", root="/abs/tree")
    assert [(s["file"], s["call_uids"], s["method_full_name"]) for s in sites] == [("src/a.js", ["c5"], "m")]
    assert fixmap.norm_path("./src/a.js") == "src/a.js"
    assert fixmap.norm_path("/abs/tree/src/a.js", "/abs/tree") == "src/a.js"
    assert fixmap.norm_path("app/routes/index.js") == "app/routes/index.js"   # the observed real form


# ───────────────────────────── gold_flow ─────────────────────────────

SITE = [{"file": "a.js", "call_uids": ["call/π:7|x"]}]


def test_gold_flow_returns_flow_whose_path_contains_a_site_uid_with_opaque_uids():
    """The CandidateFlow whose parsed path_uids contains a fix-site call uid is returned, whatever the uid
    strings look like; guards against parsing uid formats (CpgParameter uids are changing upstream)."""
    db = StubDB({"v": {"flows": [flow("F1", ["src::param#1", "call/π:7|x", "sink!"], 3)]}})
    f, reason = fixmap.gold_flow(db, "v", SITE)
    assert reason is None and f["uid"] == "F1" and f["path_uids"] == ["src::param#1", "call/π:7|x", "sink!"]
    assert f["site_uids"] == ["call/π:7|x"]


def test_gold_flow_prefers_highest_ranked_flow_through_the_site():
    """Several flows through the site -> the best-ranked one (rank 0 is best) wins; a better-ranked flow
    that misses the site is ignored; guards against picking an arbitrary or off-site flow."""
    db = StubDB({"v": {"flows": [flow("R0", ["a", "b"], 0), flow("R5", ["s", "call/π:7|x"], 5),
                                 flow("R1", ["t", "call/π:7|x", "u"], 1)]}})
    f, reason = fixmap.gold_flow(db, "v", SITE)
    assert (f["uid"], reason) == ("R1", None)


def test_gold_flow_no_site_nodes():
    """Sites with no call uids (or no sites at all) -> (None, 'no_site_nodes'), without even reading the
    flows; guards against a crash or a wrong reason when the fix touched no graph node."""
    db = StubDB({"v": {"flows": [flow("F1", ["a"], 0)]}})
    assert fixmap.gold_flow(db, "v", [{"file": "a.js", "call_uids": []}]) == (None, "no_site_nodes")
    assert fixmap.gold_flow(db, "v", []) == (None, "no_site_nodes")


def test_gold_flow_no_flow_through_site_and_bad_rows_never_crash():
    """Site nodes exist but no flow passes through them -> (None, 'no_flow_through_site'); a malformed
    path_uids row is skipped and a DB error becomes a 'query_error' reason; guards against a single bad
    row or query aborting a yield run."""
    bad = {"uid": "B", "source_uid": "x", "sink_uid": "y", "sink_category": "sql", "path_uids": "{not json", "rank": 0}
    db = StubDB({"v": {"flows": [flow("F1", ["a", "b"], 0), bad]}})
    assert fixmap.gold_flow(db, "v", SITE) == (None, "no_flow_through_site")
    err = StubDB({}, errors={("v", "flows"): "ServiceUnavailable: down"})
    f, reason = fixmap.gold_flow(err, "v", SITE)
    assert f is None and reason.startswith("query_error") and "down" in reason


# ───────────────────────────── line mapping + yield ─────────────────────────────

def test_map_line_follows_inserts_deletes_edits_and_renames():
    """Old line -> new line(s) across -U0 hunks: lines shift past inserts/deletes, an edited line maps to
    the hunk's new range, a deleted line maps to nothing, renames change the path; guards against
    comparing vulnerable and patched nodes at unshifted lines."""
    hunks = [{"file": "b.js", "old_file": "a.js", "old_start": 2, "old_end": 1, "new_start": 3, "new_end": 4},  # +2 after 2
             {"file": "b.js", "old_file": "a.js", "old_start": 5, "old_end": 6, "new_start": 7, "new_end": 7},  # 2 -> 1
             {"file": "b.js", "old_file": "a.js", "old_start": 9, "old_end": 9, "new_start": 9, "new_end": 8}]  # delete 9
    m = fixmap.map_line
    assert m(hunks, "a.js", 2) == ("b.js", [2])
    assert m(hunks, "a.js", 3) == ("b.js", [5])
    assert m(hunks, "a.js", 6) == ("b.js", [7])
    assert m(hunks, "a.js", 8) == ("b.js", [9])
    assert m(hunks, "a.js", 9) == ("b.js", [])
    assert m(hunks, "a.js", 10) == ("b.js", [10])
    assert m(hunks, "other.js", 4) == ("other.js", [4])


def _yield_db():
    v = {"methods": [meth("handler", "a.js", 1)],
         "calls": [call("vS", "a.js", 5, "param"), call("vM", "a.js", 8, "concat"),
                   call("vK1", "a.js", 12, "exec"), call("vK2", "b.js", 30, "query")],
         "flows": [flow("F1", ["vS", "vM", "vK1"], 0), flow("F2", ["vS", "vK2"], 4, "sql"),
                   flow("F3", ["vM", "vK2"], 7, "sql")]}
    p = {"methods": [meth("handler", "a.js", 1)],
         "calls": [call("pS", "a.js", 6, "param"), call("pM", "a.js", 9, "concat"),
                   call("pK1", "a.js", 13, "execFile"), call("pK2", "b.js", 30, "query")],
         "flows": [flow("P2", ["pS", "pK2"], 0, "sql")]}
    return StubDB({"X:vulnerable": v, "X:patched": p})


YIELD_HUNKS = [{"file": "a.js", "old_file": "a.js", "old_start": 2, "old_end": 1, "new_start": 3, "new_end": 3},
               {"file": "a.js", "old_file": "a.js", "old_start": 12, "old_end": 12, "new_start": 13, "new_end": 13}]


def test_pair_yield_reports_gold_flow_and_flows_gone_on_patched():
    """The yield record names the best gold flow and lists the gold flows (flows through a fix site) whose
    source->sink no longer has a CandidateFlow on the patched scan. Identity is (file, line mapped
    through the diff, call name), because uids hash the scan_id and never match across scans; guards
    against reporting every flow as 'gone' (raw uid comparison) or none of them."""
    rec = fixmap.pair_yield(_yield_db(), "X", YIELD_HUNKS,
                            vulnerable_scan_id="X:vulnerable", patched_scan_id="X:patched")
    assert set(rec) >= {"id", "vulnerable_scan_id", "patched_scan_id", "n_sites", "gold_flow", "reason",
                        "flows_gone_on_patched"}
    assert rec["id"] == "X" and rec["n_sites"] == 2 and rec["reason"] is None
    assert rec["gold_flow"]["uid"] == "F1"
    # F1: exec rewritten to execFile -> gone. F2: same param->query flow, shifted line, new uids -> kept.
    # F3 never touched a fix site, so it is not a gold flow at all.
    assert [f["uid"] for f in rec["flows_gone_on_patched"]] == ["F1"]
    assert rec["n_site_flows"] == 2


def test_pair_yield_without_gold_flow_keeps_reason_and_never_raises():
    """A fix touching no graph node -> reason 'no_site_nodes'; site nodes but no flow through them ->
    reason 'no_flow_through_site' with an empty gone-list; gold_flow None in both; guards against a crash
    or a wrong reason on the many pairs that will have no gold flow."""
    rec = fixmap.pair_yield(_yield_db(), "X", [{"file": "b.js", "old_file": "b.js", "old_start": 99,
                                                "old_end": 99, "new_start": 99, "new_end": 99}],
                            vulnerable_scan_id="X:vulnerable", patched_scan_id="X:patched")
    assert rec["gold_flow"] is None and rec["reason"] == "no_site_nodes" and rec["n_sites"] == 1
    db = _yield_db()
    db.scans["X:vulnerable"]["flows"] = [flow("F9", ["vM"], 0)]
    rec = fixmap.pair_yield(db, "X", YIELD_HUNKS[1:], vulnerable_scan_id="X:vulnerable", patched_scan_id="X:patched")
    assert (rec["gold_flow"], rec["reason"], rec["flows_gone_on_patched"]) == (None, "no_flow_through_site", [])


# ───────────────────────────── hunks from the local mirror ─────────────────────────────

@pytest.mark.usefixtures("hermetic_git")
def test_fix_hunks_drop_files_only_touched_by_unrelated_commits_between_fixes(tmp_path):
    """For a linear multi-commit fix the vulnerable..patched diff also contains unrelated commits; only
    files touched by a fix commit are kept; guards against unrelated edits becoming 'fix sites'."""
    r = GitRepo(tmp_path / "r")
    a = r.commit({"app.js": "a\nb\nc\n", "other.js": "x\n"})
    b = r.commit({"app.js": "a\nB\nc\n"}, "fix 1")
    r.commit({"other.js": "y\n"}, "unrelated")
    d = r.commit({"app.js": "a\nB\nC\n"}, "fix 2")
    m = bare_mirror(r.path, tmp_path / "m.git")
    assert {h["file"] for h in fixmap.fix_hunks(m, a, d)} == {"app.js", "other.js"}
    assert {h["file"] for h in fixmap.fix_hunks(m, a, d, fix_shas=[b, d])} == {"app.js"}


@pytest.mark.usefixtures("hermetic_git")
def test_yield_all_writes_one_record_per_built_pair_and_resumes(tmp_path):
    """yield_all uses the hunks stored with each successful build (or diffs its local mirror if none were
    stored), writes one yield record per pair, and skips pairs already in the output and pairs whose
    build did not succeed; guards against redoing or double-counting pairs in the yield number, and
    against needing mirrors that were deleted to free disk."""
    r = GitRepo(tmp_path / "r")
    v = r.commit({"a.js": "".join(f"l{i}\n" for i in range(1, 15))})
    p = r.commit({"a.js": "".join(f"l{i}\n" for i in range(1, 15)).replace("l12\n", "safe12\n")})
    m = bare_mirror(r.path, tmp_path / "m.git")
    builds = [{"id": "X", "status": "ok", "mirror": m, "vulnerable_sha": v, "patched_sha": p, "fix_shas": [p],
               "vulnerable_scan_id": "X:vulnerable", "patched_scan_id": "X:patched"},
              {"id": "Y", "status": "build_failed"},
              {"id": "Z", "status": "ok", "mirror": "/pruned/mirror.git", "hunks": YIELD_HUNKS,
               "vulnerable_scan_id": "X:vulnerable", "patched_scan_id": "X:patched"}]
    out = tmp_path / "yield.jsonl"
    fixmap.yield_all(builds, _yield_db(), out=str(out), on_event=lambda *_: None)
    fixmap.yield_all(builds, _yield_db(), out=str(out), on_event=lambda *_: None)
    rows = [json.loads(x) for x in out.read_text().splitlines()]
    assert [x["id"] for x in rows] == ["X", "Z"]
    assert rows[0]["n_hunks"] == 1 and rows[0]["gold_flow"]["uid"] == "F1"
    assert rows[1]["n_hunks"] == 2 and rows[1]["gold_flow"]["uid"] == "F1"   # stored hunks, no mirror needed
