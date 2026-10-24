import json

from eval import db, match

AK = {"file": "app.js", "function": "handler", "line_start": 100, "line_end": 104, "cwe": "CWE-89"}


def test_l1_line_window():
    assert match.l1({"file": "app.js", "function": "x", "line": 108}, AK)   # within +10 of 104..? (±10 of range)
    assert not match.l1({"file": "app.js", "function": "x", "line": 200}, AK)


def test_l1_function_name():
    assert match.l1({"file": "app.js", "function": "handler", "line": None}, AK)


def test_l2_requires_same_cwe_family():
    hit = {"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89"}
    assert match.l2(hit, AK)
    assert not match.l2({**hit, "cwe": "CWE-79"}, AK)


def test_one_to_one_assignment():
    aks = [AK, {**AK, "line_start": 100, "line_end": 104, "cwe": "CWE-78"}]
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89"}]
    out = match.match_run(f, aks)
    assert sum(1 for m in out if m["finding_idx"] == 0) == 1   # credits at most one vuln


def test_window_edges():
    assert match.l1({"file": "app.js", "function": None, "line": 90}, AK)
    assert match.l1({"file": "app.js", "function": None, "line": 114}, AK)
    assert not match.l1({"file": "app.js", "function": None, "line": 89}, AK)
    assert not match.l1({"file": "app.js", "function": None, "line": 115}, AK)


def test_file_none_never_matches():
    assert not match.l1({"file": None, "function": "handler", "line": 100}, AK)


def test_wrong_file_never_matches():
    assert not match.l1({"file": "other.js", "function": "handler", "line": 100}, AK)
    assert not match.l1({"file": "myapp.js", "function": "handler", "line": 100}, AK)


def test_file_prefix_forms():
    ak = {**AK, "file": "src/app.js"}
    assert match.l1({"file": "./src/app.js", "function": "handler", "line": None}, ak)
    assert match.l1({"file": "tree-root/src/app.js", "function": "handler", "line": None}, ak)
    assert match.l1({"file": "app.js", "function": "handler", "line": None}, ak)  # vice-versa
    assert not match.l1({"file": "src/App.js", "function": "handler", "line": None}, ak)


def test_method_full_name_last_segment():
    assert match.l1({"file": "app.js", "function": "routes.index.handler", "line": None}, AK)
    assert match.l1({"file": "app.js", "function": "Cls::handler", "line": None}, AK)
    assert match.l1({"file": "app.js", "function": "handler()", "line": None}, AK)
    assert match.l1({"file": "app.js", "function": "handler", "line": None}, {**AK, "function": "handler()"})
    assert not match.l1({"file": "app.js", "function": "routes.myhandler", "line": None}, AK)


def test_l2_one_hop_family():
    ak = {**AK, "cwe": "CWE-22"}
    hit = {"file": "app.js", "function": "handler", "line": 100}
    assert match.l2({**hit, "cwe": "CWE-23"}, ak)
    assert match.l2({**hit, "cwe": "CWE-22"}, ak)
    assert not match.l2({**hit, "cwe": "CWE-79"}, AK)
    assert not match.l2({**hit, "cwe": None}, AK)
    assert not match.l2({**hit, "file": None, "cwe": "CWE-89"}, AK)


def test_one_to_one_second_finding_unmatched():
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89"},
         {"file": "app.js", "function": "handler", "line": 101, "cwe": "CWE-89"}]
    out = match.match_run(f, [AK])
    assert [(m["finding_idx"], m["vuln_id"], m["level"], m["cwe_family"]) for m in out] == [(0, "0", "L2", True)]


def test_l2_preferred_over_l1():
    aks = [{**AK, "id": "a", "cwe": "CWE-78"}, {**AK, "id": "b", "cwe": "CWE-89"}]
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89"}]
    out = match.match_run(f, aks)
    assert out[0]["vuln_id"] == "b" and out[0]["level"] == "L2"


def test_l1_only_row():
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-79"}]
    out = match.match_run(f, [AK])
    assert out[0]["level"] == "L1" and out[0]["cwe_family"] is False and out[0]["path_level"] is None


def test_l1_fix_site():
    fs = {"file": "app.js", "line": 50, "function": "sanitize"}
    assert match.l1_fix_site({"file": "app.js", "function": "x", "line": 60}, fs)
    assert not match.l1_fix_site({"file": "app.js", "function": "x", "line": 61}, fs)
    assert match.l1_fix_site({"file": "app.js", "function": "sanitize", "line": None}, fs)
    assert not match.l1_fix_site({"file": None, "function": "sanitize", "line": 50}, fs)


PAK = {**AK, "id": "v1",
       "fix_sites": [{"file": "db.js", "line": 20, "function": "query"}],
       "accepted_entry_points": [{"uid": "e1", "kind": "http", "method_full_name": "routes.handler",
                                  "file": "app.js"}]}


def test_path_levels():
    f = {"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89",
         "path": [{"file": "app.js", "function": "handler", "line": 100, "role": "source"},
                  {"file": "db.js", "function": "query", "line": 25, "role": "sink"}]}
    pl = match.path_levels(f, PAK)
    assert pl["fix_traversal"] is True and pl["entry_hit"] is True
    assert pl["edge_validity"] is None and pl["waypoint_f1"] == 1.0


def test_path_levels_no_path():
    pl = match.path_levels({"file": "app.js", "path": []}, PAK)
    assert pl == {"fix_traversal": False, "entry_hit": False, "edge_validity": None, "waypoint_f1": None}


def test_path_levels_partial():
    f = {"path": [{"file": "x.js", "function": "other", "line": 1, "role": "a"},
                  {"file": "db.js", "function": "query", "line": 500, "role": "b"}]}
    pl = match.path_levels(f, PAK)
    assert pl["fix_traversal"] is False and pl["entry_hit"] is False
    assert abs(pl["waypoint_f1"] - 0.5) < 1e-9   # P=1/2, R=1/2


def test_match_run_path_level_json():
    # a key with fix_sites is matched against its sites (db.js:20), not the legacy range
    f = [{"file": "db.js", "function": "query", "line": 22, "cwe": "CWE-89",
          "path": [{"file": "app.js", "function": "handler", "line": 100, "role": "source"}]}]
    out = match.match_run(f, [PAK])
    assert out[0]["vuln_id"] == "v1"
    assert json.loads(out[0]["path_level"])["entry_hit"] is True


def test_write_matches_round_trip(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="orion-lm", repo="r", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c")
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89"}]
    rows = match.match_run(f, [AK])
    match.write_matches(conn, rid, rows)
    got = conn.execute("select run_id, vuln_id, finding_idx, level, cwe_family, path_level "
                       "from matches").fetchall()
    assert got == [(rid, "0", 0, "L2", "1", None)]


def test_key_without_line_end_uses_line_start():
    ak = {"file": "a.js", "function": None, "line_start": 100, "line_end": None}
    assert match.l1({"file": "a.js", "function": None, "line": 110}, ak)
    assert match.l1({"file": "a.js", "function": None, "line": 90}, ak)
    assert not match.l1({"file": "a.js", "function": None, "line": 111}, ak)


def test_inverted_bounds_are_swapped():
    ak = {"file": "a.js", "function": None, "line_start": 120, "line_end": 100}
    assert match.l1({"file": "a.js", "function": None, "line": 130}, ak)
    assert match.l1({"file": "a.js", "function": None, "line": 90}, ak)
    assert not match.l1({"file": "a.js", "function": None, "line": 131}, ak)


def test_read_matches_returns_bool(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    rid = db.start_run(conn, arm="a", repo="r", tier="headline", run_no=1, model_tag="m",
                       cli_versions="", orion_commit="c")
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89"}]
    match.write_matches(conn, rid, match.match_run(f, [AK]))
    assert match.read_matches(conn, rid)[0]["cwe_family"] is True


def test_l2_credits_any_cwe_in_cwes_when_present():
    ak = {**AK, "cwe": "CWE-918", "cwes": ["CWE-20", "CWE-918"]}
    hit = {"file": "app.js", "function": "handler", "line": 100}
    assert match.l2({**hit, "cwe": "CWE-918"}, ak)
    assert match.l2({**hit, "cwe": "CWE-20"}, ak)            # any listed CWE counts
    assert not match.l2({**hit, "cwe": "CWE-79"}, ak)
    assert not match.l2({**hit, "file": "other.js", "cwe": "CWE-20"}, ak)


def test_l2_falls_back_to_cwe_without_cwes():
    hit = {"file": "app.js", "function": "handler", "line": 100}
    assert match.l2({**hit, "cwe": "CWE-89"}, {**AK, "cwes": []})
    assert not match.l2({**hit, "cwe": "CWE-20"}, AK)


# ---- I4: real Joern full names on the manifest side; orion-lm nodes compared by file + line -----

JS_HANDLER = "app/routes/index.js::program:index"            # verbatim from fixtures/NodeGoat/cpg.bin
JAVA_POST = "org.sasanlabs.Application.main:void(java.lang.String[])"   # a real javasrc full name


def test_entry_hit_on_real_js_and_java_entry_full_names():
    for mfn, fn, file in ((JS_HANDLER, "index", "app/routes/index.js"), (JAVA_POST, "main", "A.java")):
        key = {"fix_sites": [], "accepted_entry_points": [{"uid": "e", "method_full_name": mfn, "file": file}]}
        f = {"arm": "plain-opus5", "path": [{"file": file, "function": fn, "line": 3}]}
        assert match.path_levels(f, key)["entry_hit"] is True, mfn
        assert match.path_levels(f, key)["waypoint_f1"] == 1.0


def test_l1_function_match_against_a_key_holding_a_full_name():
    key = {"file": "A.java", "function": JAVA_POST, "line_start": 500, "line_end": 500}
    assert match.l1({"file": "A.java", "function": "Application.main", "line": None}, key)
    assert not match.l1({"file": "A.java", "function": "String)", "line": None}, key)


LM_KEY = {"fix_sites": [{"file": "db.js", "line": 20, "end_line": 40, "function": "query"}],
          "accepted_entry_points": [{"uid": "e1", "method_full_name": JS_HANDLER,
                                     "file": "app/routes/index.js", "line": 5}]}


def test_orion_lm_nodes_are_compared_by_file_and_line_not_the_callee_name():
    # orion-lm path nodes carry the CALLEE's method_full_name (orion/lm/slice.py)
    path = [{"file": "app/routes/index.js", "function": "__ecma.Date:getDay", "line": 7, "role": "source"},
            {"file": "db.js", "function": "mongo.find", "line": 35, "role": "sink"}]
    pl = match.path_levels({"arm": "orion-lm", "path": path}, LM_KEY)
    assert pl["fix_traversal"] is True                  # 35 is inside [20-10, 40+10]
    assert pl["entry_hit"] is True and pl["waypoint_f1"] == 1.0
    # the same nodes read as a plain arm's: the callee names match nothing
    plain = match.path_levels({"arm": "plain-opus5", "path": path}, LM_KEY)
    assert plain["entry_hit"] is False and plain["fix_traversal"] is True


def test_orion_lm_entry_without_a_line_is_never_hit_and_windows_are_bounded():
    far = [{"file": "app/routes/index.js", "function": "x", "line": 16}]        # 5 + 10 < 16
    assert match.path_levels({"arm": "orion-lm", "path": far}, LM_KEY)["entry_hit"] is False
    no_line = {**LM_KEY, "accepted_entry_points": [dict(LM_KEY["accepted_entry_points"][0], line=None)]}
    near = [{"file": "app/routes/index.js", "function": "x", "line": 5}]
    pl = match.path_levels({"arm": "orion-lm-base", "path": near}, no_line)
    assert pl["entry_hit"] is False and pl["waypoint_f1"] == 0.0


def test_fix_traversal_honours_end_line():
    key = {"fix_sites": [{"file": "db.js", "line": 20, "end_line": 40}]}
    inside = {"path": [{"file": "db.js", "function": "q", "line": 50}]}
    beyond = {"path": [{"file": "db.js", "function": "q", "line": 51}]}
    assert match.path_levels(inside, key)["fix_traversal"] is True
    assert match.path_levels(beyond, key)["fix_traversal"] is False


# ---- I3: a manifest row's key = ANY fix site; patched runs use the patched-side sites ------------

def test_l1_fix_site_honours_end_line():
    fs = {"file": "app.js", "line": 50, "end_line": 70, "function": "sanitize"}
    assert match.l1_fix_site({"file": "app.js", "function": "x", "line": 80}, fs)      # 70 + 10
    assert not match.l1_fix_site({"file": "app.js", "function": "x", "line": 81}, fs)
    assert match.l1_fix_site({"file": "app.js", "function": "x", "line": 40}, fs)      # 50 - 10
    assert not match.l1_fix_site({"file": "app.js", "function": "x", "line": 39}, fs)
    assert match.l1_fix_site({"file": "app.js", "function": "x", "line": 60}, {**fs, "end_line": None})


MULTI = {"id": "CVE-1", "cwe": "CWE-89", "fix_sites": [
    {"file": "a.js", "line": 10, "end_line": 12, "function": "f"},
    {"file": "lib/b.js", "line": 300, "end_line": 330, "function": "g"}]}


def test_l1_credits_any_fix_site():
    assert match.l1({"file": "a.js", "function": None, "line": 22}, MULTI)
    assert match.l1({"file": "lib/b.js", "function": None, "line": 340}, MULTI)
    assert match.l1({"file": "lib/b.js", "function": "g", "line": None}, MULTI)
    assert not match.l1({"file": "lib/b.js", "function": "f", "line": 100}, MULTI)   # f lives in a.js
    assert not match.l1({"file": "c.js", "function": "f", "line": 11}, MULTI)
    assert not match.l1({"file": "a.js", "function": None, "line": 11}, {**MULTI, "fix_sites": []})


def test_l2_with_a_site_key():
    assert match.l2({"file": "a.js", "line": 11, "cwe": "CWE-89"}, MULTI)
    assert not match.l2({"file": "a.js", "line": 11, "cwe": "CWE-79"}, MULTI)
