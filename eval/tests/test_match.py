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
    f = [{"file": "app.js", "function": "handler", "line": 100, "cwe": "CWE-89",
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
