from orion.lm import codeindex as ci, cases
from train import stage1

VULN = ("def view(r):\n    q = 'SELECT ' + r\n    return db.execute(q)\n\n"
        "def other(a):\n    log(a)\n    x = a\n    y = x\n    return y\n\n"
        "def third(b):\n    x = f(b)\n    y = x\n    z = y\n    return z\n")
PATCHED = VULN.replace("    q = 'SELECT ' + r\n    return db.execute(q)\n", "    return db.execute('SELECT ?', [r])\n")
PAIR = {"id": "CVE-1", "cwe": ["CWE-89"], "cwe_class": "dataflow"}
HUNK = [{"file": "app.py", "old_file": "app.py", "old_start": 2, "old_end": 3, "new_start": 2, "new_end": 2}]

def _idx(tmp_path, text=VULN):
    (tmp_path / "app.py").write_text(text); return ci.RepoIndex(str(tmp_path))

def test_single_function_fix_gives_vuln_patched_negatives(tmp_path):
    """The changed function is the positive, its fixed version the negative pair, and unchanged functions are extra negatives."""
    ex, rec = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": PATCHED},
                                budget=cases.CaseBudget(), n_negatives=2, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable", "patched", "negative", "negative"]
    assert ex[0]["lead"] == {"flow_id": "F0", "file": "app.py", "function": "view", "line": 2,
                             "cwe": "CWE-89", "confidence": "HIGH"}
    assert ex[1]["lead"] is None and "execute('SELECT ?'" in ex[1]["case"]["snippets"][0]["code"]
    assert {e["case"]["snippets"][0]["function"] for e in ex[2:]} == {"other", "third"}
    assert rec["status"] == "ok" and rec["tiers"] == {"single": 1}

def test_seeded_negatives_are_deterministic(tmp_path):
    a, _ = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=1, seed=3)
    b, _ = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=1, seed=3)
    assert a == b

def test_annotation_beats_changed_functions(tmp_path):
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "third", "start_line": 11, "end_line": 15, "vulnerable_lines": [12]}]}
    ex, rec = stage1.cases_from(pair, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex[0]["lead"]["function"] == "third" and ex[0]["lead"]["line"] == 12 and rec["tiers"] == {"annotated": 1}

def test_deleted_function_keeps_vulnerable_drops_patched(tmp_path):
    """Review Focus 2."""
    ex, rec = stage1.cases_from(PAIR, HUNK, _idx(tmp_path), {"app.py": VULN.split("def other")[0].replace("view", "renamed")},
                                budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable"] and "patched_missing" in rec["reason"]

def test_sprawling_and_test_only_fixes_yield_nothing(tmp_path):
    """More than MAX_MULTI changed functions is too noisy to label; test-only fixes have no target."""
    vuln4 = VULN + "\ndef fourth(c):\n    g(c)\n    return c\n"          # fourth = lines 17-19
    four = [{"file": "app.py", "old_file": "app.py", "old_start": s, "old_end": s, "new_start": s, "new_end": s}
            for s in (2, 6, 12, 18)]                                       # one line in each of 4 functions
    ex, rec = stage1.cases_from(PAIR, four, _idx(tmp_path, vuln4), {"app.py": vuln4},
                                budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "sprawling"
    tests_only = [{"file": "tests/test_app.py", "old_file": "tests/test_app.py", "old_start": 1, "old_end": 1, "new_start": 1, "new_end": 1}]
    ex, rec = stage1.cases_from(PAIR, tests_only, _idx(tmp_path), {}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "no_target"

# --- additions beyond the brief ---

def test_primary_cwe_prefers_dataflow_then_first():
    assert stage1.primary_cwe({"cwe": ["CWE-20", "CWE-89"]}) == "CWE-89"
    assert stage1.primary_cwe({"cwe": ["CWE-20", "CWE-400"]}) == "CWE-20"
    assert stage1.primary_cwe({"cwe": []}) is None

def test_patched_example_does_not_mutate_the_vulnerable_index(tmp_path):
    idx = _idx(tmp_path)
    before = (dict(idx.files), dict(idx._text))
    stage1.cases_from(PAIR, HUNK, idx, {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert (dict(idx.files), dict(idx._text)) == before
    ex, _ = stage1.cases_from(PAIR, HUNK, idx, {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert "q = 'SELECT '" in ex[0]["case"]["snippets"][0]["code"]

def test_sink_location_resolves_by_suffix_and_locations_by_line(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "app.py").write_text(VULN)
    idx = ci.RepoIndex(str(tmp_path))
    h = [{"file": "pkg/app.py", "old_file": "pkg/app.py", "old_start": 2, "old_end": 3, "new_start": 2, "new_end": 2}]
    t, _ = stage1.targets({**PAIR, "sink_location": "app.py:12:5"}, h, idx, {"pkg/app.py": PATCHED})
    assert [(x["tier"], x["name"], x["anchor_old"]) for x in t] == [("annotated", "third", 12)]
    loc = {"locations": [{"sink": {"file": "pkg/app.py", "lineno": 6}, "source": {}}, {"block": {"file": "pkg/app.py", "start_lineno": 12}}]}
    t, _ = stage1.targets({**PAIR, **loc}, h, idx, {})
    assert [x["name"] for x in t] == ["other", "third"]

def test_unresolvable_annotation_falls_back_to_changed_function(tmp_path):
    pair = {**PAIR, "vuln_methods": [{"file": "gone.py", "method": "x", "start_line": 1, "end_line": 2, "vulnerable_lines": [1]}]}
    t, _ = stage1.targets(pair, HUNK, _idx(tmp_path), {"app.py": PATCHED})
    assert t[0]["tier"] == "single" and t[0]["name"] == "view"
    assert t[0]["anchor_old"] == 2 and t[0]["patched_span"].name == "view" and t[0]["anchor_new"] == 2

def test_add_only_hunk_anchors_on_insertion_line(tmp_path):
    h = [{"file": "app.py", "old_file": "app.py", "old_start": 7, "old_end": 6, "new_start": 8, "new_end": 8}]
    t, _ = stage1.targets(PAIR, h, _idx(tmp_path), {"app.py": VULN})
    assert t[0]["name"] == "other" and t[0]["anchor_old"] == 7

def test_multi_tier_and_unknown_class(tmp_path):
    h = [{"file": "app.py", "old_file": "app.py", "old_start": s, "old_end": s, "new_start": s, "new_end": s} for s in (2, 6)]
    t, _ = stage1.targets(PAIR, h, _idx(tmp_path), {"app.py": VULN})
    assert [x["tier"] for x in t] == ["multi", "multi"]
    ex, rec = stage1.cases_from({"id": "X", "cwe": [], "cwe_class": "unknown"}, HUNK, _idx(tmp_path), {"app.py": PATCHED},
                                budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "no_cwe"

def test_unchanged_patched_function_gets_no_patched_example(tmp_path):
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "third", "start_line": 11, "end_line": 15, "vulnerable_lines": [12]}]}
    ex, rec = stage1.cases_from(pair, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable"] and "patched_unchanged" in rec["reason"]
