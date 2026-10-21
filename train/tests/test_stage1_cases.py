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
    t, _ = stage1.targets(PAIR, h, _idx(tmp_path), {"app.py": VULN.replace("    x = a\n", "    x = a\n    check(x)\n")})
    assert t[0]["name"] == "other" and t[0]["anchor_old"] == 7

def test_multi_tier_and_unknown_class(tmp_path):
    h = [{"file": "app.py", "old_file": "app.py", "old_start": s, "old_end": s, "new_start": s, "new_end": s} for s in (2, 6)]
    fixed = VULN.replace("'SELECT ' + r", "'SELECT ' + esc(r)").replace("log(a)", "log(b)")   # both really change
    t, _ = stage1.targets(PAIR, h, _idx(tmp_path), {"app.py": fixed})
    assert [x["tier"] for x in t] == ["multi", "multi"]
    ex, rec = stage1.cases_from({"id": "X", "cwe": [], "cwe_class": "unknown"}, HUNK, _idx(tmp_path), {"app.py": PATCHED},
                                budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "no_cwe"

def test_unchanged_patched_function_gets_no_patched_example(tmp_path):
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "third", "start_line": 11, "end_line": 15, "vulnerable_lines": [12]}]}
    ex, rec = stage1.cases_from(pair, HUNK, _idx(tmp_path), {"app.py": PATCHED}, budget=cases.CaseBudget(), n_negatives=0, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable"] and "patched_unchanged" in rec["reason"]


# --- fix round 1: reviewer probes ---
import pytest
from train import diffs
from train.tests._git import GitRepo

B = cases.CaseBudget()


def _real(tmp_path, hermetic_git, old: dict, new: dict):
    """Vulnerable index + real `git diff -U0` hunks + patched text for a two-commit repo."""
    repo = GitRepo(tmp_path / "r")
    a = repo.commit(old)
    b = repo.commit(new)
    hunks = diffs.parse_u0(diffs.git_diff_u0(repo.path, a, b))
    repo.checkout(a)            # RepoIndex.source reads the disk: keep the vulnerable tree checked out
    return ci.RepoIndex(repo.path), hunks, {k: v for k, v in new.items()}


def test_negative_never_nested_in_or_around_a_target(tmp_path):
    """I1 (P1, P1b)."""
    src = "def outer():\n    a = 1\n    def inner():\n        log(a)\n        x = a\n        y = x\n        return y\n    return inner\n"
    (tmp_path / "app.py").write_text(src)
    idx = ci.RepoIndex(str(tmp_path))
    h = [{"file": "app.py", "old_file": "app.py", "old_start": 2, "old_end": 2, "new_start": 2, "new_end": 2}]
    ex, _ = stage1.cases_from(PAIR, h, idx, {"app.py": src.replace("a = 1", "a = 2")}, budget=B, n_negatives=5, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable", "patched"]
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "outer", "start_line": 1, "end_line": 8, "vulnerable_lines": [5]}]}
    ex, _ = stage1.cases_from(pair, h, idx, {"app.py": src}, budget=B, n_negatives=5, seed=0)
    assert "negative" not in [e["label"] for e in ex]


def test_annotated_functions_past_the_cap_are_never_negatives(tmp_path):
    """I2 (P2)."""
    src = "".join(f"def f{i}(a):\n    log(a)\n    x = a\n    y = x\n    return y\n\n" for i in range(5))
    (tmp_path / "app.py").write_text(src)
    idx = ci.RepoIndex(str(tmp_path))
    vm = [{"file": "app.py", "method": f"f{i}", "start_line": 6 * i + 1, "end_line": 6 * i + 5, "vulnerable_lines": [6 * i + 2]} for i in range(5)]
    h = [{"file": "app.py", "old_file": "app.py", "old_start": 2, "old_end": 2, "new_start": 2, "new_end": 2}]
    ex, rec = stage1.cases_from({**PAIR, "vuln_methods": vm}, h, idx, {"app.py": src.replace("log(a)", "log(b)", 1)},
                                budget=B, n_negatives=5, seed=0)
    assert rec["n_targets"] == 3 and "negative" not in [e["label"] for e in ex]


PY_OLD = "def f(a):\n    log(a)\n    return a\n"


@pytest.mark.parametrize("name,new", [
    ("new function at EOF", PY_OLD + "\ndef g(b):\n    return b\n"),
    ("new method appended after the last function", PY_OLD + "def g(b):\n    return b\n"),
    ("insertion at top of file", "import os\n" + PY_OLD),
])
def test_untouched_neighbour_is_not_a_target(tmp_path, hermetic_git, name, new):
    """I3: add-only hunks at line 0, after a function's last line, or holding a whole new function give no target."""
    idx, hunks, patched = _real(tmp_path, hermetic_git, {"m.py": PY_OLD}, {"m.py": new})
    ex, rec = stage1.cases_from(PAIR, hunks, idx, patched, budget=B, n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "no_target", name


def test_insertion_strictly_inside_a_body_is_a_target(tmp_path, hermetic_git):
    idx, hunks, patched = _real(tmp_path, hermetic_git, {"m.py": PY_OLD},
                                {"m.py": PY_OLD.replace("    return a", "    check(a)\n    return a")})
    t, _ = stage1.targets(PAIR, hunks, idx, patched)
    assert [x["name"] for x in t] == ["f"]


def test_new_function_inserted_between_functions_is_not_a_target(tmp_path, hermetic_git):
    old = PY_OLD + "def h(c):\n    return c\n"
    idx, hunks, patched = _real(tmp_path, hermetic_git, {"m.py": old},
                                {"m.py": PY_OLD + "def g(b):\n    return b\n" + "def h(c):\n    return c\n"})
    assert stage1.targets(PAIR, hunks, idx, patched) == ([], "no_target")


def test_unchanged_long_function_does_not_get_both_labels(tmp_path):
    """I4 (P4): whole-function comparison, not budget windows."""
    big = "def big(a):\n" + "".join(f"    x{i} = a + {i}\n" for i in range(200)) + "    return a\n"
    other = "\ndef small(b):\n    log(b)\n    return b\n"
    (tmp_path / "app.py").write_text(big + other)
    idx = ci.RepoIndex(str(tmp_path))
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "big", "start_line": 1, "end_line": 202, "vulnerable_lines": [150]}]}
    h = [{"file": "app.py", "old_file": "app.py", "old_start": 205, "old_end": 205, "new_start": 205, "new_end": 205}]
    ex, rec = stage1.cases_from(pair, h, idx, {"app.py": big + other.replace("log(b)", "log(c)")},
                                budget=B, n_negatives=0, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable"] and "patched_unchanged" in rec["reason"]


def test_overloads_each_get_their_own_patched_code(tmp_path, hermetic_git):
    """I5 (probe4): the first overload grows by 4 lines; the second must still pair with its own fix."""
    old = ("class P {\n  int parse(String a) {\n    return raw(a);\n  }\n\n"
           "  int parse(String a, int b) {\n    return raw(a) + b;\n  }\n}\n")
    new = ("class P {\n  int parse(String a) {\n    if (a == null) {\n      throw new E();\n    }\n"
           "    check(a);\n    return raw(a);\n  }\n\n"
           "  int parse(String a, int b) {\n    return safe(a) + b;\n  }\n}\n")
    idx, hunks, patched = _real(tmp_path, hermetic_git, {"P.java": old}, {"P.java": new})
    ex, rec = stage1.cases_from({**PAIR, "cwe": ["CWE-20"]}, hunks, idx, patched, budget=B, n_negatives=0, seed=0)
    pat = [e["case"]["snippets"][0]["code"] for e in ex if e["label"] == "patched"]
    assert len(pat) == 2 and any("check(a)" in c for c in pat) and any("safe(a) + b" in c for c in pat)
    assert not any("check(a)" in c and "safe(" in c for c in pat)


# --- final review I4: a "changed" function whose whole text the fix did not change is not a target ---
HELPER = "def helper(v):\n    w = v + 1\n    z = w * 2\n    return z\n"
VIEW_OLD = "def view(r):\n    q = 'SELECT ' + r\n    return db.execute(q)\n"
VIEW_FIX = "def view(r):\n    return db.execute('SELECT ?', [r])\n"
OTHER_FN = "def other(a):\n    log(a)\n    x = a\n    y = x\n    return y\n"


def test_moved_unchanged_helper_is_not_a_target(tmp_path, hermetic_git):
    """The fix rewrites view() and moves an unchanged helper() to the top: git's delete hunk spans the old
    helper, but its whole text is the same on both sides, so it gets no HIGH vulnerable lead."""
    old = VIEW_OLD + "\n\n" + OTHER_FN + "\n\n" + HELPER
    new = HELPER + "\n\n" + VIEW_FIX + "\n\n" + OTHER_FN
    repo = GitRepo(tmp_path / "r")
    a, b = repo.commit({"app.py": old}), repo.commit({"app.py": new})
    hunks = diffs.parse_u0(diffs.git_diff_u0(repo.path, a, b))
    assert any(h["old_start"] <= 13 <= h["old_end"] for h in hunks)        # the hunk does span the old helper
    repo.checkout(a)                                                       # the index reads the vulnerable tree
    idx = ci.RepoIndex(repo.path)
    ex, rec = stage1.cases_from(PAIR, hunks, idx, {"app.py": new}, budget=B, n_negatives=0, seed=0)
    assert [(e["label"], (e["lead"] or {}).get("function")) for e in ex] == [("vulnerable", "view"), ("patched", None)]
    assert rec["tiers"] == {"single": 1} and rec["n_targets"] == 1 and "unchanged_target" in rec["reason"]
    t, _ = stage1.targets(PAIR, hunks, idx, {"app.py": new})
    assert [(x["name"], x["tier"]) for x in t] == [("view", "single")]    # the tier is recomputed


def test_only_unchanged_targets_left_is_no_target(tmp_path):
    """Line-ending-only edits (CRLF -> LF) read the same under universal newlines: nothing remains, so no_target."""
    (tmp_path / "app.py").write_bytes(VULN.replace("\n", "\r\n").encode())
    idx = ci.RepoIndex(str(tmp_path))
    h = [{"file": "app.py", "old_file": "app.py", "old_start": s, "old_end": s, "new_start": s, "new_end": s}
         for s in (2, 6)]
    ex, rec = stage1.cases_from(PAIR, h, idx, {"app.py": VULN}, budget=B, n_negatives=0, seed=0)
    assert ex == [] and rec["reason"] == "no_target"
    assert stage1.targets(PAIR, h, idx, {"app.py": VULN}) == ([], "no_target")


def test_annotated_targets_are_kept_even_when_unchanged(tmp_path):
    """I4 applies to the single/multi tiers only: an annotation is the pair's own evidence."""
    pair = {**PAIR, "vuln_methods": [{"file": "app.py", "method": "third", "start_line": 11, "end_line": 15,
                                      "vulnerable_lines": [12]}]}
    ex, rec = stage1.cases_from(pair, HUNK, _idx(tmp_path), {"app.py": VULN}, budget=B, n_negatives=0, seed=0)
    assert [e["label"] for e in ex] == ["vulnerable"] and rec["tiers"] == {"annotated": 1}
