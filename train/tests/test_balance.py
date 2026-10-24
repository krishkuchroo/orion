from collections import Counter

import pytest

from train import balance


def fake_annotate(case, profile=None):
    """Deterministic stand-in for orion.lm.sinks.annotate: a sink when the target code says SINK."""
    out = dict(case)
    if case.get("nodes") or case.get("sink_category") is not None:
        return out
    t = case["snippets"][0]
    if "SINK" in t["code"]:
        out["sink_category"] = "sql"
        out["nodes"] = [{"role": "sink", "file": t["file"], "line": t["start"], "function": t["function"],
                         "code": "SINK"}]
    return out


def _case(fn, code="x"):
    return {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
            "snippets": [{"role": "target", "file": "a.py", "function": fn, "start": 1, "end": 2, "code": code}]}


def pair_rows(pid, *, tier="single", targets=((True,),), negs=("SINK", "x"), split="train", cwe="CWE-89"):
    """Stage 1 rows of one pair, in the order Stage 1 writes them: per target a vulnerable row and its patched
    twin right after it (when the target's flag is True), then the negatives. Every row's code is unique."""
    rows = []
    for i, (twin,) in enumerate(targets):
        rows.append({"pair_id": pid, "label": "vulnerable", "tier": tier, "cwe_class": "dataflow",
                     "case": _case(f"t{i}", f"{pid}:t{i}:v"), "split": split,
                     "lead": {"flow_id": "F0", "file": "a.py", "function": f"t{i}", "line": 1, "cwe": cwe,
                              "confidence": "HIGH"}})
        if twin:
            rows.append({"pair_id": pid, "label": "patched", "tier": tier, "cwe_class": "dataflow",
                         "case": _case(f"t{i}", f"{pid}:t{i}:p"), "split": split, "lead": None})
    for j, code in enumerate(negs):
        rows.append({"pair_id": pid, "label": "negative", "tier": "negative", "cwe_class": "dataflow",
                     "case": _case(f"n{j}", f"{pid}:n{j}:{code}"), "split": split, "lead": None})
    return rows


def pair_meta(pid, lang, repo, cwe="CWE-89"):
    return {"id": pid, "language": lang, "repo_canonical": repo, "cwe": [cwe]}


def build(specs):
    """specs: list of (pid, lang, repo, kwargs) -> (rows, pairs_by_id)."""
    rows, pairs = [], {}
    for pid, lang, repo, kw in specs:
        rows += pair_rows(pid, **kw)
        pairs[pid] = pair_meta(pid, lang, repo, kw.get("cwe", "CWE-89"))
    return rows, pairs


def sel(rows, pairs, **kw):
    kw.setdefault("annotate", fake_annotate)
    kw.setdefault("cwe_share", 1.0)            # tiny fixtures have few CWEs; the cap tests set these
    kw.setdefault("family_share", 1.0)
    return balance.select(rows, pairs, **kw)


# ───────────────────────────── unit construction ─────────────────────────────

def test_unit_is_one_vulnerable_its_twin_and_one_negative_preferring_twin_and_sink():
    rows = pair_rows("P", targets=((False,), (True,)), negs=("x", "SINK", "SINK"))
    out, rep = sel(rows, {"P": pair_meta("P", "py", "o/r")}, total=100)
    labels = Counter(r["label"] for r in out)
    assert labels == {"vulnerable": 1, "patched": 1, "negative": 1}
    v = next(r for r in out if r["label"] == "vulnerable")
    assert v["case"]["snippets"][0]["function"] == "t1"          # the target that HAS a twin
    n = next(r for r in out if r["label"] == "negative")
    assert n["case"]["snippets"][0]["function"] == "n1"          # first negative WITH a sink line
    assert rep["twin_pairs_kept"] == 1


def test_unit_falls_back_to_a_twinless_target_and_a_sinkless_negative():
    rows = pair_rows("P", targets=((False,),), negs=("x",))
    out, rep = sel(rows, {"P": pair_meta("P", "py", "o/r")}, total=100)
    assert [r["label"] for r in out] == ["vulnerable", "negative"]
    assert rep["twin_pairs_kept"] == 0
    rows = pair_rows("Q", targets=((True,),), negs=())
    out, _ = sel(rows, {"Q": pair_meta("Q", "py", "o/r")}, total=100)
    assert [r["label"] for r in out] == ["vulnerable", "patched"]


def test_twin_is_the_patched_row_right_after_its_vulnerable_row():
    """A patched row belongs to the vulnerable row directly before it in the same pair; output keeps that order."""
    rows = pair_rows("P", targets=((True,), (True,)), negs=("x",))
    out, rep = sel(rows, {"P": pair_meta("P", "py", "o/r")}, total=100)
    v = out.index(next(r for r in out if r["label"] == "vulnerable"))
    assert out[v + 1]["label"] == "patched" and out[v + 1] is rows[1]   # t0's twin, not t1's
    assert "adjacen" in rep["rules"]["twin"]


def test_train_split_only_and_rows_are_the_original_stage1_rows():
    rows, pairs = build([("A", "py", "o/a", {}), ("B", "py", "o/b", {"split": "dev"}),
                         ("C", "py", "o/c", {"split": "oldcve"})])
    out, _ = sel(rows, pairs, total=100)
    assert {r["pair_id"] for r in out} == {"A"}
    assert all(any(r is s for s in rows) for r in out)              # originals, not annotated copies
    assert len({id(r) for r in out}) == len(out)


def test_default_annotate_is_orion_sinks(monkeypatch):
    import orion.lm.sinks as sinks
    calls = []
    monkeypatch.setattr(sinks, "annotate", lambda case, profile=None: calls.append(1) or dict(case))
    rows, pairs = build([("A", "py", "o/a", {})])
    balance.select(rows, pairs, total=100)
    assert calls


# ───────────────────────────── language fill ─────────────────────────────

def test_every_python_fix_then_js_and_java_alternate_by_row_count():
    specs = [(f"py{i}", "py", f"o/py{i}", {}) for i in range(5)]
    specs += [(f"js{i}", "js", f"o/js{i}", {}) for i in range(40)]
    specs += [(f"jv{i}", "java", f"o/jv{i}", {"negs": ()}) for i in range(40)]   # java units are 2 rows
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=60, cwe_share=1.0, small_family=0)      # no small family jumps the queue
    langs = Counter(pairs[r["pair_id"]]["language"] for r in out)
    assert langs["py"] == 15                                    # all 5 python fixes, 3 rows each
    assert abs(langs["js"] - langs["java"]) <= 3                # alternated by ROW count
    assert len(out) == 60
    assert rep["counts"]["language"] == dict(langs)


def test_total_is_never_exceeded_and_gaps_are_filled_with_smaller_units():
    specs = [(f"js{i}", "js", f"o/js{i}", {}) for i in range(10)]
    specs += [(f"jv{i}", "java", f"o/jv{i}", {"targets": ((False,),), "negs": ()}) for i in range(10)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=13, cwe_share=1.0)
    assert len(out) == 13 and rep["rows"] == 13 and rep["shortfall"] == 0


# ───────────────────────────── caps ─────────────────────────────

def test_repo_cap_keeps_at_most_n_fixes_per_repo_preferring_annotated():
    specs = [(f"s{i}", "js", "Big/Repo", {"tier": "single"}) for i in range(6)]
    specs += [(f"a{i}", "js", "big/repo", {"tier": "annotated"}) for i in range(2)]   # same repo, other case
    specs += [("o1", "java", "o/x", {})]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=1000, repo_cap=3, cwe_share=1.0)
    fixes = {r["pair_id"] for r in out if r["label"] == "vulnerable" and pairs[r["pair_id"]]["repo_canonical"].lower() == "big/repo"}
    assert len(fixes) == 3 and {"a0", "a1"} <= fixes
    assert rep["dropped"]["repo_cap"] == 5
    assert rep["biggest_repo"] == {"repo": "big/repo", "fixes": 3}
    assert rep["repos_used"] == 2


def test_cwe_cap_holds_on_the_final_vulnerable_count_preferring_annotated():
    specs = [(f"x{i}", "js", f"o/x{i}", {"cwe": "CWE-79", "tier": "single"}) for i in range(10)]
    specs += [(f"a{i}", "js", f"o/a{i}", {"cwe": "CWE-79", "tier": "annotated"}) for i in range(2)]
    specs += [(f"o{i}", "java", f"o/o{i}", {"cwe": f"CWE-{100 + i}"}) for i in range(10)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=1000, cwe_share=0.2)
    vuln = [r for r in out if r["label"] == "vulnerable"]
    c = Counter(r["lead"]["cwe"] for r in vuln)
    assert c["CWE-79"] <= 0.2 * len(vuln) and c["CWE-79"] >= 1
    kept79 = {r["pair_id"] for r in vuln if r["lead"]["cwe"] == "CWE-79"}
    assert kept79 == {"a0", "a1"}             # 12 fixes, floor(0.2 * 12) = 2, and the annotated ones win
    assert rep["dropped"]["cwe_cap"] == 12 - c["CWE-79"]
    assert rep["counts"]["cwe_top15"][0] == ["CWE-79", c["CWE-79"]]


def test_an_unmeetable_cwe_cap_shrinks_the_output_instead_of_being_broken():
    """5 CWEs at 12% each can cover at most 60% of the vulnerable rows, so no non-empty set satisfies the cap."""
    specs = [(f"p{i}", "js", f"o/r{i}", {"cwe": f"CWE-{i % 5}"}) for i in range(40)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=100, cwe_share=0.12)
    assert out == [] and rep["shortfall"] == 100
    specs += [(f"q{i}", "js", f"o/q{i}", {"cwe": f"CWE-{100 + i}"}) for i in range(60)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=10_000, cwe_share=0.12)
    vuln = Counter(r["lead"]["cwe"] for r in out if r["label"] == "vulnerable")
    assert out and max(vuln.values()) <= 0.12 * sum(vuln.values())


def test_fewer_rows_than_total_are_returned_honestly_instead_of_breaking_a_cap():
    specs = [(f"r{i}", "js", "one/repo", {}) for i in range(10)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=100, repo_cap=2, cwe_share=1.0)
    assert len(out) == 6 and rep["rows"] == 6 and rep["requested"] == 100 and rep["shortfall"] == 94
    assert rep["dropped"]["repo_cap"] == 8


# ───────────────────────────── order ─────────────────────────────

def _assert_no_twin_split(rows, out, g):
    pos = {id(r): i for i, r in enumerate(out)}
    checked = 0
    for i, r in enumerate(rows):
        if r["label"] == "patched" and id(r) in pos:
            v = rows[i - 1]
            assert v["label"] == "vulnerable" and id(v) in pos
            assert pos[id(r)] == pos[id(v)] + 1
            assert pos[id(v)] // g == pos[id(r)] // g, (pos[id(v)], pos[id(r)])
            checked += 1
    return checked


@pytest.mark.parametrize("seed", range(8))
def test_a_vulnerable_row_and_its_twin_never_straddle_a_step_boundary(seed):
    specs = []
    for i in range(60):
        kw = {"targets": ((i % 4 != 0,),), "negs": ("SINK",) if i % 3 else ()}
        specs.append((f"p{i}", ("py", "js", "java")[i % 3], f"o/r{i}", kw))
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=10_000, seed=seed, cwe_share=1.0, grad_accum=4)
    assert _assert_no_twin_split(rows, out, 4) == rep["twin_pairs_kept"] > 0
    assert len(out) == rep["rows"]


def test_layout_fills_a_step_end_with_another_units_single_row():
    """Twin-only units: a pair that would start on a step's last slot gets a single row from a later unit."""
    specs = [(f"t{i}", "js", f"o/t{i}", {"negs": ()}) for i in range(6)]
    specs += [("n", "js", "o/n", {"negs": ("x",)}), ("s", "js", "o/s", {"targets": ((False,),), "negs": ()})]
    rows, pairs = build(specs)
    for seed in range(20):
        out, rep = sel(rows, pairs, total=1000, seed=seed, cwe_share=1.0, grad_accum=4)
        assert _assert_no_twin_split(rows, out, 4) == rep["twin_pairs_kept"] == 7
        assert rep["rows"] == len(out) == 16 and rep["twins_dropped_for_layout"] == 0


def test_layout_drops_a_twin_rather_than_split_it_when_no_single_row_is_left():
    specs = [(f"t{i}", "js", f"o/t{i}", {"negs": ()}) for i in range(3)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=1000, cwe_share=1.0, grad_accum=3)
    assert _assert_no_twin_split(rows, out, 3) == rep["twin_pairs_kept"] == 2
    assert rep["twins_dropped_for_layout"] == 1 and rep["rows"] == len(out) == 5
    assert rep["counts"]["label"] == {"vulnerable": 3, "patched": 2}


def test_deterministic_for_a_seed():
    specs = [(f"p{i}", ("py", "js", "java")[i % 3], f"o/r{i % 7}", {"cwe": f"CWE-{i % 5}"}) for i in range(40)]
    rows, pairs = build(specs)
    a, ra = sel(rows, pairs, total=60, seed=1)
    b, rb = sel(rows, pairs, total=60, seed=1)
    c, _ = sel(rows, pairs, total=60, seed=2)
    assert [id(r) for r in a] == [id(r) for r in b] and ra == rb
    assert [id(r) for r in a] != [id(r) for r in c]


# ───────────────────────────── report ─────────────────────────────

def test_report_counts_are_computed_from_the_output():
    specs = [("A", "py", "o/a", {"tier": "annotated", "negs": ("SINK",)}),
             ("B", "js", "o/b", {"negs": ("x",)}),
             ("C", "java", "o/c", {"targets": ((False,),), "negs": ()})]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=100, cwe_share=1.0)
    assert rep["rows"] == len(out) == 7
    assert rep["counts"]["label"] == {"vulnerable": 3, "patched": 2, "negative": 2}
    assert rep["counts"]["tier"] == {"annotated": 2, "single": 3, "negative": 2}
    assert rep["fixes"] == 3 and rep["twin_pairs_kept"] == 2
    assert rep["sink_share"]["negative"] == 0.5 and rep["sink_share"]["vulnerable"] == 0.0
    assert rep["params"] == {"total": 100, "seed": 0, "repo_cap": 15, "cwe_share": 1.0, "grad_accum": 16,
                             "family_share": 1.0, "small_family": 150, "fits": False}
    assert set(rep["rules"]) >= {"twin", "unit", "language", "caps", "order", "conflicts", "families"}
    assert rep["rows_in_partial_last_step"] == 7 and rep["twins_dropped_for_layout"] == 0


# ───────────────────────────── rule 1: label conflicts and duplicates ─────────────────────────────

def _row(pid, label, code, split="train", tier="single"):
    r = {"pair_id": pid, "label": label, "tier": tier if label != "negative" else "negative", "cwe_class": "dataflow",
         "case": _case("f", code), "split": split, "lead": None}
    if label == "vulnerable":
        r["lead"] = {"flow_id": "F0", "file": "a.py", "function": "f", "line": 1, "cwe": "CWE-89", "confidence": "HIGH"}
    return r


def test_drop_conflicts_drops_patched_and_negative_rows_whose_code_is_a_vulnerable_rows_code():
    v = _row("A", "vulnerable", "  same()\n")
    p = _row("B", "patched", "same()")              # an incomplete fix's patched version = the next CVE's vulnerable
    n = _row("C", "negative", "\tsame()  ")
    ok = _row("C", "negative", "other()")
    kept, rep = balance.drop_conflicts([v, p, n, ok])
    assert kept == [v, ok]
    assert rep["conflict_rows_dropped"] == {"negative": 1, "patched": 1}
    assert rep["conflict_groups"] == 1 and rep["conflict_group_rows"] == 3
    assert rep["rows_in"] == 4 and rep["rows_kept"] == 2


def test_drop_conflicts_keeps_the_first_row_per_code_and_label_and_compares_within_a_split():
    a, b = _row("A", "vulnerable", "f()"), _row("B", "vulnerable", " f() ")
    c, d = _row("A", "negative", "g()"), _row("B", "negative", "g()")
    e = _row("B", "patched", "g()")                 # same code as a negative but no vulnerable row has it: kept
    dev = _row("D", "patched", "f()", split="dev")  # another split: not a conflict
    kept, rep = balance.drop_conflicts([a, b, c, d, e, dev])
    assert kept == [a, c, e, dev]
    assert rep["duplicate_rows_dropped"] == {"negative": 1, "vulnerable": 1}
    assert rep["conflict_rows_dropped"] == {}


def test_select_applies_rule_1_before_building_units():
    """A conflicting twin is dropped, so its vulnerable row falls back to the pair's other target with a twin;
    a duplicate vulnerable row is gone, so its orphaned twin is never used."""
    rows = pair_rows("P", targets=((True,), (True,)), negs=("x",))
    rows[1]["case"] = _case("t0", "Q:t0:v")                        # P's first twin == Q's vulnerable code
    rows += pair_rows("Q", targets=((True,),), negs=())
    rows += pair_rows("R", targets=((True,),), negs=())
    rows[-2]["case"] = _case("t0", "Q:t0:v")                       # R's vulnerable duplicates Q's: R loses it
    pairs = {k: pair_meta(k, "py", f"o/{k}") for k in "PQR"}
    out, rep = sel(rows, pairs, total=100)
    v = [r for r in out if r["label"] == "vulnerable"]
    assert {r["pair_id"] for r in v} == {"P", "Q"}
    assert next(r for r in v if r["pair_id"] == "P")["case"]["snippets"][0]["function"] == "t1"
    assert not any(r["pair_id"] == "R" for r in out)              # R's orphaned patched row is not used
    r1 = rep["rule1_train"]
    assert r1["conflict_rows_dropped"] == {"patched": 1} and r1["duplicate_rows_dropped"] == {"vulnerable": 1}
    assert rep["twins_after_drops"] == {"raw_twin_pairs": 4, "twin_dropped_vulnerable_kept": 1,
                                        "vulnerable_dropped_twin_orphaned": 1, "both_dropped": 0, "intact": 2}


# ───────────────────────────── rule 2: CWE families ─────────────────────────────

def test_family_map_is_keyed_by_cwe_id_and_unknown_is_other():
    assert balance.FAMILIES[-1] == "other" and len(balance.FAMILIES) == 15
    assert set(balance.FAMILY_OF.values()) <= set(balance.FAMILIES)
    for cwe, fam in (("CWE-89", "injection"), ("CWE-78", "injection"), ("CWE-22", "path"), ("CWE-79", "XSS"),
                     ("CWE-918", "SSRF"), ("CWE-502", "deserialization"), ("CWE-611", "XXE"),
                     ("CWE-1321", "prototype pollution"), ("CWE-862", "access control"), ("CWE-287", "auth/session"),
                     ("CWE-352", "auth/session"), ("CWE-601", "open redirect"), ("CWE-327", "crypto"),
                     ("CWE-200", "info leak"), ("CWE-1333", "DoS"), ("CWE-20", "CWE-20"), ("CWE-99999", "other"),
                     (None, "other"), ("NVD-CWE-Other", "other")):
        assert balance.family(cwe) == fam, cwe


def _fam_specs():
    """Injection is big (java + js); open redirect is a small js family that would lose to python-first."""
    specs = [(f"inj{i}", ("java", "js")[i % 2], f"o/inj{i}", {"cwe": f"CWE-{(77, 78, 89, 94)[i % 4]}"}) for i in range(40)]
    specs += [(f"red{i}", "js", f"o/red{i}", {"cwe": "CWE-601"}) for i in range(3)]
    specs += [(f"py{i}", "py", f"o/py{i}", {"cwe": "CWE-22"}) for i in range(10)]
    return specs


def test_small_families_are_taken_whole_before_anything_else():
    rows, pairs = build(_fam_specs())
    out, rep = sel(rows, pairs, total=15, small_family=5)
    assert {r["pair_id"] for r in out if r["pair_id"].startswith("red")} == {"red0", "red1", "red2"}
    fam = rep["families"]["open redirect"]
    assert fam["small"] is True and fam["pool_vulnerable_rows"] == 3 and fam["vulnerable_rows"] == 3
    assert rep["families"]["injection"]["small"] is False


def test_small_family_fixes_still_obey_the_repo_cap_and_it_is_reported():
    specs = _fam_specs()
    specs = [(pid, lang, "one/repo" if pid.startswith("red") else repo, kw) for pid, lang, repo, kw in specs]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=1000, small_family=5, repo_cap=1)
    assert sum(r["pair_id"].startswith("red") for r in out if r["label"] == "vulnerable") == 1
    assert rep["small_family_fixes"]["dropped"] == {"repo_cap": 2, "cwe_cap": 0, "family_cap": 0}


def test_family_cap_holds_on_the_final_vulnerable_count_and_drops_are_reported():
    rows, pairs = build(_fam_specs())
    out, rep = sel(rows, pairs, total=10_000, family_share=0.4, small_family=5)
    vuln = [r for r in out if r["label"] == "vulnerable"]
    fams = Counter(balance.family(r["lead"]["cwe"]) for r in vuln)
    assert fams["injection"] <= 0.4 * len(vuln) and fams["injection"] > 0
    assert fams["path"] <= 0.4 * len(vuln)                        # path (10 py fixes) is capped too
    assert rep["dropped"]["family_cap"] == (40 - fams["injection"]) + (10 - fams["path"])
    assert rep["dropped_rows"]["family_cap"] == 3 * rep["dropped"]["family_cap"]
    tab = rep["families"]["injection"]
    assert tab["vulnerable_rows"] == fams["injection"] and tab["rows"] == 3 * fams["injection"]
    assert tab["python_rows"] == 0 and tab["annotated_share"] == 0.0
    assert rep["families"]["path"]["python_rows"] == 3 * fams["path"]


def test_family_rules_keep_the_twin_step_property_and_determinism():
    rows, pairs = build(_fam_specs() + [(f"x{i}", "py", f"o/x{i}", {"cwe": "CWE-611", "negs": ()}) for i in range(9)])
    a, ra = sel(rows, pairs, total=10_000, family_share=0.3, small_family=12, grad_accum=4, seed=5)
    b, rb = sel(rows, pairs, total=10_000, family_share=0.3, small_family=12, grad_accum=4, seed=5)
    assert [id(r) for r in a] == [id(r) for r in b] and ra == rb
    assert _assert_no_twin_split(rows, a, 4) == ra["twin_pairs_kept"] > 0


def test_report_lists_the_cwes_mapped_to_other():
    rows, pairs = build([("A", "js", "o/a", {"cwe": "CWE-15"}), ("B", "js", "o/b", {"cwe": "CWE-15"}),
                         ("C", "js", "o/c", {"cwe": "CWE-89"})])
    _, rep = sel(rows, pairs, total=100)
    assert rep["other_cwes"] == [["CWE-15", 2]]


# ───────────────────────────── over-length rows (fits) ─────────────────────────────

def test_fits_removes_rows_before_units_and_a_failing_vulnerable_row_loses_its_twin():
    rows = pair_rows("P", targets=((True,), (True,)), negs=("SINK", "x"))
    rows += pair_rows("Q", targets=((True,),), negs=())
    too_long = {"P:t1:v", "P:n0:SINK", "Q:t0:p"}
    fits = lambda r: r["case"]["snippets"][0]["code"] not in too_long
    pairs = {k: pair_meta(k, "py", f"o/{k}") for k in "PQ"}
    out, rep = sel(rows, pairs, total=100, fits=fits)
    assert not any(r["case"]["snippets"][0]["code"] in too_long for r in out)
    p = [r["case"]["snippets"][0]["code"] for r in out if r["pair_id"] == "P"]
    assert sorted(p) == ["P:n1:x", "P:t0:p", "P:t0:v"]          # t1 is out, so t0 + its twin; sinkless negative
    assert [r["label"] for r in out if r["pair_id"] == "Q"] == ["vulnerable"]
    assert rep["dropped_over_length"] == {"negative": 1, "patched": 1, "vulnerable": 1}
    assert rep["twins_after_drops"]["vulnerable_dropped_twin_orphaned"] == 1
    assert rep["twins_after_drops"]["twin_dropped_vulnerable_kept"] == 1
    assert rep["params"]["fits"] is True
    import json
    json.dumps(rep)                                              # the callable never lands in the report


def test_fits_runs_after_rule_1():
    rows = pair_rows("P", targets=((True,),), negs=())
    rows += pair_rows("Q", targets=((True,),), negs=())
    rows[-1]["case"] = _case("t0", "P:t0:v")                     # conflicts with P's vulnerable code
    seen = []
    out, rep = sel(rows, {k: pair_meta(k, "py", f"o/{k}") for k in "PQ"}, total=100,
                   fits=lambda r: seen.append(r["case"]["snippets"][0]["code"]) or True)
    assert "P:t0:v" in seen and seen.count("P:t0:v") == 1          # the conflicting patched row was never asked
    assert rep["dropped_over_length"] == {}


def test_other_family_is_exempt_from_the_family_cap_but_its_cwes_keep_the_cwe_cap():
    assert balance.FAMILY_CAP_EXEMPT == {"other"}
    specs = [(f"o{i}", "js", f"o/o{i}", {"cwe": f"CWE-{(15, 16, 19, 116, 125)[i % 5]}"}) for i in range(30)]
    specs += [(f"k{i}", "java", f"o/k{i}", {"cwe": f"CWE-{(89, 22, 79, 918, 502, 611, 601, 327, 200, 400)[i % 10]}"})
              for i in range(10)]
    rows, pairs = build(specs)
    out, rep = sel(rows, pairs, total=10_000, family_share=0.12, cwe_share=0.12, small_family=0)
    vuln = [r for r in out if r["label"] == "vulnerable"]
    fams = Counter(balance.family(r["lead"]["cwe"]) for r in vuln)
    cwes = Counter(r["lead"]["cwe"] for r in vuln)
    assert fams["other"] > 0.12 * len(vuln)                       # "other" is over 12%: exempt
    assert max(cwes.values()) <= 0.12 * len(vuln)                 # but no single CWE is
    assert all(n <= 0.12 * len(vuln) for f, n in fams.items() if f != "other")
    assert rep["dropped"]["family_cap"] == 0 and "other" in rep["rules"]["caps"]
