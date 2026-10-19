import json
import os

import pytest

from orion.lm import cases
from train import stage2

PAIR = {"id": "P", "language": "js", "repo": "o/r", "cwe": ["CWE-78"], "cwe_class": "dataflow"}
VULN_A = "function run(x){\n  exec(x)\n}\n"
PATCHED_A = "function run(x){\n  exec(clean(x))\n}\n"
B_JS = "function other(y){\n  eval(y)\n}\n"
HUNK = {"file": "a.js", "old_file": "a.js", "old_start": 2, "old_end": 2, "new_start": 2, "new_end": 2}


def _call(uid, f, line, name, fn):
    return {"uid": uid, "f": f, "l": line, "name": name, "file": f, "line": line, "function": fn,
            "code": f"{name}(...)"}


def _flow(uid, path, rank, cat="code_exec"):
    return {"uid": uid, "source_uid": path[0], "sink_uid": path[-1], "sink_category": cat,
            "path_uids": json.dumps(path), "rank": rank}


GOLD = {"uid": "fl0", "source_uid": "vs0", "sink_uid": "vk0", "sink_category": "code_exec", "rank": 0}


class StubDB:
    """Canned graph per scan. Accepts **kw and answers EXPLAIN with query_type 'r' (commit 515225b)."""

    def __init__(self, scans):
        self.scans, self.queries, self.cleared = scans, [], []

    def run_cypher(self, scan_id, query, limit=50, **kw):
        self.queries.append((scan_id, query))
        if query.lstrip().upper().startswith("EXPLAIN"):
            return {"rows": [], "row_count": 0, "query_type": "r"}
        s = self.scans.get(scan_id, {})
        if "CandidateFlow" in query:
            rows = s.get("flows", [])
        elif "CpgMethod" in query:
            rows = s.get("methods", [])
        elif "c.uid IN" in query:
            rows = [{k: c[k] for k in ("uid", "file", "function", "line", "code")}
                    for c in s.get("calls", []) if f"'{c['uid']}'" in query]
        elif "AS code" in query:       # the template queries of the trace tests
            rows = s.get("other", [])
        elif "CpgCall" in query:
            rows = [{k: c[k] for k in ("uid", "f", "l", "name")} for c in s.get("calls", [])]
        else:
            rows = s.get("other", [])
        return {"rows": rows, "row_count": len(rows), "query_type": "r"}

    def clear_scan(self, scan_id):
        self.cleared.append(scan_id)


def graph(patched_flows=True):
    return StubDB({
        "P:vulnerable": {
            "calls": [_call("vs0", "a.js", 1, "src", "run"), _call("vk0", "a.js", 2, "exec", "run"),
                      _call("bs", "b.js", 1, "src", "other"), _call("bk", "b.js", 2, "eval", "other")],
            "methods": [{"fn": "run", "f": "a.js", "l": 1}, {"fn": "other", "f": "b.js", "l": 1}],
            "flows": [_flow("fl0", ["vs0", "vk0"], 0), _flow("fl1", ["bs", "bk"], 1)]},
        "P:patched": {
            "calls": [_call("ps0", "a.js", 1, "src", "run"), _call("pk0", "a.js", 2, "exec", "run")],
            "methods": [{"fn": "run", "f": "a.js", "l": 1}],
            "flows": [_flow("pf0", ["ps0", "pk0"], 0)] if patched_flows else []}})


@pytest.fixture
def trees(tmp_path):
    vt, pt = tmp_path / "vt", tmp_path / "pt"
    for t, a in ((vt, VULN_A), (pt, PATCHED_A)):
        t.mkdir()
        (t / "a.js").write_text(a)
        (t / "b.js").write_text(B_JS)
    return str(vt), str(pt)


def yrec(**kw):
    return {"id": "P", "gold_flow": GOLD, "vulnerable_scan_id": "P:vulnerable", "patched_scan_id": "P:patched",
            "flows_gone_on_patched": [], "flows_unresolved": [], **kw}


def run_cases(db, trees, rec=None, **kw):
    kw = {"budget": cases.CaseBudget(), "n_negatives": 1, "seed": 0, "hunks": [HUNK], **kw}
    return stage2.cases_from_graph(db, rec or yrec(), PAIR, *trees, **kw)


# ───────────────────────────── select ─────────────────────────────

def test_select_is_dataflow_only_size_capped_and_language_balanced():
    pairs = [{"id": f"{l}{i}", "language": l, "cwe_class": "dataflow", "cwe": ["CWE-78"], "repo": f"o/{l}{i}"}
             for l in ("js", "py", "java") for i in range(10)] + \
            [{"id": "x", "language": "js", "cwe_class": "other", "cwe": ["CWE-78"], "repo": "o/x"}]
    sizes = {p["repo"]: (999_999 if p["id"] == "js0" else 10) for p in pairs}
    splits = {p["id"]: "train" for p in pairs}
    sel = stage2.select(pairs, splits, sizes, n=6, max_repo_kb=1000, seed=0)
    assert len(sel) == 6 and {p["language"] for p in sel} == {"js", "py", "java"}
    assert all(p["cwe_class"] == "dataflow" and p["id"] != "js0" for p in sel)
    assert [p["language"] for p in sel].count("js") == 2
    assert stage2.select(pairs, splits, sizes, n=6, max_repo_kb=1000, seed=0) == sel      # seeded
    assert stage2.select(pairs, splits, sizes, n=6, max_repo_kb=1000, seed=1) != sel


def test_select_excludes_oldcve_unknown_size_and_missing_cwe():
    base = {"language": "py", "cwe_class": "dataflow", "cwe": ["CWE-79"]}
    pairs = [{**base, "id": "a", "repo": "o/a"}, {**base, "id": "b", "repo": "o/b"}, {**base, "id": "c", "repo": "o/c"},
             {**base, "id": "d", "repo": "o/d", "cwe": []}, {**base, "id": "e", "repo": "o/e"}]
    splits = {"a": "train", "b": "oldcve", "c": "dev", "d": "train", "e": "train"}
    sizes = {"o/a": 1, "o/b": 1, "o/c": 1, "o/d": 1, "o/e": None}
    sel = stage2.select(pairs, splits, sizes, n=10, max_repo_kb=100, seed=0)
    assert sorted(p["id"] for p in sel) == ["a", "c"]
    assert {p["id"]: p["split"] for p in sel} == {"a": "train", "c": "dev"}


# ───────────────────────────── cases_from_graph ─────────────────────────────

def test_cases_from_graph_vuln_patched_and_negative(trees):
    ex = run_cases(graph(), trees)
    assert [e["label"] for e in ex] == ["vulnerable", "patched", "negative"] and all(e["stage"] == 2 for e in ex)
    assert all(e["pair_id"] == "P" and e["cwe_class"] == "dataflow" for e in ex)
    v, p, n = ex
    assert v["lead"] == {"flow_id": v["case"]["flow_id"], "file": "a.js", "function": "run", "line": 2,
                         "cwe": "CWE-78", "confidence": "HIGH"}
    assert p["lead"] is None and n["lead"] is None
    assert "exec(x)" in v["case"]["snippets"][0]["code"] and "clean(x)" in p["case"]["snippets"][0]["code"]
    assert v["case"]["sink_uid"] == "vk0" and p["case"]["sink_uid"] == "pk0" and n["case"]["sink_uid"] == "bk"
    assert n["tier"] == "negative"


@pytest.mark.parametrize("rec", [yrec(flows_gone_on_patched=[GOLD]), yrec(flows_unresolved=[GOLD]),
                                 yrec(patched_scan_id=None)])
def test_patched_example_omitted_when_flow_gone_unresolved_or_unbuilt(trees, rec):
    assert [e["label"] for e in run_cases(graph(), trees, rec)] == ["vulnerable", "negative"]


def test_patched_example_omitted_when_patched_scan_has_no_flows(trees):
    assert [e["label"] for e in run_cases(graph(patched_flows=False), trees)] == ["vulnerable", "negative"]


def test_negatives_never_touch_a_fix_site_and_are_seeded(trees):
    db = graph()
    # a different source and sink than the gold flow, but its path runs THROUGH the fix-site call vk0:
    # only the fix-site filter can exclude it
    db.scans["P:vulnerable"]["flows"].append(_flow("fl2", ["bs", "vk0", "bk"], 2))
    ex = run_cases(db, trees, n_negatives=5)
    assert [e["case"]["sink_uid"] for e in ex if e["label"] == "negative"] == ["bk"]
    assert [e["case"]["rank"] for e in ex if e["label"] == "negative"] == [1]      # fl1, not fl2
    assert [e["label"] for e in run_cases(db, trees, n_negatives=0)] == ["vulnerable", "patched"]


def test_negative_sampling_is_deterministic_per_seed(trees):
    db = graph()
    for k in range(2, 12):    # many eligible flows so that the seed matters
        db.scans["P:vulnerable"]["flows"].append(_flow(f"fx{k}", [f"s{k}", f"k{k}"], k))
        db.scans["P:vulnerable"]["calls"] += [_call(f"s{k}", "b.js", 1, "src", "other"),
                                              _call(f"k{k}", "b.js", 2, "eval", "other")]
    pick = lambda seed: [e["case"]["sink_uid"] for e in run_cases(db, trees, n_negatives=3, seed=seed)
                         if e["label"] == "negative"]
    assert pick(0) == pick(0) and len(pick(0)) == 3
    assert any(pick(s) != pick(0) for s in range(1, 8))


def test_no_gold_flow_gives_no_examples(trees):
    assert run_cases(graph(), trees, yrec(gold_flow=None)) == []


def test_graph_cases_reports_why_the_patched_example_is_missing(trees):
    _, why = stage2._graph_cases(graph(), yrec(flows_gone_on_patched=[GOLD]), PAIR, *trees,
                                 budget=cases.CaseBudget(), n_negatives=0, seed=0, hunks=[HUNK])
    assert why == ["flow_gone"]
    _, why = stage2._graph_cases(graph(), yrec(flows_unresolved=[GOLD]), PAIR, *trees,
                                 budget=cases.CaseBudget(), n_negatives=0, seed=0, hunks=[HUNK])
    assert why == ["flow_unresolved"]


# ───────────────────────────── trace_for ─────────────────────────────

CASE = {"flow_id": "F0", "rank": 0, "sink_category": "code_exec", "source_uid": "vs0", "sink_uid": "vk0",
        "nodes": [], "snippets": []}
TPL = "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.uid = <<sink_uid>> RETURN c.code AS code"


def test_trace_for_rejects_unscoped_template_and_returns_none_without_templates():
    assert stage2.trace_for(CASE, StubDB({}), "s:vulnerable", None) is None
    with pytest.raises(ValueError):
        stage2.trace_for(CASE, StubDB({}), "s:vulnerable", ["MATCH (n) RETURN n"])


def test_trace_for_fills_uids_runs_queries_and_ends_with_final():
    db = StubDB({"s:vulnerable": {"other": [{"code": "exec(x)"}]}})
    lead = {"flow_id": "F0", "file": "a.js", "function": "run", "line": 2, "cwe": "CWE-78", "confidence": "HIGH"}
    tr = stage2.trace_for(CASE, db, "s:vulnerable", [TPL], lead=lead, meta={"pair_id": "P", "split": "train"})
    assert tr["case"] is CASE or tr["case"] == CASE
    assert tr["actions"][0] == {"action": "run_cypher", "query": TPL.replace("<<sink_uid>>", "'vk0'")}
    assert tr["actions"][-1] == {"action": "final", "leads": [lead]}
    assert tr["results"] == [{"rows": [{"code": "exec(x)"}], "row_count": 1}]
    assert len(tr["results"]) == len(tr["actions"]) - 1
    assert tr["meta"] == {"pair_id": "P", "split": "train"}
    # a negative / patched case ends with no leads
    assert stage2.trace_for(CASE, db, "s:vulnerable", [TPL])["actions"][-1] == {"action": "final", "leads": []}


def test_trace_for_escapes_uids_into_the_literal_and_rejects_unknown_placeholders():
    case = {**CASE, "sink_uid": "a'b\\c"}
    tr = stage2.trace_for(case, StubDB({}), "s", [TPL])
    assert "'a\\'b\\\\c'" in tr["actions"][0]["query"]
    with pytest.raises(ValueError):
        stage2.trace_for(CASE, StubDB({}), "s", [TPL.replace("sink_uid", "nope")])
    with pytest.raises(ValueError):    # a template that needs a uid the case does not have
        stage2.trace_for({**CASE, "sink_uid": None}, StubDB({}), "s", [TPL])


def test_trace_for_returns_none_when_a_query_errors():
    class Bad(StubDB):
        def run_cypher(self, scan_id, query, limit=50, **kw):
            if not query.startswith("EXPLAIN"):
                return {"error": "boom"}
            return super().run_cypher(scan_id, query, limit, **kw)

    assert stage2.trace_for(CASE, Bad({}), "s", [TPL]) is None


def test_load_templates(tmp_path):
    assert stage2.load_templates(str(tmp_path / "queries.json")) is None
    p = tmp_path / "queries.json"
    p.write_text(json.dumps([TPL]))
    assert stage2.load_templates(str(p)) == [TPL]
    p.write_text(json.dumps(["MATCH (n) RETURN n"]))
    with pytest.raises(ValueError):
        stage2.load_templates(str(p))


# ───────────────────────────── build ─────────────────────────────

def fake_pair_build(calls, status="ok"):
    def build_pair(pair, mirror, work_root, **kw):
        calls.append(pair["id"])
        ok = status == "ok"
        side = lambda s: {"side": s, "status": "ok", "scan_id": f"{pair['id']}:{s}", "n_nodes": 10,
                          "neo4j_nodes": 9, "cpg_bin_bytes": 100, "peak_rss_python_mb": 1.5,
                          "timings": {"export_s": 0.1, "parse_s": 2.0, "side_total_s": 3.0}}
        return {"id": pair["id"], "status": status, "reason": None if ok else "joern died",
                "vulnerable_sha": "v" * 40, "patched_sha": "p" * 40, "hunks": [HUNK],
                "vulnerable_scan_id": f"{pair['id']}:vulnerable" if ok else None,
                "patched_scan_id": f"{pair['id']}:patched" if ok else None,
                "sides": {"vulnerable": side("vulnerable"), "patched": side("patched")} if ok else {},
                "total_s": 6.0}
    return build_pair


def fake_export(mirror, sha, dest, **kw):
    os.makedirs(dest, exist_ok=True)
    a = VULN_A if sha.startswith("v") else PATCHED_A
    for name, text in (("a.js", a), ("b.js", B_JS)):
        with open(os.path.join(dest, name), "w") as fh:
            fh.write(text)


def run_build(tmp_path, db, selected=None, status="ok", templates=None, calls=None, **kw):
    calls = [] if calls is None else calls
    args = dict(mirror_root=str(tmp_path / "m"), work_root=str(tmp_path / "w"), out_jsonl=str(tmp_path / "s2.jsonl"),
                ledger=str(tmp_path / "ledger.jsonl"), budget=cases.CaseBudget(), n_negatives=1, seed=0,
                templates=templates, on_event=lambda *_: None, db=db, ensure=lambda p, root, **k: "mirror",
                pair_builder=fake_pair_build(calls, status), export_tree=fake_export)
    args.update(kw)
    totals = stage2.build(selected if selected is not None else [{**PAIR, "split": "train"}], **args)
    return totals, calls, args


def read(path):
    return [json.loads(ln) for ln in open(path)] if os.path.exists(path) else []


def test_build_writes_examples_one_ledger_line_and_evicts_both_scans(tmp_path):
    db = graph()
    totals, calls, a = run_build(tmp_path, db)
    rows = read(a["out_jsonl"])
    assert [r["label"] for r in rows] == ["vulnerable", "patched", "negative"]
    assert all(r["pair_id"] == "P" and r["split"] == "train" and r["stage"] == 2 for r in rows)
    (led,) = read(a["ledger"])
    assert led["id"] == "P" and led["status"] == "ok" and led["n_examples"] == 3 and led["yield_reason"] is None
    assert led["sides"]["vulnerable"]["timings"]["parse_s"] == 2.0 and led["sides"]["patched"]["neo4j_nodes"] == 9
    assert sorted(db.cleared) == ["P:patched", "P:vulnerable"] and totals["examples"] == 3
    assert not os.path.exists(os.path.join(a["work_root"], "stage2_trees"))      # trees removed


def test_build_with_templates_adds_traces_carrying_pair_id_and_split(tmp_path):
    db = graph()
    db.scans["P:vulnerable"]["other"] = [{"code": "exec(x)"}]
    db.scans["P:patched"]["other"] = [{"code": "exec(clean(x))"}]
    _, _, a = run_build(tmp_path, db, templates=[TPL])
    traces = [r for r in read(a["out_jsonl"]) if "actions" in r]
    assert len(traces) == 3 and all(t["meta"]["pair_id"] == "P" and t["meta"]["split"] == "train" for t in traces)
    by = {t["meta"]["label"]: t for t in traces}
    assert by["vulnerable"]["actions"][0]["query"].endswith("RETURN c.code AS code") and "'vk0'" in by["vulnerable"]["actions"][0]["query"]
    assert "'pk0'" in by["patched"]["actions"][0]["query"]          # patched case is queried on the patched scan
    assert by["vulnerable"]["actions"][-1]["leads"] and by["negative"]["actions"][-1]["leads"] == []
    assert any(sid == "P:patched" and "'pk0'" in q for sid, q in db.queries)


def test_build_rejects_bad_templates_before_doing_any_work(tmp_path):
    calls = []
    with pytest.raises(ValueError):
        run_build(tmp_path, graph(), templates=["MATCH (n) RETURN n"], calls=calls)
    assert calls == []


def test_build_is_resumable_and_records_failed_builds_without_examples(tmp_path):
    db = graph()
    _, calls, a = run_build(tmp_path, db, status="build_failed")
    (led,) = read(a["ledger"])
    assert led["status"] == "build_failed" and led["reason"] == "joern died" and led["n_examples"] == 0
    assert read(a["out_jsonl"]) == []
    _, calls2, _ = run_build(tmp_path, db, calls=[])
    assert calls2 == [] and len(read(a["ledger"])) == 1


def test_build_records_no_gold_with_the_yield_reason(tmp_path):
    db = graph()
    db.scans["P:vulnerable"]["flows"] = []
    _, _, a = run_build(tmp_path, db)
    (led,) = read(a["ledger"])
    assert led["status"] == "no_gold" and led["yield_reason"] == "no_flow_through_site" and led["n_examples"] == 0
    assert sorted(db.cleared) == ["P:patched", "P:vulnerable"]


def test_build_evicts_and_records_error_when_a_step_raises(tmp_path):
    db = graph()

    def boom(*a, **k):
        raise RuntimeError("neo4j down")

    _, _, a = run_build(tmp_path, db, yielder=boom)
    (led,) = read(a["ledger"])
    assert led["status"] == "error" and "neo4j down" in led["reason"]
    assert sorted(db.cleared) == ["P:patched", "P:vulnerable"]


def test_build_reconciles_rows_of_a_pair_that_crashed_before_its_ledger_line(tmp_path):
    out = tmp_path / "s2.jsonl"
    out.write_text(json.dumps({"pair_id": "OLD", "label": "vulnerable"}) + "\n"
                   + json.dumps({"case": {}, "actions": [], "results": [], "meta": {"pair_id": "OLD"}}) + "\n"
                   + json.dumps({"pair_id": "DONE", "label": "negative"}) + "\n" + '{"pair_id": "torn')
    (tmp_path / "ledger.jsonl").write_text(json.dumps({"id": "DONE", "status": "ok"}) + "\n")
    run_build(tmp_path, graph(), selected=[])
    assert [r["pair_id"] for r in read(str(out))] == ["DONE"]


def test_a_case_with_a_trace_is_written_only_as_the_trace_and_export_has_no_conflicting_prompts(tmp_path):
    """The single-step row (target: final) and the trace's first step (target: run_cypher) of the same
    case have the same prompt and different targets; only the trace may be written for such a case."""
    from train import examples
    db = graph()
    db.scans["P:vulnerable"]["other"] = [{"code": "exec(x)"}]
    db.scans["P:patched"]["other"] = [{"code": "exec(clean(x))"}]
    _, _, a = run_build(tmp_path, db, selected=[{**PAIR, "split": "dev"}], templates=[TPL])
    rows = read(a["out_jsonl"])
    assert sum("actions" in r for r in rows) == 3 and not any("label" in r and "actions" not in r for r in rows)
    (led,) = read(a["ledger"])
    assert led["n_examples"] == 0 and led["n_traces"] == 3
    s1 = tmp_path / "s1.jsonl"
    s1.write_text("")
    out = tmp_path / "out"
    examples.export(str(s1), a["out_jsonl"], [], out_dir=str(out), schema_text="SCHEMA",
                    shares={"stage2": 1.0}, seed=0)
    sft = read(str(out / "dev.jsonl"))
    assert sft
    targets: dict[str, set[str]] = {}
    for r in sft:
        targets.setdefault(json.dumps(r["messages"], sort_keys=True), set()).add(r["target"])
    assert all(len(t) == 1 for t in targets.values())


def test_a_case_whose_trace_is_dropped_keeps_its_single_step_row(tmp_path):
    db = graph()      # no "other" rows for the template -> rows empty but no error; force an error instead
    orig = db.run_cypher

    def run(scan_id, query, limit=50, **kw):
        if not query.startswith("EXPLAIN") and "c.uid = " in query and scan_id == "P:patched":
            return {"error": "boom"}
        return orig(scan_id, query, limit=limit, **kw)

    db.run_cypher = run
    _, _, a = run_build(tmp_path, db, templates=[TPL])
    rows = read(a["out_jsonl"])
    assert [r["label"] for r in rows if "actions" not in r] == ["patched"]
    assert sum("actions" in r for r in rows) == 2
    (led,) = read(a["ledger"])
    assert led["n_examples"] == 1 and led["n_traces"] == 2 and led["traces_dropped"] == 1
