import json
import logging

import pytest

from orion.lm import format as fmt
from train import examples

CASE = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
        "snippets": [{"role": "target", "file": "a.py", "function": "f", "start": 1, "end": 2, "code": "x"}]}
LEAD = {"flow_id": "F0", "file": "a.py", "function": "f", "line": 1, "cwe": "CWE-89", "confidence": "HIGH"}


def test_to_sft_uses_runtime_formatter_and_canonical_target():
    """A training example is byte-identical to what the runtime would show at that step."""
    s = examples.to_sft({"pair_id": "P", "label": "vulnerable", "tier": "single", "case": CASE, "lead": LEAD}, schema_text="S")
    assert s["messages"] == [fmt.system_message("S"), fmt.task_message([CASE])]
    assert s["target"] == fmt.dumps_action({"action": "final", "leads": [LEAD]})
    assert s["meta"] == {"pair_id": "P", "label": "vulnerable", "tier": "single", "stage": 1, "language": None,
                         "repo": None, "cwe": None, "cwe_class": None, "split": None}
    p = examples.to_sft({"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None, "stage": 2}, schema_text="S")
    assert p["target"] == fmt.dumps_action({"action": "final", "leads": []})
    assert p["meta"]["stage"] == 2


def test_cut_one_example_per_action_with_tool_results():
    q = {"action": "run_cypher", "query": "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code"}
    fin = {"action": "final", "leads": []}
    t = {"case": CASE, "actions": [q, fin], "results": [{"rows": [], "row_count": 0}], "meta": {"pair_id": "P"}}
    ex = examples.cut(t, schema_text="S")
    assert len(ex) == 2 and ex[1]["messages"][-1] == fmt.tool_result_message(q, {"rows": [], "row_count": 0})
    assert ex[0]["messages"] == [fmt.system_message("S"), fmt.task_message([CASE])]
    assert ex[0]["target"] == fmt.dumps_action(q) and ex[1]["target"] == fmt.dumps_action(fin)
    assert ex[1]["messages"][-2] == {"role": "assistant", "content": fmt.dumps_action(q)}
    assert ex[1]["meta"]["pair_id"] == "P" and ex[1]["meta"]["stage"] == 2


def test_cut_rejects_mismatched_results():
    with pytest.raises(ValueError):
        examples.cut({"case": CASE, "actions": [{"action": "final", "leads": []}], "results": [{}], "meta": {}}, schema_text="S")


def test_mix_draws_group_shares(tmp_path):
    out = examples.mix({"stage1": [{"g": 1}] * 90, "stage2": [{"g": 2}] * 100}, {"stage1": 0.9, "stage2": 0.1}, total=100, seed=0)
    assert sum(1 for e in out if e["g"] == 2) == 10 and len(out) == 100


def test_mix_short_group_used_whole_and_logged(caplog):
    with caplog.at_level(logging.WARNING):
        out = examples.mix({"a": [{"g": "a"}] * 5, "b": [{"g": "b"}] * 100}, {"a": 0.5, "b": 0.5}, total=40, seed=1)
    assert sum(1 for e in out if e["g"] == "a") == 5 and sum(1 for e in out if e["g"] == "b") == 20
    assert "shortfall" in caplog.text


def test_mix_seeded_deterministic():
    g = {"a": [{"i": i} for i in range(50)], "b": [{"i": 100 + i} for i in range(50)]}
    s = {"a": 0.5, "b": 0.5}
    assert examples.mix(g, s, total=20, seed=3) == examples.mix(g, s, total=20, seed=3)
    assert examples.mix(g, s, total=20, seed=3) != examples.mix(g, s, total=20, seed=4)


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_export_never_writes_dev_or_oldcve_into_train(tmp_path):
    rows = [{"pair_id": f"{s}-{i}", "label": "vulnerable", "tier": "single", "case": CASE, "lead": LEAD, "split": s}
            for s in ("train", "dev", "oldcve") for i in range(3)]
    s1 = tmp_path / "s1.jsonl"
    _write(s1, rows)
    out = tmp_path / "out"
    counts = examples.export(str(s1), None, None, out_dir=str(out), schema_text="S", shares={"stage1": 1.0}, seed=0, allow_placeholder=True)
    tr = [json.loads(l) for l in (out / "train.jsonl").read_text().splitlines()]
    dv = [json.loads(l) for l in (out / "dev.jsonl").read_text().splitlines()]
    assert {r["meta"]["pair_id"] for r in tr} == {f"train-{i}" for i in range(3)}
    assert {r["meta"]["pair_id"] for r in dv} == {f"dev-{i}" for i in range(3)}
    assert "oldcve" not in (out / "train.jsonl").read_text() + (out / "dev.jsonl").read_text()
    assert counts["train"] == 3 and counts["dev"] == 3 and counts["oldcve_dropped"] == 3


def test_export_stage2_traces_cypher_rows_and_missing_split(tmp_path):
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{"pair_id": "a", "label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}])
    s2 = tmp_path / "s2.jsonl"
    trace = {"case": CASE, "actions": [{"action": "final", "leads": []}], "results": [], "meta": {"pair_id": "b", "split": "train"}}
    _write(s2, [trace])
    cy = [{"messages": [], "target": "{}", "meta": {"pair_id": "c", "split": "dev"}}]
    c = examples.export(str(s1), str(s2), cy, out_dir=str(tmp_path / "o"), schema_text="S",
                        shares={"stage1": 0.5, "stage2": 0.5, "cypher": 0.0}, seed=0, allow_placeholder=True)
    assert c["train"] == 2 and c["dev"] == 1
    _write(s2, [{**trace, "meta": {"pair_id": "b"}}])
    with pytest.raises(ValueError):
        examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "o2"), schema_text="S", shares={"stage1": 1}, seed=0, allow_placeholder=True)


def test_export_rejects_pair_with_conflicting_splits(tmp_path):
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{"pair_id": "P", "label": "vulnerable", "tier": "single", "case": CASE, "lead": LEAD, "split": "train"}])
    s2 = tmp_path / "s2.jsonl"
    _write(s2, [{"case": CASE, "actions": [{"action": "final", "leads": []}], "results": [],
                 "meta": {"pair_id": "P", "split": "dev"}}])
    with pytest.raises(ValueError, match="P"):
        examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "o"), schema_text="S",
                        shares={"stage1": 0.5, "stage2": 0.5}, seed=0, allow_placeholder=True)
    assert not (tmp_path / "o" / "train.jsonl").exists()


def test_export_default_is_the_runtime_compact_system_message(tmp_path):
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}])
    examples.export(str(s1), None, None, out_dir=str(tmp_path / "o"), shares={"stage1": 1.0}, seed=0, allow_placeholder=True)
    row = json.loads((tmp_path / "o" / "train.jsonl").read_text().splitlines()[0])
    assert row["messages"][0] == fmt.system_message()


def test_export_requires_pair_id_on_stage_rows_but_not_cypher(tmp_path):
    good = {"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{**good, "pair_id": ""}])
    with pytest.raises(ValueError, match="pair_id"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "a"), schema_text="S", shares={"stage1": 1.0}, seed=0, allow_placeholder=True)
    _write(s1, [{k: v for k, v in good.items() if k != "pair_id"}])
    with pytest.raises(ValueError, match="pair_id"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "b"), schema_text="S", shares={"stage1": 1.0}, seed=0, allow_placeholder=True)
    _write(s1, [good])
    s2 = tmp_path / "s2.jsonl"
    _write(s2, [{"case": CASE, "actions": [{"action": "final", "leads": []}], "results": [], "meta": {"split": "train"}}])
    with pytest.raises(ValueError, match="pair_id"):
        examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "c"), schema_text="S",
                        shares={"stage1": 0.5, "stage2": 0.5}, seed=0, allow_placeholder=True)
    assert not (tmp_path / "c" / "train.jsonl").exists()
    cy = [{"messages": [], "target": "{}", "meta": {"split": "train"}}]
    c = examples.export(str(s1), None, cy, out_dir=str(tmp_path / "d"), schema_text="S",
                        shares={"stage1": 0.5, "cypher": 0.5}, seed=0, allow_placeholder=True)
    assert c["train"] == 2


def test_export_total_defaults_to_all_train_rows_logs_and_reports_used(tmp_path, caplog):
    """Final review I6: 1000 Stage 1 + 50 Stage 2 rows at 0.8/0.2. The default total is every train row, so
    Stage 1 is no longer cut to 4x Stage 2; down-sampling and shortfalls are logged; `used` is returned."""
    row = {"label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}
    s1, s2 = tmp_path / "s1.jsonl", tmp_path / "s2.jsonl"
    _write(s1, [{**row, "pair_id": f"a{i}"} for i in range(1000)])
    _write(s2, [{**row, "pair_id": f"b{i}", "tier": "graph"} for i in range(50)])
    shares = {"stage1": 0.8, "stage2": 0.2}
    with caplog.at_level(logging.WARNING):
        c = examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "o"), schema_text="S", shares=shares, seed=0, allow_placeholder=True)
    assert c["used"] == {"stage1": 840, "stage2": 50} and c["train"] == 890      # total = 1050
    assert c["available"]["train"] == {"stage1": 1000, "stage2": 50}
    assert "'stage1' down-sampled" in caplog.text and "'stage2' shortfall" in caplog.text
    c = examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "p"), schema_text="S", shares=shares, seed=0,
                        total=250, allow_placeholder=True)
    assert c["used"] == {"stage1": 200, "stage2": 50} and c["train"] == 250


def test_export_refuses_a_placeholder_prompt_and_records_the_system_hash(tmp_path, monkeypatch):
    """Final review M9: no training on the placeholder system prompt (unless a dry run says so), and every
    export records which system message it was built with: in the counts and a `<out>.prompt.sha256` sidecar."""
    import hashlib
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}])
    monkeypatch.setattr(fmt, "system_prompt_text", lambda: "PLACEHOLDER — Krish writes it")
    with pytest.raises(ValueError, match="PLACEHOLDER"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "a"), schema_text="S", shares={"stage1": 1.0}, seed=0)
    assert not (tmp_path / "a").exists()
    c = examples.export(str(s1), None, None, out_dir=str(tmp_path / "b"), schema_text="S", shares={"stage1": 1.0},
                        seed=0, allow_placeholder=True)
    want = hashlib.sha256(fmt.system_message("S")["content"].encode("utf-8")).hexdigest()
    assert c["system_sha256"] == want
    for name in ("train.jsonl", "dev.jsonl"):
        assert (tmp_path / "b" / f"{name}.prompt.sha256").read_text() == want + "\n"
    monkeypatch.setattr(fmt, "system_prompt_text", lambda: "You are Orion-LM.")    # a real prompt: no override
    c = examples.export(str(s1), None, None, out_dir=str(tmp_path / "c"), schema_text="S", shares={"stage1": 1.0}, seed=0)
    assert c["system_sha256"] == hashlib.sha256(fmt.system_message("S")["content"].encode("utf-8")).hexdigest() != want


# ───────────────────────────── data v2: sink annotation, meta, balanced sampler ─────────────────────────────

PAIR = {"id": "P", "language": "py", "repo_canonical": "Org/Repo", "cwe": ["CWE-20", "CWE-89"]}


def fake_annotate(case, profile=None):
    out = dict(case)
    if case.get("nodes") or case.get("sink_category") is not None:
        return out
    t = case["snippets"][0]
    if "SINK" in t["code"]:
        out["sink_category"] = "sql"
        out["nodes"] = [{"role": "sink", "file": t["file"], "line": t["start"], "function": t["function"], "code": "SINK"}]
    return out


def test_to_sft_annotates_the_case_with_orion_sinks(monkeypatch):
    """Training rows carry the same sink node the runtime's code-only cases get (annotate is idempotent)."""
    from orion.lm import sinks
    monkeypatch.setattr(sinks, "annotate", fake_annotate)
    case = {**CASE, "snippets": [{**CASE["snippets"][0], "code": "SINK"}]}
    s = examples.to_sft({"pair_id": "P", "label": "negative", "tier": "negative", "case": case, "lead": None}, schema_text="S")
    want = fake_annotate(case)
    assert want["sink_category"] == "sql"
    assert s["messages"][1] == fmt.task_message([want])
    again = examples.to_sft({"pair_id": "P", "label": "negative", "tier": "negative", "case": want, "lead": None}, schema_text="S")
    assert again["messages"] == s["messages"]


def test_to_sft_uses_the_real_annotate_by_default():
    from orion.lm import sinks
    case = {**CASE, "snippets": [{**CASE["snippets"][0], "code": "cursor.execute(q)\nos.system(cmd)"}]}
    s = examples.to_sft({"pair_id": "P", "label": "negative", "tier": "negative", "case": case, "lead": None}, schema_text="S")
    assert s["messages"][1] == fmt.task_message([sinks.annotate(case)])


def test_to_sft_meta_joins_pairs_json():
    row = {"pair_id": "P", "label": "patched", "tier": "annotated", "cwe_class": "dataflow", "case": CASE,
           "lead": None, "split": "train"}
    m = examples.to_sft(row, schema_text="S", pair=PAIR)["meta"]
    assert m == {"pair_id": "P", "label": "patched", "tier": "annotated", "stage": 1, "language": "py",
                 "repo": "Org/Repo", "cwe": "CWE-89", "cwe_class": "dataflow", "split": "train"}


def _code_case(code):
    return {**CASE, "snippets": [{**CASE["snippets"][0], "code": code}]}


def _v2_rows():
    """Two train pairs (one twin each + a sink negative), one dev pair, one oldcve pair; every code unique."""
    rows, pairs = [], {}
    for pid, split, lang in (("A", "train", "py"), ("B", "train", "js"), ("D", "dev", "java"), ("O", "oldcve", "py")):
        lead = {**LEAD, "cwe": "CWE-89"}
        rows += [{"pair_id": pid, "label": "vulnerable", "tier": "annotated", "cwe_class": "dataflow", "case": _code_case(f"{pid}v"), "lead": lead, "split": split},
                 {"pair_id": pid, "label": "patched", "tier": "annotated", "cwe_class": "dataflow", "case": _code_case(f"{pid}p"), "lead": None, "split": split},
                 {"pair_id": pid, "label": "negative", "tier": "negative", "cwe_class": "dataflow", "case": _code_case(f"{pid}n"), "lead": None, "split": split},
                 {"pair_id": pid, "label": "negative", "tier": "negative", "cwe_class": "dataflow",
                  "case": _code_case(f"SINK {pid}"), "lead": None, "split": split}]
        pairs[pid] = {"id": pid, "language": lang, "repo_canonical": f"o/{pid}", "cwe": ["CWE-89"]}
    return rows, pairs


def _v2_files(tmp_path):
    rows, pairs = _v2_rows()
    s1, pj = tmp_path / "s1.jsonl", tmp_path / "pairs.json"
    _write(s1, rows)
    pj.write_text(json.dumps(list(pairs.values())))
    return s1, pj, rows, pairs


def test_export_balanced_writes_sampler_order_report_and_annotated_dev(tmp_path, monkeypatch):
    from orion.lm import sinks
    from train import balance
    monkeypatch.setattr(sinks, "annotate", fake_annotate)
    s1, pj, rows, pairs = _v2_files(tmp_path)
    out = tmp_path / "o"
    c = examples.export(str(s1), None, None, out_dir=str(out), schema_text="S", shares={"stage1": 1.0}, seed=0,
                        total=100, sampler="balanced", pairs_path=str(pj),
                        balance_kwargs={"cwe_share": 1.0, "family_share": 1.0}, allow_placeholder=True)
    want, rep = balance.select(rows, pairs, total=100, seed=0, cwe_share=1.0, family_share=1.0)
    tr = [json.loads(l) for l in (out / "train.jsonl").read_text().splitlines()]
    assert [examples.to_sft(r, schema_text="S", pair=pairs[r["pair_id"]]) for r in want] == tr   # sampler order kept
    assert len(tr) == 6 and {r["meta"]["split"] for r in tr} == {"train"}
    rep["dev"] = c["balance"]["dev"]
    assert json.loads((out / "train.balance.json").read_text()) == json.loads(json.dumps(rep))
    assert c["train"] == 6 and c["used"] == {"stage1": 6} and c["balance"]["rows"] == 6
    neg = [r for r in tr if r["meta"]["label"] == "negative"]
    assert all("sink_category=sql" in r["messages"][1]["content"] for r in neg)          # the sink negative won
    dv = [json.loads(l) for l in (out / "dev.jsonl").read_text().splitlines()]
    assert len(dv) == 4 and c["dev"] == 4                                                # ALL dev rows, unbalanced
    assert {r["meta"]["language"] for r in dv} == {"java"} and {r["meta"]["repo"] for r in dv} == {"o/D"}
    assert sum("sink_category=sql" in r["messages"][1]["content"] for r in dv) == 1      # annotated
    assert not (out / "dev.balance.json").exists()


def test_export_random_stays_the_default_and_gains_meta_with_pairs(tmp_path):
    s1, pj, rows, pairs = _v2_files(tmp_path)
    (tmp_path / "o").mkdir()
    (tmp_path / "o" / "train.balance.json").write_text("{}")          # stale report from an earlier balanced export
    c = examples.export(str(s1), None, None, out_dir=str(tmp_path / "o"), schema_text="S", shares={"stage1": 1.0},
                        seed=0, pairs_path=str(pj), allow_placeholder=True)
    assert c["train"] == 8 and "balance" not in c and not (tmp_path / "o" / "train.balance.json").exists()
    tr = [json.loads(l) for l in (tmp_path / "o" / "train.jsonl").read_text().splitlines()]
    assert {r["meta"]["language"] for r in tr} == {"py", "js"}


def test_export_balanced_needs_pairs_and_stage1_only(tmp_path):
    s1, pj, rows, pairs = _v2_files(tmp_path)
    with pytest.raises(ValueError, match="pairs_path"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "a"), schema_text="S", shares={"stage1": 1.0},
                        seed=0, sampler="balanced", allow_placeholder=True)
    cy = [{"messages": [], "target": "{}", "meta": {"split": "train"}}]
    with pytest.raises(ValueError, match="stage1"):
        examples.export(str(s1), None, cy, out_dir=str(tmp_path / "b"), schema_text="S",
                        shares={"stage1": 0.5, "cypher": 0.5}, seed=0, sampler="balanced", pairs_path=str(pj),
                        allow_placeholder=True)
    with pytest.raises(ValueError, match="sampler"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "c"), schema_text="S", shares={"stage1": 1.0},
                        seed=0, sampler="nope", allow_placeholder=True)
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


def _v2_dev_conflict_files(tmp_path):
    """Dev pair E's patched row has D's vulnerable code (rule 1), and E's negative duplicates D's negative."""
    rows, pairs = _v2_rows()
    rows += [{"pair_id": "E", "label": "vulnerable", "tier": "single", "cwe_class": "dataflow", "case": _code_case("Ev"),
              "lead": {**LEAD, "cwe": "CWE-79"}, "split": "dev"},
             {"pair_id": "E", "label": "patched", "tier": "single", "cwe_class": "dataflow", "case": _code_case(" Dv "),
              "lead": None, "split": "dev"},
             {"pair_id": "E", "label": "negative", "tier": "negative", "cwe_class": "dataflow", "case": _code_case("Dn"),
              "lead": None, "split": "dev"},
             {"pair_id": "E", "label": "negative", "tier": "negative", "cwe_class": "dataflow", "case": _code_case("LONG"),
              "lead": None, "split": "dev"}]
    pairs["E"] = {"id": "E", "language": "js", "repo_canonical": "o/E", "cwe": ["CWE-79"]}
    s1, pj = tmp_path / "s1.jsonl", tmp_path / "pairs.json"
    _write(s1, rows)
    pj.write_text(json.dumps(list(pairs.values())))
    return s1, pj


def test_export_balanced_applies_rule_1_and_fits_to_dev_and_reports_them(tmp_path):
    s1, pj = _v2_dev_conflict_files(tmp_path)
    fits = lambda r: r["case"]["snippets"][0]["code"] not in ("LONG", "SINK A")
    c = examples.export(str(s1), None, None, out_dir=str(tmp_path / "o"), schema_text="S", shares={"stage1": 1.0},
                        seed=0, total=100, sampler="balanced", pairs_path=str(pj),
                        balance_kwargs={"cwe_share": 1.0, "family_share": 1.0, "fits": fits}, allow_placeholder=True)
    dv = [json.loads(l) for l in (tmp_path / "o" / "dev.jsonl").read_text().splitlines()]
    assert c["dev"] == len(dv) == 5                           # 8 dev rows - 1 conflict - 1 duplicate - 1 too long
    dev = c["balance"]["dev"]
    assert dev["rule1"]["conflict_rows_dropped"] == {"patched": 1}
    assert dev["rule1"]["duplicate_rows_dropped"] == {"negative": 1}
    assert dev["dropped_over_length"] == {"negative": 1}
    assert c["balance"]["dropped_over_length"] == {"negative": 1}              # train: A's sink negative
    saved = json.loads((tmp_path / "o" / "train.balance.json").read_text())
    assert saved["dev"] == dev and saved["params"]["fits"] is True


def test_export_random_leaves_dev_conflicts_alone(tmp_path):
    s1, pj = _v2_dev_conflict_files(tmp_path)
    c = examples.export(str(s1), None, None, out_dir=str(tmp_path / "o"), schema_text="S", shares={"stage1": 1.0},
                        seed=0, pairs_path=str(pj), allow_placeholder=True)
    assert c["dev"] == 8
