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
    assert s["meta"] == {"pair_id": "P", "label": "vulnerable", "tier": "single", "stage": 1}
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
    counts = examples.export(str(s1), None, None, out_dir=str(out), schema_text="S", shares={"stage1": 1.0}, seed=0)
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
                        shares={"stage1": 0.5, "stage2": 0.5, "cypher": 0.0}, seed=0)
    assert c["train"] == 2 and c["dev"] == 1
    _write(s2, [{**trace, "meta": {"pair_id": "b"}}])
    with pytest.raises(ValueError):
        examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "o2"), schema_text="S", shares={"stage1": 1}, seed=0)


def test_export_rejects_pair_with_conflicting_splits(tmp_path):
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{"pair_id": "P", "label": "vulnerable", "tier": "single", "case": CASE, "lead": LEAD, "split": "train"}])
    s2 = tmp_path / "s2.jsonl"
    _write(s2, [{"case": CASE, "actions": [{"action": "final", "leads": []}], "results": [],
                 "meta": {"pair_id": "P", "split": "dev"}}])
    with pytest.raises(ValueError, match="P"):
        examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "o"), schema_text="S",
                        shares={"stage1": 0.5, "stage2": 0.5}, seed=0)
    assert not (tmp_path / "o" / "train.jsonl").exists()


def test_export_default_schema_is_runtime_pruned_schema(tmp_path):
    from orion.lm import slice as lm_slice
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}])
    examples.export(str(s1), None, None, out_dir=str(tmp_path / "o"), shares={"stage1": 1.0}, seed=0)
    row = json.loads((tmp_path / "o" / "train.jsonl").read_text().splitlines()[0])
    assert row["messages"][0] == fmt.system_message(lm_slice.pruned_schema())


def test_export_requires_pair_id_on_stage_rows_but_not_cypher(tmp_path):
    good = {"pair_id": "P", "label": "patched", "tier": "single", "case": CASE, "lead": None, "split": "train"}
    s1 = tmp_path / "s1.jsonl"
    _write(s1, [{**good, "pair_id": ""}])
    with pytest.raises(ValueError, match="pair_id"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "a"), schema_text="S", shares={"stage1": 1.0}, seed=0)
    _write(s1, [{k: v for k, v in good.items() if k != "pair_id"}])
    with pytest.raises(ValueError, match="pair_id"):
        examples.export(str(s1), None, None, out_dir=str(tmp_path / "b"), schema_text="S", shares={"stage1": 1.0}, seed=0)
    _write(s1, [good])
    s2 = tmp_path / "s2.jsonl"
    _write(s2, [{"case": CASE, "actions": [{"action": "final", "leads": []}], "results": [], "meta": {"split": "train"}}])
    with pytest.raises(ValueError, match="pair_id"):
        examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "c"), schema_text="S",
                        shares={"stage1": 0.5, "stage2": 0.5}, seed=0)
    assert not (tmp_path / "c" / "train.jsonl").exists()
    cy = [{"messages": [], "target": "{}", "meta": {"split": "train"}}]
    c = examples.export(str(s1), None, cy, out_dir=str(tmp_path / "d"), schema_text="S",
                        shares={"stage1": 0.5, "cypher": 0.5}, seed=0)
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
        c = examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "o"), schema_text="S", shares=shares, seed=0)
    assert c["used"] == {"stage1": 840, "stage2": 50} and c["train"] == 890      # total = 1050
    assert c["available"]["train"] == {"stage1": 1000, "stage2": 50}
    assert "'stage1' down-sampled" in caplog.text and "'stage2' shortfall" in caplog.text
    c = examples.export(str(s1), str(s2), None, out_dir=str(tmp_path / "p"), schema_text="S", shares=shares, seed=0,
                        total=250)
    assert c["used"] == {"stage1": 200, "stage2": 50} and c["train"] == 250
