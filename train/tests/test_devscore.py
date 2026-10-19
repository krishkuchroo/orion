import json

from orion.lm import format as fmt
from orion.lm import slice as lm_slice
from orion.lm.model import ContextOverflow, GenResult
from train import devscore

CASE = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
        "snippets": [{"role": "target", "file": "a.py", "function": "f", "start": 1, "end": 2, "code": "x"}]}
LEAD = {"flow_id": "F0", "file": "a.py", "function": "f", "line": 1, "cwe": "CWE-89", "confidence": "HIGH"}


def test_judge_scores_pairs_and_forces_final():
    """Patched silent + vulnerable flagged = pair-correct; a non-final first action gets one forced final."""
    exs = [{"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD},
           {"pair_id": "P", "label": "patched", "case": CASE, "lead": None},
           {"pair_id": "Q", "label": "negative", "case": CASE, "lead": None}]
    replies = iter([json.dumps({"action": "read_code", "file": "a.py", "start": 1, "end": 2}),
                    json.dumps({"action": "final", "leads": [LEAD]}),
                    json.dumps({"action": "final", "leads": []}), "garbage", json.dumps({"action": "final", "leads": []})])
    out = devscore.judge(lambda m: GenResult(text=next(replies), prompt_tokens=10, completion_tokens=2, cached_tokens=0),
                         exs, schema_text="S")
    assert out["vuln_recall"] == 1.0 and out["patched_silence"] == 1.0 and out["pair_correct"] == 1.0
    assert out["negative_silence"] == 1.0 and out["parse_fail_rate"] > 0 and out["tokens"] == 60
    assert out["n"] == 3


def test_judge_messages_and_dev_only_and_misses():
    seen = []
    final = json.dumps({"action": "final", "leads": [LEAD]})

    def gen(messages):
        seen.append(list(messages))
        return GenResult(text=final, prompt_tokens=1, completion_tokens=1, cached_tokens=0)

    exs = [{"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD, "split": "dev"},
           {"pair_id": "P", "label": "patched", "case": CASE, "lead": None, "split": "dev"},
           {"pair_id": "T", "label": "vulnerable", "case": CASE, "lead": LEAD, "split": "train"}]
    out = devscore.judge(gen, exs, schema_text="S")
    assert seen[0] == [fmt.system_message("S"), fmt.task_message([CASE])]
    assert len(seen) == 2 and out["n"] == 2
    assert out["patched_silence"] == 0.0 and out["pair_correct"] == 0.0 and out["vuln_recall"] == 1.0
    assert out["negative_silence"] is None  # no negatives: not a made-up 0 or 1
    assert out["parse_fail_rate"] == 0.0


def test_forced_final_appends_assistant_turn_and_default_schema():
    calls = []
    first = json.dumps({"action": "run_cypher", "query": "MATCH (n) RETURN n"})

    def gen(messages):
        calls.append(list(messages))
        text = first if len(calls) == 1 else json.dumps({"action": "final", "leads": []})
        return GenResult(text=text, prompt_tokens=1, completion_tokens=1, cached_tokens=0)

    devscore.judge(gen, [{"pair_id": "P", "label": "negative", "case": CASE, "lead": None}], schema_text=None)
    assert calls[0][0] == fmt.system_message(lm_slice.pruned_schema())
    assert calls[1] == calls[0] + [{"role": "assistant", "content": first}, fmt.forced_final_message()]


def test_unparseable_forced_final_is_no_lead_and_overflow_counted():
    def bad(messages):
        return GenResult(text="nope", prompt_tokens=1, completion_tokens=1, cached_tokens=0)

    ex = [{"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD}]
    out = devscore.judge(bad, ex, schema_text="S")
    assert out["vuln_recall"] == 0.0 and out["parse_fail_rate"] == 1.0

    def over(messages):
        raise ContextOverflow(9000, 8192)

    out = devscore.judge(over, ex, schema_text="S")
    assert out["vuln_recall"] == 0.0 and out["context_overflow"] == 1


def test_pair_correct_aggregates_duplicate_rows_per_pair():
    """Every vulnerable row flagged AND every patched row silent; one-sided pairs are excluded."""
    flag = json.dumps({"action": "final", "leads": [LEAD]})
    quiet = json.dumps({"action": "final", "leads": []})
    replies = iter([quiet, flag, quiet,          # P: vuln flagged, vuln missed, patched silent -> wrong
                    flag, flag, quiet,           # R: two vuln flagged, patched silent -> correct
                    flag])                       # S: vulnerable only -> excluded
    exs = [{"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD},
           {"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD},
           {"pair_id": "P", "label": "patched", "case": CASE, "lead": None},
           {"pair_id": "R", "label": "vulnerable", "case": CASE, "lead": LEAD},
           {"pair_id": "R", "label": "vulnerable", "case": CASE, "lead": LEAD},
           {"pair_id": "R", "label": "patched", "case": CASE, "lead": None},
           {"pair_id": "S", "label": "vulnerable", "case": CASE, "lead": LEAD}]
    out = devscore.judge(lambda m: GenResult(text=next(replies), prompt_tokens=1, completion_tokens=1, cached_tokens=0),
                         exs, schema_text="S")
    assert out["pair_correct"] == 0.5
