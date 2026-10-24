"""Tool-less dev judge for Orion-LM: one `[system, task]` call per dev example, no graph tools.

If the first action is not `final`, the assistant turn plus `forced_final_message()` is appended and the
model is called once more. Output that does not parse as an action counts as no lead plus a parse failure.
All counts are measured; a rate with an empty denominator is None, never 0 or 1.
"""
from __future__ import annotations

import time

from orion.lm import format as fmt
from orion.lm.model import ContextOverflow


def _rate(num: int, den: int):
    return num / den if den else None


def _field(row: dict, key: str):
    val = row.get(key)
    if val is None:
        val = (row.get("meta") or {}).get(key)
    if val is None:
        raise ValueError(f"dev row has no {key!r} (top level or meta): {str(row)[:200]}")
    return val


def normalise_row(row: dict) -> dict:
    """THE dev-row reader (this module and `eval.bakeoff`): `{case, pair_id, split, label, lead}` from a Stage
    1/2 example row or a Stage 2 trace (`stage2.trace_for`: pair_id/split/label under `meta`). `lead` is the
    row's lead, or for a trace the first lead of its last `final` action (None when it has none). A row
    without a split raises ValueError: it is never treated as dev."""
    if "actions" in row:
        finals = [a for a in row.get("actions") or [] if isinstance(a, dict) and a.get("action") == "final"]
        leads = (finals[-1].get("leads") or []) if finals else []
        lead = leads[0] if leads else None
    else:
        lead = row.get("lead")
    return {"case": _field(row, "case"), "pair_id": _field(row, "pair_id"), "split": _field(row, "split"),
            "label": _field(row, "label"), "lead": lead}


def _judge_one(generate, example: dict, schema_text: str | None, acc: dict) -> tuple[bool, bool, bool]:
    """-> (flagged, parse_failed, overflowed). Adds token and time counts into `acc`."""
    messages = [fmt.system_message(schema_text), fmt.task_message([example["case"]])]
    parse_failed = False
    action = None
    for step in range(2):
        t0 = time.perf_counter()
        try:
            res = generate(messages)
        except ContextOverflow:
            return False, parse_failed, True
        acc["seconds"] += time.perf_counter() - t0
        acc["tokens"] += res.prompt_tokens + res.completion_tokens
        acc["completion"] += res.completion_tokens
        action = fmt.parse_action(res.text)
        if action is None:
            parse_failed = True
        if action is not None and action.get("action") == "final":
            break
        if step == 0:
            messages = messages + [{"role": "assistant", "content": res.text}, fmt.forced_final_message()]
    if action is None or action.get("action") != "final":
        return False, parse_failed, False
    leads = action.get("leads")
    return bool(leads), parse_failed, False


def judge(generate, dev_examples, *, schema_text=None) -> dict:
    """Score `generate(messages) -> GenResult` on the dev rows (example rows or Stage 2 traces, read by
    `normalise_row`). Only `split == "dev"` is scored; a row with no split raises ValueError. `schema_text`
    defaults to None, the runtime's compact system message (no graph schema)."""
    rows = [r for r in map(normalise_row, dev_examples) if r["split"] == "dev"]
    acc = {"tokens": 0, "completion": 0, "seconds": 0.0}
    flagged_by: dict[str, dict[str, list[bool]]] = {}
    by_label: dict[str, list[bool]] = {"vulnerable": [], "patched": [], "negative": []}
    parse_fail = overflow = 0
    for r in rows:
        flagged, pf, ov = _judge_one(generate, r, schema_text, acc)
        parse_fail += pf
        overflow += ov
        by_label.setdefault(r["label"], []).append(flagged)
        flagged_by.setdefault(r["pair_id"], {}).setdefault(r["label"], []).append(flagged)
    # A pair is scored only when it has both sides; it is correct iff every vulnerable row is flagged
    # and every patched row is silent (Stage 1 and Stage 2 can share a pair_id, so rows repeat).
    pairs = [d for d in flagged_by.values() if d.get("vulnerable") and d.get("patched")]
    correct = sum(1 for d in pairs if all(d["vulnerable"]) and not any(d["patched"]))
    vul, pat, neg = by_label["vulnerable"], by_label["patched"], by_label["negative"]
    return {
        "n": len(rows),
        "vuln_recall": _rate(sum(vul), len(vul)),
        "patched_silence": _rate(len(pat) - sum(pat), len(pat)),
        "negative_silence": _rate(len(neg) - sum(neg), len(neg)),
        "pair_correct": _rate(correct, len(pairs)),
        "parse_fail_rate": _rate(parse_fail, len(rows)),
        "context_overflow": overflow,
        "tokens": acc["tokens"],
        "tok_per_s": _rate(acc["completion"], acc["seconds"]) if acc["seconds"] > 0 else None,
    }
