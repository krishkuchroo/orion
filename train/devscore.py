"""Tool-less dev judge for Orion-LM: one `[system, task]` call per dev example, no graph tools.

If the first action is not `final`, the assistant turn plus `forced_final_message()` is appended and the
model is called once more. Output that does not parse as an action counts as no lead plus a parse failure.
All counts are measured; a rate with an empty denominator is None, never 0 or 1.
"""
from __future__ import annotations

import time

from orion.lm import format as fmt
from orion.lm import slice as lm_slice
from orion.lm.model import ContextOverflow


def _rate(num: int, den: int):
    return num / den if den else None


def _judge_one(generate, example: dict, schema_text: str, acc: dict) -> tuple[bool, bool, bool]:
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
    """Score `generate(messages) -> GenResult` on the dev rows. A row with no `split` counts as dev; any
    other split is skipped. `schema_text` defaults to the runtime `slice.pruned_schema()`."""
    if schema_text is None:
        schema_text = lm_slice.pruned_schema()
    rows = [r for r in dev_examples if r.get("split", "dev") == "dev"]
    acc = {"tokens": 0, "completion": 0, "seconds": 0.0}
    flagged_by: dict[tuple, bool] = {}
    by_label: dict[str, list[bool]] = {"vulnerable": [], "patched": [], "negative": []}
    parse_fail = overflow = 0
    for r in rows:
        flagged, pf, ov = _judge_one(generate, r, schema_text, acc)
        parse_fail += pf
        overflow += ov
        by_label.setdefault(r["label"], []).append(flagged)
        flagged_by[(r["pair_id"], r["label"])] = flagged
    pairs = sorted({p for p, lab in flagged_by if lab == "vulnerable"} &
                   {p for p, lab in flagged_by if lab == "patched"})
    correct = sum(1 for p in pairs if flagged_by[(p, "vulnerable")] and not flagged_by[(p, "patched")])
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
