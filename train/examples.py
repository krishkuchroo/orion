"""SFT rows: examples -> (messages, target), built only with `orion.lm.format`.

A training row is byte-identical to what the runtime prompter shows the model at that step: the
messages come from the same formatter functions and the target is the canonical action text
(`format.dumps_action`). Nothing here builds message text by hand.

Runtime note: `prompter.py` appends the model's raw reply (`res.text`) as the assistant turn, while
`cut` writes `dumps_action(action)`. They are identical whenever the model emits the canonical form,
which is what training teaches.
"""
from __future__ import annotations

import json
import logging
import random

from orion.lm import format as fmt

log = logging.getLogger(__name__)

SPLITS = ("train", "dev", "oldcve")


def to_sft(example: dict, *, schema_text: str) -> dict:
    lead = example.get("lead")
    return {
        "messages": [fmt.system_message(schema_text), fmt.task_message([example["case"]])],
        "target": fmt.dumps_action({"action": "final", "leads": [lead] if lead else []}),
        "meta": {"pair_id": example.get("pair_id"), "label": example.get("label"),
                 "tier": example.get("tier"), "stage": example.get("stage", 1)},
    }


def cut(trace: dict, *, schema_text: str) -> list[dict]:
    """One example per action of a Stage 2 trace; each sees the conversation so far."""
    actions, results = trace["actions"], trace["results"]
    if len(results) != len(actions) - 1:
        raise ValueError(f"trace has {len(actions)} actions but {len(results)} results (need one fewer)")
    history = [fmt.system_message(schema_text), fmt.task_message([trace["case"]])]
    out = []
    for i, action in enumerate(actions):
        out.append({"messages": list(history), "target": fmt.dumps_action(action),
                    "meta": {**(trace.get("meta") or {}), "stage": 2, "step": i}})
        if i < len(results):
            history.append({"role": "assistant", "content": fmt.dumps_action(action)})
            history.append(fmt.tool_result_message(action, results[i]))
    return out


def mix(groups: dict[str, list[dict]], shares: dict[str, float], *, total: int | None, seed: int) -> list[dict]:
    """Draw each group in proportion to its share; a short group is used whole (shortfall logged).
    `total=None` takes the largest total every group can fill."""
    rng = random.Random(seed)
    active = {k: s for k, s in shares.items() if s > 0 and k in groups}
    if not active:
        return []
    norm = sum(active.values())
    active = {k: s / norm for k, s in active.items()}
    if total is None:
        total = int(min(len(groups[k]) / s for k, s in active.items()))
    out: list[dict] = []
    for k in sorted(active):
        want = round(active[k] * total)
        have = groups[k]
        if want > len(have):
            log.warning("mix: group %r shortfall: wanted %d, have %d (used whole)", k, want, len(have))
            out.extend(have)
        else:
            out.extend(rng.sample(have, want))
    rng.shuffle(out)
    return out


def _read(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def _split_of(split, where: str) -> str:
    if split not in SPLITS:
        raise ValueError(f"{where}: split must be one of {SPLITS}, got {split!r}")
    return split


def _write(path: str, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def export(stage1_jsonl, stage2_jsonl, cypher_rows, *, out_dir, schema_text, shares, seed) -> dict:
    """Write `train.jsonl` (mixed by `shares`) and `dev.jsonl` (all dev rows, unmixed). `oldcve` is
    never written; a dev pair never reaches train. Every row needs a split or export raises."""
    import os
    by_split: dict[str, dict[str, list[dict]]] = {"train": {}, "dev": {}}
    dropped = 0

    def put(group: str, split: str, rows: list[dict]) -> None:
        nonlocal dropped
        if split == "oldcve":
            dropped += len(rows)
        else:
            by_split[split].setdefault(group, []).extend(rows)

    for row in _read(stage1_jsonl):
        put("stage1", _split_of(row.get("split"), f"stage1 {row.get('pair_id')}"), [to_sft(row, schema_text=schema_text)])
    if stage2_jsonl:
        for row in _read(stage2_jsonl):
            if "actions" in row:
                split = _split_of((row.get("meta") or {}).get("split"), "stage2 trace")
                put("stage2", split, cut(row, schema_text=schema_text))
            else:
                put("stage2", _split_of(row.get("split"), f"stage2 {row.get('pair_id')}"),
                    [to_sft({**row, "stage": 2}, schema_text=schema_text)])
    for row in cypher_rows or []:
        put("cypher", _split_of((row.get("meta") or {}).get("split", row.get("split")), "cypher row"), [row])

    train = mix(by_split["train"], shares, total=None, seed=seed)
    rng = random.Random(seed)
    dev = [r for g in sorted(by_split["dev"]) for r in by_split["dev"][g]]
    rng.shuffle(dev)
    os.makedirs(out_dir, exist_ok=True)
    _write(os.path.join(out_dir, "train.jsonl"), train)
    _write(os.path.join(out_dir, "dev.jsonl"), dev)
    return {"train": len(train), "dev": len(dev), "oldcve_dropped": dropped,
            "available": {s: {g: len(v) for g, v in gs.items()} for s, gs in by_split.items()}}
