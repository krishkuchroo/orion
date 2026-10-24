"""SFT rows: examples -> (messages, target), built only with `orion.lm.format`.

A training row is byte-identical to what the runtime prompter shows the model at that step: the
messages come from the same formatter functions and the target is the canonical action text
(`format.dumps_action`). Nothing here builds message text by hand.

Runtime note: `prompter.py` appends the model's raw reply (`res.text`) as the assistant turn, while
`cut` writes `dumps_action(action)`. They are identical whenever the model emits the canonical form,
which is what training teaches.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
from collections import Counter

from orion.lm import format as fmt
from orion.lm import sinks

log = logging.getLogger(__name__)

SPLITS = ("train", "dev", "oldcve")
SAMPLERS = ("random", "balanced")


def _primary_cwe(pair: dict) -> str | None:
    from train.stage1 import primary_cwe
    return primary_cwe(pair)


def to_sft(example: dict, *, schema_text: str | None = None, pair: dict | None = None) -> dict:
    """The case goes through `orion.lm.sinks.annotate` (idempotent), as the runtime's code-only cases do. `pair`
    (the example's `pairs.json` entry) fills meta's language / repo / cwe (the primary CWE, as Stage 1's lead)."""
    lead = example.get("lead")
    pair = pair or {}
    return {
        "messages": [fmt.system_message(schema_text), fmt.task_message([sinks.annotate(example["case"])])],
        "target": fmt.dumps_action({"action": "final", "leads": [lead] if lead else []}),
        "meta": {"pair_id": example.get("pair_id"), "label": example.get("label"),
                 "tier": example.get("tier"), "stage": example.get("stage", 1),
                 "language": pair.get("language"), "repo": pair.get("repo_canonical"),
                 "cwe": _primary_cwe(pair) if pair else None, "cwe_class": example.get("cwe_class"),
                 "split": example.get("split")},
    }


def cut(trace: dict, *, schema_text: str | None = None) -> list[dict]:
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


def _wants(groups: dict[str, list[dict]], shares: dict[str, float], total: int | None) -> dict[str, int]:
    """round(share * total) per group with a positive share (shares renormalised over the groups present).
    `total=None` takes the largest total every group can fill."""
    active = {k: s for k, s in shares.items() if s > 0 and k in groups}
    if not active:
        return {}
    norm = sum(active.values())
    active = {k: s / norm for k, s in active.items()}
    if total is None:
        total = int(min(len(groups[k]) / s for k, s in active.items()))
    return {k: round(active[k] * total) for k in sorted(active)}


def mix(groups: dict[str, list[dict]], shares: dict[str, float], *, total: int | None, seed: int) -> list[dict]:
    """Draw each group in proportion to its share; a short group is used whole (shortfall logged), and a group
    drawn below what it has is logged too. `total=None` takes the largest total every group can fill."""
    rng = random.Random(seed)
    out: list[dict] = []
    for k, want in _wants(groups, shares, total).items():
        have = groups[k]
        if want > len(have):
            log.warning("mix: group %r shortfall: wanted %d, have %d (used whole)", k, want, len(have))
            out.extend(have)
        else:
            if want < len(have):
                log.warning("mix: group %r down-sampled: using %d of %d rows", k, want, len(have))
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


def export(stage1_jsonl, stage2_jsonl, cypher_rows, *, out_dir, schema_text=None, shares, seed,
           total: int | None = None, allow_placeholder: bool = False, sampler: str = "random",
           pairs_path: str | None = None, balance_kwargs: dict | None = None) -> dict:
    """Write `train.jsonl` (mixed by `shares`) and `dev.jsonl` (all dev rows, unmixed). `oldcve` is
    never written; a dev pair never reaches train. Every row needs a split, and every pair_id must have
    ONE split across all inputs, or export raises. `schema_text` defaults to None, the runtime's compact
    system message (no graph schema). `total` (train rows to mix) defaults to every available train row of the
    groups with a positive share, so a small group is used whole (shortfall logged) instead of capping the
    others; `used` in the returned counts is the rows each group contributed.

    A system prompt that still starts with `PLACEHOLDER` raises unless `allow_placeholder=True` (dry runs).
    `system_sha256` (sha256 of the system message every row starts with) is returned and written next to
    each output file as `<out>.prompt.sha256`, so a training set always says which prompt it was built with.

    `pairs_path` (`train/data/pairs.json`) adds language / repo / cwe to every row's meta. `sampler="balanced"`
    (needs `pairs_path`; Stage 1 is the only group it draws) picks and orders the train rows with
    `train.balance.select` (`total` defaults to its 7000; `balance_kwargs` passes repo_cap / cwe_share / grad_accum
    through), keeps that order, and writes its report to
    `train.balance.json` next to `train.jsonl`; `"random"` (the default) is the old seeded mix. In balanced mode
    the dev Stage 1 rows also go through rule 1 (`balance.drop_conflicts`) and, when `balance_kwargs` has `fits`,
    lose the rows that fail it; both are reported under `dev` in the balance report."""
    if sampler not in SAMPLERS:
        raise ValueError(f"sampler must be one of {SAMPLERS}, got {sampler!r}")
    if sampler == "balanced" and not pairs_path:
        raise ValueError("sampler='balanced' needs pairs_path (pairs.json: language, repo, cwe per pair)")
    if not allow_placeholder and fmt.system_prompt_text().startswith("PLACEHOLDER"):
        raise ValueError("orion/lm/system_prompt.txt is still the PLACEHOLDER: training on it would skew the system "
                         "turn against evaluation; pass allow_placeholder=True only for a dry run")
    system_sha256 = hashlib.sha256(fmt.system_message(schema_text)["content"].encode("utf-8")).hexdigest()
    pairs_by_id: dict[str, dict] = {}
    if pairs_path:
        with open(pairs_path, encoding="utf-8") as f:
            pairs_by_id = {p["id"]: p for p in json.load(f)}
    pair_splits: dict[str, set[str]] = {}
    by_split: dict[str, dict[str, list[dict]]] = {"train": {}, "dev": {}}
    stage1_train: list[dict] = []
    stage1_dev: list[dict] = []
    dropped = 0

    def put(group: str, split: str, rows: list[dict]) -> None:
        nonlocal dropped
        for r in rows:
            pid = (r.get("meta") or {}).get("pair_id")
            if group != "cypher" and not pid:
                raise ValueError(f"{group} row has no pair_id (split {split!r}): cannot check it for leakage")
            if pid:
                pair_splits.setdefault(pid, set()).add(split)
        if split == "oldcve":
            dropped += len(rows)
        else:
            by_split[split].setdefault(group, []).extend(rows)

    def sft(row: dict) -> dict:
        return to_sft(row, schema_text=schema_text, pair=pairs_by_id.get(row.get("pair_id")))

    for row in _read(stage1_jsonl):
        split = _split_of(row.get("split"), f"stage1 {row.get('pair_id')}")
        if split == "train":
            stage1_train.append(row)
        elif split == "dev":
            stage1_dev.append(row)
        put("stage1", split, [sft(row)])
    if stage2_jsonl:
        for row in _read(stage2_jsonl):
            if "actions" in row:
                split = _split_of((row.get("meta") or {}).get("split"), "stage2 trace")
                put("stage2", split, cut(row, schema_text=schema_text))
            else:
                put("stage2", _split_of(row.get("split"), f"stage2 {row.get('pair_id')}"), [sft({**row, "stage": 2})])
    for row in cypher_rows or []:
        put("cypher", _split_of((row.get("meta") or {}).get("split", row.get("split")), "cypher row"), [row])

    for pid, sp in sorted(pair_splits.items()):
        if len(sp) > 1:
            raise ValueError(f"pair {pid!r} appears in more than one split: {sorted(sp)}")
    groups = by_split["train"]
    report = None
    if sampler == "balanced":
        others = sorted(k for k in groups if k != "stage1" and shares.get(k, 0) > 0)
        if others:
            raise ValueError(f"sampler='balanced' draws stage1 rows only; give {others} a zero share")
        from train import balance
        kw = dict(balance_kwargs or {})
        if total is not None:
            kw["total"] = total
        picked, report = balance.select(stage1_train, pairs_by_id, seed=seed, **kw)
        train = [sft(r) for r in picked]
        used = {"stage1": len(train)}
        dev_kept, dev_rule1 = balance.drop_conflicts(stage1_dev)          # rule 1 in the dev split too
        dev_over: dict[str, int] = {}
        if kw.get("fits") is not None:
            ok = [kw["fits"](r) for r in dev_kept]
            dev_over = dict(sorted(Counter(r["label"] for r, y in zip(dev_kept, ok) if not y).items()))
            dev_kept = [r for r, y in zip(dev_kept, ok) if y]
        by_split["dev"]["stage1"] = [sft(r) for r in dev_kept]
        report["dev"] = {"rule1": dev_rule1, "dropped_over_length": dev_over, "rows": len(dev_kept)}
    else:
        if total is None:
            total = sum(len(groups[k]) for k in groups if shares.get(k, 0) > 0)
        train = mix(groups, shares, total=total, seed=seed)
        used = {k: min(want, len(groups[k])) for k, want in _wants(groups, shares, total).items()}
    rng = random.Random(seed)
    dev = [r for g in sorted(by_split["dev"]) for r in by_split["dev"][g]]
    rng.shuffle(dev)
    os.makedirs(out_dir, exist_ok=True)
    for name, rows in (("train.jsonl", train), ("dev.jsonl", dev)):
        path = os.path.join(out_dir, name)
        _write(path, rows)
        with open(path + ".prompt.sha256", "w", encoding="utf-8") as f:
            f.write(system_sha256 + "\n")
    counts = {"train": len(train), "dev": len(dev), "oldcve_dropped": dropped,
              "available": {s: {g: len(v) for g, v in gs.items()} for s, gs in by_split.items()}, "used": used,
              "system_sha256": system_sha256}
    report_path = os.path.join(out_dir, "train.balance.json")
    if report is None and os.path.exists(report_path):
        os.remove(report_path)                   # a random export must not sit next to an old balanced report
    if report is not None:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
            f.write("\n")
        counts["balance"] = report
    return counts
