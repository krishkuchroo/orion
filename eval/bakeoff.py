"""Bake-off harness: run each candidate model through `train.devscore.judge` on one seeded dev sample.

`peak_rss_mb` is sampled while the model loads and runs (psutil, `eval.resources.PhaseSampler`); None when
nothing could be sampled. It is never estimated. `train_cutoff` is whatever string the caller supplies.
"""
from __future__ import annotations

import os
import random

from eval.resources import PhaseSampler
from orion.lm import model as lm_model
from train import devscore

COLUMNS = ["model", "n", "vuln_recall", "patched_silence", "negative_silence", "pair_correct",
           "parse_fail_rate", "tokens", "tok_per_s", "peak_rss_mb", "train_cutoff"]


def sample_dev(dev_examples, *, sample_n: int, seed: int) -> list[dict]:
    """Seeded sample of whole pairs (so pair_correct stays defined), at most `sample_n` rows. The result
    depends only on the dev rows, `sample_n` and `seed`, never on the candidate."""
    groups: dict[str, list[dict]] = {}
    for r in dev_examples:
        if r.get("split", "dev") == "dev":
            groups.setdefault(r["pair_id"], []).append(r)
    ids = sorted(groups)
    random.Random(seed).shuffle(ids)
    out: list[dict] = []
    for pid in ids:
        if len(out) + len(groups[pid]) <= sample_n:
            out.extend(sorted(groups[pid], key=lambda r: r["label"]))
    return out


def run_candidate(model_path, dev_examples, *, schema_text=None, load=lm_model.load,
                  sample_n=300, seed=0, train_cutoff=None) -> dict:
    sample = sample_dev(dev_examples, sample_n=sample_n, seed=seed)
    with PhaseSampler(os.getpid(), interval=0.5) as sampler:
        sampler._sample_once()
        model = load(model_path)
        scores = devscore.judge(model.generate, sample, schema_text=schema_text)
        sampler._sample_once()
    return {**scores, "model": str(model_path), "peak_rss_mb": sampler.peak_rss_mb, "train_cutoff": train_cutoff}


def _cell(v) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.3f}" if abs(v) < 10 else f"{v:.0f}"
    return str(v)


def table(rows) -> str:
    lines = ["| " + " | ".join(COLUMNS) + " |", "|" + "|".join("---" for _ in COLUMNS) + "|"]
    for r in rows:
        lines.append("| " + " | ".join(_cell(r.get(c)) for c in COLUMNS) + " |")
    return "\n".join(lines)
