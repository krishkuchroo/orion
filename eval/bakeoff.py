"""Bake-off harness: run each candidate model through `train.devscore.judge` on one seeded dev sample.

`peak_rss_mb` is the child process's own `ru_maxrss` high-water mark, so each candidate runs in a FRESH
subprocess (`run_all` / `--one`). An in-process run (`isolated=False`, used by tests) records None, because a
process-wide high-water mark would include earlier candidates. It is never estimated. `train_cutoff` is
whatever string the caller supplies.
"""
from __future__ import annotations

import argparse
import json
import random
import resource
import subprocess
import sys

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


def _maxrss_mb() -> float:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024  # bytes on macOS, KB on Linux


def run_candidate(model_path, dev_examples, *, schema_text=None, load=lm_model.load,
                  sample_n=300, seed=0, train_cutoff=None, isolated=False) -> dict:
    sample = sample_dev(dev_examples, sample_n=sample_n, seed=seed)
    model = load(model_path)
    scores = devscore.judge(model.generate, sample, schema_text=schema_text)
    return {**scores, "model": str(model_path), "peak_rss_mb": _maxrss_mb() if isolated else None,
            "train_cutoff": train_cutoff}


def _subprocess_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def _error_row(path, exc: Exception) -> dict:
    reason = f"{type(exc).__name__}: {exc}"
    stderr = getattr(exc, "stderr", None)
    if stderr:
        reason += " | stderr: " + str(stderr).strip()[:300]
    return {**{c: None for c in COLUMNS}, "model": str(path), "error": reason[:500]}


def run_all(candidates, dev_path, *, sample_n=300, seed=0, train_cutoffs=None, run=_subprocess_run) -> list[dict]:
    """One fresh child process per candidate (`python -m eval.bakeoff --one ...`); `run(cmd) -> stdout`
    is injectable. The row is the last JSON line the child prints."""
    rows = []
    for path in candidates:
        cmd = [sys.executable, "-m", "eval.bakeoff", "--one", str(path), "--dev", str(dev_path),
               "--sample-n", str(sample_n), "--seed", str(seed)]
        cutoff = (train_cutoffs or {}).get(path)
        if cutoff is not None:
            cmd += ["--train-cutoff", cutoff]
        try:
            lines = run(cmd).strip().splitlines()
            if not lines:
                raise ValueError("child printed nothing")
            rows.append(json.loads(lines[-1]))
        except Exception as exc:  # one bad candidate must not drop the others' rows
            rows.append(_error_row(path, exc))
    return rows


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


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--one", required=True, help="model path: score this one candidate, print its row as JSON")
    ap.add_argument("--dev", required=True, help="dev examples JSONL")
    ap.add_argument("--sample-n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--train-cutoff", default=None)
    a = ap.parse_args(argv)
    with open(a.dev, encoding="utf-8") as f:
        dev = [json.loads(ln) for ln in f if ln.strip()]
    row = run_candidate(a.one, dev, sample_n=a.sample_n, seed=a.seed, train_cutoff=a.train_cutoff, isolated=True)
    print(json.dumps(row))


if __name__ == "__main__":
    main()
