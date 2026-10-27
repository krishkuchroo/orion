---
name: orion-lm-train
description: Orion-LM training run: Stage 1 data build, base-model bake-off, SFT export, Unsloth cloud training, MLX convert, dev scoring, the system prompt, context budget, code indexing. Use when training, building data for, scoring, or explaining the Orion-LM model.
---

# Orion-LM training run

Answer concisely: lead with the answer, then a short table or bullets in plain words.

Run from `~/Documents/OrionLutherLeo/orion-train` as `PYTHONPATH=$PWD ./.venv/bin/python ...`.
Full design: `docs/superpowers/plans/2026-10-18-orion-lm-hybrid.md`.

## Data flow

```
orion-lm-research/raw/ (15 sources) -> train/mine.py [done]
  -> train/data/pairs.json (4,850) + splits.json (frozen: train 4,120 / dev 702 / oldcve 28)
  -> train.stage1 -> train/data/stage1.jsonl
  -> examples.export(sampler='balanced', pairs_path=...) -> train/data/sft/{train,dev}.jsonl + train.balance.json
  -> train.unsloth_data --tokenized -> train/data/mlx/{train,dev}.jsonl
  -> bash train/start_c1.sh (Unsloth MLX trainer on the Mac, guard, TensorBoard) -> train/runs/qwen35-c1/
  -> train.convert.merge_lora('models/orion-lm-base', 'train/runs/qwen35-c1', 'models/orion-lm')
  -> [next] freeze sampling; dev bakeoff of models/orion-lm vs models/orion-lm-base
```

`../orion/train/data/` is a stale 2026-10-18 copy (4,058 pairs, no splits). Use orion-train's.
A pair is metadata only (repo, commits, CWE); Stage 1 fetches the code from GitHub.

## Steps

| # | Do | Done when |
|---|---|---|
| 0 | Krish writes `orion/lm/system_prompt.txt`: flag the fix site; code-only cases with no path; Cypher rules from `train/templates/README.md`; one case per session | file no longer starts with `PLACEHOLDER` |
| 1 | Pilot: `python -m train.stage1 --per-language 10`; record numbers in `docs/notes/orion-lm-stage1.md` | ledger has 30 lines |
| 2 | Full: `python -m train.stage1 2>&1 \| tee train/data/stage1.log` (resumes from ledger, Ctrl-C safe) | ledger has 4,579 lines (4,850 minus 271 `unknown` CWE) |
| 3 | Bake-off per candidate: `to_mlx('<HF repo>', 'models/<name>-base')`, then `python -m eval.bakeoff --one models/<name>-base --dev train/data/stage1.jsonl --train-cutoff <date>`; table in `docs/notes/orion-lm-bakeoff.md` | Krish picks the winner (E4B if inconclusive); cutoff < 2026-05-31 |
| 4 | Export: `examples.export('train/data/stage1.jsonl', None, None, out_dir='train/data/sft', shares={'stage1': 1.0}, seed=0, total=7000, sampler='balanced', pairs_path='train/data/pairs.json')`, then `python -m train.unsloth_data --in train/data/sft/<s>.jsonl --out train/data/mlx/<s>.jsonl --tokenizer unsloth/Qwen3.5-4B --max-len 4096 --tokenized` for train and dev | `train/data/mlx/{train,dev}.jsonl`, `train.balance.json` |
| 5 | Train on the Mac: `bash train/start_c1.sh` (base `models/orion-lm-base`, LoRA r16/alpha16, top 8 layers, 1 epoch, dev eval every 100 steps, 9 GB cap, checkpoint every 10 steps; rerunning it continues from the newest complete checkpoint). Never next to a Stage 1/2 build or Joern | adapter in `train/runs/qwen35-c1/` |
| 6 | Merge: `train.convert.merge_lora(base, run_dir, 'models/orion-lm')` keeps the adapted layers bf16 (never re-quantize to 4-bit: it rounds the fine-tune away); check its dev loss matches the trainer's final eval; then rerun step 3's bakeoff on it | row comparable to the base row (same sample, seed 0) |

## Files per step

| Step | Code | Writes |
|---|---|---|
| 0 | `orion/lm/format.py` reads the txt | — |
| 1–2 | `train/stage1.py`, `snapshot.py`, `build.py`, `fixmap.py`, `splits.py`, `sources.py`, `orion/lm/codeindex.py`, `cases.py` | `stage1.jsonl`, `stage1_ledger.jsonl`, `train/data/work/` (temp) |
| 3, 6 | `train/convert.py`, `eval/bakeoff.py`, `train/devscore.py`, `orion/lm/model.py` | `models/*` |
| 4 | `train/examples.py`, `orion/lm/format.py`, `slice.py` | `train/data/sft/*` |
| 4 | `train/balance.py`, `train/unsloth_data.py`, `orion/lm/sinks.py`, `orion/lm/schema_card.txt` | `train/data/mlx/*` |
| 5 | `train/mlx_train.py`, `train/guard.py`, `train/start_c1.sh` (Colab: `train/unsloth_lora.ipynb`, not updated) | `train/runs/qwen35-c1/` |

## Context budget

The prompt lives in `system_prompt.txt`; the file format adds no tokens, only its length counts.
`format.system_message` = prompt txt + `schema_card.txt` (GRAPH SCHEMA) + `ACTION_RULES` = 609 Qwen3.5 tokens
(2026-10-24); training rows and runtime calls use the same message.

| Limit | Value | Where |
|---|---|---|
| Hard cap per training row | 4,096 tokens; longer rows leave the pool before sampling, never truncated | `mlx_train --max-len`, `balance` `fits` filter |
| Code per case | target ≤120 lines; ≤2 callers + ≤2 callees at ≤40 lines | `cases.CaseBudget` |
| Graph rows per query | 25 | `tools.ROW_LIMIT` |
| Cases per session | 1 (K=1) | `engine.DEFAULT_K` |

## Indexing

- **Code**: `codeindex.RepoIndex` parses each JS/TS/Python/Java file once with tree-sitter into function
  spans `(file, name, start, end, calls)`; it skips tests, `*.min.js`, files >1 MB and vendored dirs.
  `enclosing(file, line)` finds the function; callers/callees resolve same file, then same dir, then sorted path.
- **Case**: `cases.py` turns a graph flow or a changed function into one CodeCase (target + source +
  callers/callees), trimmed to `CaseBudget`.
- **Graph**: Neo4j, every node keyed by `scan_id`; Orion's precompute ranks CandidateFlows.
