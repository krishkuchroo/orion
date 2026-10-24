# Orion-LM Stage 1: measured pilot and full-run counts

## Pilot (2026-10-23)

Command: `python -m train.stage1 --per-language 10` (seeded sample, seed 0: 10 js, 10 py, 10 java pairs).
Every number below is read from `train/data/stage1_ledger.jsonl` and `train/data/stage1.jsonl` after the
run. Projections are marked as projections and use only these measurements.

| metric | value |
|---|---|
| pairs | 30: 27 ok, 3 skipped (2 `sprawling`, 1 `no_target`), 0 snapshot failures |
| examples | 131: vulnerable 45 · patched 34 · negative 52 |
| examples by split | train 107 · dev 24 |
| tiers | annotated 20 · single 28 · multi 31 · negative 52 |
| `seconds_network`, summed (min / max per pair) | 115.4 s (0.6 / 20.2) |
| `seconds_index`, summed (min / max) | 13.2 s (0.0 / 3.3) |
| `bytes_clone` per repo (min / max) | 62,810 B / 115,757,370 B; snapshots deleted after each repo |
| files indexed / skipped | 13,608 / 2,721 |
| code lines per case (p50 / p90 / max) | 60 / 134 / 211 |
| code chars per case (p50 / p90 / max) | 2,147 / 6,930 / 502,609 |
| `stage1.jsonl` size | 2,645,958 B |

**Finding: minified files not named `*.min.js` get indexed.** CVE-2023-2327 pulls
`bundles/AdminBundle/Resources/public/js/lib/ace/src-min-noconflict/ace.js` (one 370,084-char line) and
`worker-css.js` (one 131,831-char line) in as caller/callee snippets of 3 examples. Those rows exceed the
8,000-token cap, so the notebook drops them (never truncates); at runtime the same case would raise
`ContextOverflow`. Fix proposed, not applied: `codeindex` skips files whose longest line is very long,
with a recorded reason, then the affected pairs are rebuilt.

**Projection (from the pilot only; n = 30, so wide):**
- Time: mean `seconds_network + seconds_index` = 4.29 s per pair; × 4,549 remaining eligible pairs ≈ 5.4 h.
  Other per-pair work (diffs, `git show`, case building) is not in these fields, so wall-clock will be longer.
- Examples: 4.37 per pair × 4,579 eligible pairs ≈ 20,000 examples, ≈ 17,000 of them train (train share
  3,883 / 4,579 eligible pairs).

## Minified-file fix (2026-10-23, approved by Krish)

`codeindex.MAX_LINE_CHARS = 2_000`: a file with any longer line is skipped as
`minified (a line over 2000 chars)`, in the walk and in `update()`. In the 126 pairs built before the fix,
hand-written snippets peaked at 439 chars per line; the minified ones were 130,342 to 370,084. Tokens per
row with the Qwen3.5 tokenizer on 200 pre-fix rows (placeholder prompt): p50 2,192, p90 3,249, max
151,802, 5 over 8,000.

The pre-fix outputs were moved aside (not mixed in) and the full run restarted from scratch.

## Full run

Started 2026-10-23 with `PYTHONUNBUFFERED=1 python -m train.stage1 2>&1 | tee train/data/stage1.log`, from
an empty ledger, with the fix. Final counts are recorded here when it finishes.

Finished 2026-10-23 23:20 (read from `stage1_ledger.jsonl` and `stage1.jsonl`). The run was stopped and resumed
from the ledger several times. On 2026-10-23 22:32 Krish skipped the last 19 liferay/liferay-portal pairs
(~70 s per pair, 105 in the repo); their ledger rows say `skipped_by_user`.

| metric | value |
|---|---|
| pairs | 4,579: 3,496 ok, 1,078 skipped, 5 `commit_missing` |
| skip reasons | `sprawling` 616 · `no_target` 432 · `skipped_by_user` 19 · `no_cwe` 11 · `not in mirror` 5 |
| examples | 17,086 (60 MB) |
| train | 14,449 rows from 2,951 fixes: vulnerable 4,639 · patched 4,127 · negative 5,683 |
| dev | 2,536 rows from 521 fixes: vulnerable 814 · patched 710 · negative 1,012 |
| oldcve | 101 rows from 24 fixes |
| train languages (rows) | js 44% · java 42% · py 14% |
| train repos / CWEs | 1,856 / 219 |

Found afterwards: 87 groups (176 train rows) where identical target code is labelled vulnerable in one row and
safe in another (an incomplete fix's patched version is the next CVE's vulnerable version), plus 202 groups of
exact duplicates. `train/balance.py` drops both before sampling.
