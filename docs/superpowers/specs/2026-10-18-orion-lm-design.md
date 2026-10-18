# Orion-LM: a trained local model for Orion, and a benchmark that proves it

- **Date:** 2026-10-18
- **Branch:** `eval/orion-lm` (cut from `eval/open-weight-study` @ 805412d)
- **Status:** APPROVED by Krish 2026-10-18. Implementation plan: not yet written (next step).
- **Builds on:** `2026-09-17-open-weight-eval-design.md` (dataset rule, matching rule, run log).
  Where the two disagree, this document wins **on this branch only**.

## 1. Intent

Orion already finds attack paths by building a code graph (Joern → Neo4j) and letting an LLM query
it. Today that LLM is Claude, through `claude -p`. Krish wants Orion to have **its own model**:
a small open-weight model, fine-tuned with Unsloth to do exactly one job — **write Cypher against
Orion's graph, follow source→sink paths, and judge whether code is vulnerable** — running fully on
the laptop, with no Claude, no Ollama, no API, no network.

Then prove it with **solid numbers**: does Orion + its own model beat frontier models (Claude Opus,
Claude Sonnet, GPT) on real, recent, unseen vulnerabilities — specifically on **efficiency** (bugs
found per token) and **false alarms**, with recall reported honestly either way.

Why it matters: a local model that is cheap, private, and good at this one task is a real product
edge, and a defensible paper result.

## 2. Goals, non-goals, anti-goals

**Goals**
1. `orion scan <repo> --engine lm` runs end to end on the M4 16 GB using the trained model
   in-process.
2. The model judges **unknown code**: it flags real vulnerable paths AND stays quiet on safe code
   (trained with negatives, measured with a false-alarm metric).
3. A repeatable **training loop**: build data → train → convert → score on dev → repeat.
4. An **eval system built for attack paths**: scores the path (entry → steps → sink), not just the
   file, with pre-registered metrics, error bars, and paired comparisons.
5. Everything built in **a few days**.

**Non-goals (this sprint)**
- Reinforcement learning (GRPO). Evidence says it can raise missed bugs; deferred until SFT works.
- A verifier stage for Orion-LM (v1 scores raw leads; a second-pass verifier is a later round).
- Exploit generation / proof-of-concept running (already deferred by the 09-17 study).
- Access-control bugs as a training target (no data flow to trace; reported separately).
- Training from scratch. "Custom model" = a fine-tuned open-weight base.

**Anti-goals (would make this a failure even if it technically works)**
- Any number that is estimated, backfilled, or fabricated. Missing = recorded as missing.
- Tuning against the test set. The test set is touched **once**, at the end.
- Claude or GPT outputs used as training data (terms of service + circular).
- Training on any repo that appears in the test period (leak).
- An agent able to see the answer (e.g. the fix commit in `.git`).
- Breaking Orion's existing behaviour: the default `orion scan` path, FLOWS_TO parity
  (217 NodeGoat / 1075 PyGoat), and the 75 token-free tests must stay green.

## 3. Constraints

- **Machine:** MacBook Pro M4, 16 GB unified memory, no NVIDIA GPU. macOS gives the GPU ≈10.7 GB by
  default. Neo4j must run alongside the model (heap capped ≈2 GB). Joern and the model are never
  loaded together (build phase, then reasoning phase — existing CLAUDE.md rule).
- **Training hardware:** the Unsloth Python library does not train on Apple Silicon. Train on a
  cloud GPU (free Kaggle/Colab T4 first; RunPod 24 GB card ≈$0.16–0.27/h as fallback).
- **No Claude, no Ollama** anywhere in the Orion-LM path. Frontier models appear only as competitor
  arms.
- **Base model must have a published training-data cutoff before 2026-05-31**, or the test CVEs may
  be memorized. (This is the existing reason Qwen is excluded.)
- **Research rules from the 09-17 study still apply:** no fabricated data; results reported either
  way; pre-registration before any scored run; changes need a dated `eval/CHANGELOG.md` entry.
- **Timeline:** a few days for everything except, possibly, the final test run (sized on Day 1).

## 4. Decided by Krish (2026-10-17/18)

1. Train a custom model with Unsloth; it runs **inside Orion**, no Ollama, no Claude.
2. A **hand-written prompter** (our own agent loop), not `claude -p`.
3. The model's job is to **write Cypher queries that solve the graph**, inside an iterative loop:
   run → score → keep what worked → retrain.
4. The model must judge **unknown code**, not only listed CVEs.
5. **Test set is run once at the end**; all tuning happens on dev.
6. **Frontier models are competitors only** — never training data, never inside the pipeline.
7. **Headline = efficiency + false-alarm rate**; recall reported either way.
8. Work lives on a **separate branch** (`eval/orion-lm`).
9. Build **fast** — the milestones in days, not weeks.
10. Survey other Unsloth models instead of assuming Gemma (done; see §5.3).

## 5. Design

### 5.1 Orion-LM runtime (the product)

```
repo ─► Joern ─► Neo4j graph (existing build, unchanged)
                      │      CandidateFlow = ranked source→sink paths
        ┌─────────────▼─────────────────────────────────────────┐
        │ PROMPTER (new, our code)                              │
        │  system: role + pruned schema + rules + action format │
        │  user:   task + top-K CandidateFlows (as path slices) │
        │  loop:   model emits ONE action as JSON               │
        │          run_cypher  → validate (EXPLAIN) → run       │
        │                        read-only → ≤25 rows back      │
        │          read_code   → file lines back                │
        │          final       → leads JSON, loop ends          │
        │  limits: 8k-token context, then a forced `final`;     │
        │          40 actions max                               │
        └─────────────┬─────────────────────────────────────────┘
                      ▼
   leads: [{file, function, line, cwe, confidence, path:[{file,function,line,role}]}]
```

- **Model in-process:** MLX-LM, 4-bit weights, one prompt cache per run, append-only history (so
  earlier turns are never re-read; a template that rewrites history breaks the cache). Gemma-style
  "thinking" off. Final JSON forced with constrained decoding (Outlines). Fallback runtime:
  llama-cpp-python + GGUF.
- **Tools:** `run_cypher` reuses Orion's existing read-only guard (`orion/mcp_server.py`);
  `read_code(file, start, end)` is sandboxed to the scanned repo. `semantic_search` is out of v1.
- **Validator:** every query goes through `EXPLAIN` first; a syntax/schema error is returned to the
  model as a short structured message instead of rows.
- **Input slicing:** CandidateFlows are serialized as path slices (path nodes + the lines they touch),
  not whole methods; schema text is pruned to what dataflow needs.
- **Logging:** every step (LLM call or tool call) writes prompt/completion/cached tokens, wall time,
  the query, rows returned, and any error to a `steps` table. Exact counts come from the tokenizer.
- **Integration:** `orion scan --engine lm [--model <path>]` replaces the discovery stage; default
  `orion scan` (Claude) is untouched. Leads are emitted in Orion's lead format plus the `path`
  field.
- **Session shape (builder-check call):** CandidateFlows are worked in rank order in batches of K = 5
  per session; each session has its own 8k-token cap and forced `final`. One scan = one session per
  batch, up to a per-scan cap of the top 50 flows (cap and K tuned on dev, then frozen in the
  pre-registration). Tokens are summed across all sessions of a scan. At most one lead per flow.

### 5.2 Training factory (the loop)

```
sources ─► pairs (vulnerable commit, patched commit, fix sites, CWE)
        ─► Joern + Neo4j build of BOTH commits (persisted by scan_id)
        ─► gold traces (scripted)  +  model rollouts (rounds ≥2)
        ─► keep traces that pass the PAIR TEST
        ─► per-step SFT examples ─► Unsloth LoRA (cloud GPU)
        ─► merge ─► mlx_lm.convert -q ─► drop into Orion ─► dev score ─► next round
```

- **Pair test (the training label):** a trace is correct only if it flags the bug on the vulnerable
  commit AND stays silent **at the fix site** on the patched commit (QLCoder/IRIS criterion; "no
  leads anywhere" would be wrong, since a patched repo can still hold other real bugs). Anti-spray:
  gold traces emit only the true lead, and a rollout is rejected if it emits more than one lead that
  does not match the fix site. This is what teaches "judge unknown code".
- **Sources, in order:**
  1. Ready-made pairs: CWE-Bench-Java (120 Java), OpenSSF CVE Benchmark (200+ JS/TS, has pre/post
     patch commits + weakness location), Vul4J (79 Java).
  2. GitHub Security Advisories via OSV, reviewed + CWE + GitHub commit link, injection-type CWEs
     (22, 78, 79, 89, 94, 502, 611, 918, 1321), ≤2 per repo. Fix commits are only plain web links
     in the export — regex `github.com/<owner>/<repo>/commit/<sha>`; vulnerable = parent of the first
     fix commit.
  3. ReposVul (Python/Java) and PYSEC to fill gaps. MoreFixes/CVEfixes only for changed-method
     metadata (MoreFixes runs past the cutoff — date-filter it).
- **Filters:** advisory AND fix before 2026-05-31; fix touches ≤10 files; dedupe by CVE/GHSA alias,
  then (repo id, fix SHA); **drop every repo that appears in a post-cutoff advisory** (research found
  ≈40% of those repos also have pre-cutoff advisories — they would leak).
- **Negatives:** the patched commit of every pair (hard negative, free) + a small Juliet Java sample.
  OWASP Benchmark is **not** used for training (it is the false-alarm test set).
- **Cypher retention:** a small share of Neo4j text2cypher-2025v1 (Apache-2.0) plus Cypher examples
  written against Orion's own schema.
- **Example shape:** one SFT example = "conversation so far → next action", cut step by step from a
  trace.
- **Rounds:** round 1 = gold scripted traces only. Rounds 2–3 add the model's own rollouts: sample
  several runs per pair, keep the **shortest** one that passes the pair test (VulnLLM-R), and retrain
  **from the base model** each round (ReST-EM). Stop after 3 rounds or when dev pair-correct stops
  improving.
- **Size:** set on Day 1 from measured Joern build+load time per commit on the M4. No number is
  committed before that measurement.

### 5.3 Base model — bake-off, not a leaderboard pick

Candidates (fit ≈10 GB with an 8k context; Unsloth-supported; Apache-2.0):

| Candidate | Why | Risk |
|---|---|---|
| Gemma 4 E4B | ~6 GB 4-bit, fast on M4 (community: ~26–34 tok/s), ready Unsloth notebook | Weakest agentic score (Tau2 42) |
| Granite 4.1 8B | Best non-Qwen tool-calling score that fits (BFCL v3 68) | No M4 speed data |
| Gemma 4 12B | Much stronger (Tau2 69, LCB v6 72) | ~9.4 GB peak at 4k; 3–4× slower; 8k may not fit |

Each candidate runs **untrained** through the prompter on dev; measure query-success %, dev recall,
pair-correct, tokens, speed, peak memory; check its training cutoff (§3). Fine-tune the winner.
Ruled out on memory: gpt-oss-20b, ≥14B models. Qwen: see §8.

### 5.4 Eval system (built for attack paths)

**Arms**

| Arm | What | Proves |
|---|---|---|
| `orion-lm` | Trained model + Orion prompter | The entry |
| `orion-lm-base` | Same base, untrained, same prompter | What training added |
| `plain-sonnet5`, `plain-opus5` | Claude Code CLI on the repo, no Orion | Frontier bar |
| `plain-gpt` | Codex CLI on the repo, no Orion | Frontier bar |

The 09-17 arms `orion-gemma4`, `orion-gptoss20b`, `plain-gemma4` (Ollama/`claude -p`) are superseded
on this branch.

**Data sets**
- **Test:** the post-2026-05-31 CVEs (currently 29 candidates in 25 repos; size: see §8.6), each run
  on the vulnerable AND the patched commit. The 09-17 inclusion rules still apply. Access-control
  CWEs (8 of the 29) labeled by protected operation and reported separately.
- **Scale tier (carried over from 09-17):** before the tag, a graph-build pre-check (Joern heap 8 GB,
  no model) on every test commit. A repo whose build fails moves to the scale tier for ALL arms,
  reported separately — decided before any arm runs, so it can't be cherry-picked.
- **False-alarm set:** a stratified sample of OWASP Benchmark — 60 Python v0.1 + 60 Java v1.2 cases,
  balanced real/trap within each category — run as a **targeted judgement** task (the agent is
  pointed at the case's file/entry point and answers vulnerable or not, with the lead). R = 1, all
  five arms. (Whole-app runs would make TPR near zero by design under the 8k/50-flow caps.)
- **Old-CVE check:** a random 20% of OpenSSF + CWE-Bench-Java pairs held out from training; the gap
  vs the new CVEs is the memorization signal. R = 1, all five arms.
- **Budget:** frontier arms are subscription-only (no API billing, as in 09-17); runs pause when a
  usage limit hits and resume after.
- **Dev:** NodeGoat (15 labeled) + a held-out slice of training pairs. Never the test set.

**Harness fixes (must land before any run counts)** — found in the existing `eval/` code:
1. Answer leak: checkouts carry full git history incl. the fix (`eval/repo.py` full clone +
   `fetch --all`). Each run gets a fresh `git archive` tree, no `.git`, no network for agents.
2. Runs 1–3 overwrite each other (`eval/run.py` run_dir lacks the run number; shim `tee -a` mixes
   usage). Use `runs/<arm>/<repo>/<commit>/<run>/`.
3. Plain arms' `findings.json` stays in the shared checkout (`eval/arms/plain.py`). Copy out, then
   discard the tree.
4. Failed runs silently requeued until success (`eval/queue.py`). Record every attempt; a hung or
   crashed run is a miss and its tokens still count.
5. Nothing writes `agent_calls`/`resources` (only tests call the loggers). Wire them in.
6. Codex usage parsed from the wrong level (`eval/usage.py:parse_codex_event`); Claude vs Codex
   cache-token semantics differ. Normalize to {uncached_in, cache_read, cache_write, out,
   reasoning}.
7. `MODEL_TAGS` maps Gemma arms to `gemma3:12b` (moot once those arms are superseded; remove).
8. **`plain-sonnet5` and `plain-opus5` pass no `--model`** (`eval/arms/plain.py:9-15`), so both run
   whatever the CLI default is. Pin the model explicitly per arm and record it in `runs.model_tag`.
9. **Frontier agents can look the answer up online.** Plain Claude arms run with
   `--permission-mode bypassPermissions` and nothing disables web tools; Codex network policy is not
   set. Disallow WebFetch/WebSearch for Claude arms and run Codex without network access (verify the
   flag on the installed CLI), so "no network for agents" actually holds.

**New components (in `eval/`)**

| Component | Job |
|---|---|
| `dataset/manifest.json` v2 | per vuln: vulnerable + patched commit, fix sites, sink or protected operation, accepted entry points + evidence, guard, CWE, labelers + agreement |
| `steps` table | per-step tokens/time/query/rows/error for Orion-LM |
| `normalize.py` | every arm's output → one finding shape with `path:[{file,function,line,role}]` (add `path` to the plain-agent schema before the tag) |
| `match.py` | L1 (frozen rule), L2 (+CWE family), path levels, one-to-one matching; writes a `matches` table |
| `judge.py` | LLM judge for location-less findings + labels unmatched findings (real other bug / false alarm / unsure); calibration (κ and Gwet's AC1 on ≥100 blinded findings); prediction-powered inference for precision |
| `report.py` | tables with CIs, Holm adjustment, pass@3/pass^3, cost-vs-accuracy Pareto plot |

The training loop's dev scoring uses `match.py`, so the matcher is built here (see §8 on the
separate-scoring-session rule).

**LLM judge scope:** the judge is used **only** in the final test scoring (separate session), never
in the training or dev loop — rollout filtering and dev scores use the deterministic matcher only, so
no judge output can enter training selection. The judge is blinded to arm identity, its agreement with
human labels is reported per arm (to expose self-preference), and precision is PPI-corrected. Its
model identity is recorded in the report.

**Path ground truth (cheap, from the fix):** auto-extract fix sites from the diff → find Orion
CandidateFlows through a fix site that disappear on the patched commit → reverse reachability from
fix sites to `:EntryPoint` gives the accepted entry set → a human confirms sink, entry and guard
(adds graph-missed paths; writes "unknown" when unsure) → a second labeler, agreement reported.
Edges missing from Orion's graph (e.g. the arrow-function gap) are checked by a human, so the path
score doesn't favour Orion.

## 6. Pre-registration (frozen by tag `orion-lm-prereg-v1` before any test run)

Unit of analysis = the vulnerability (score = mean of its runs). R = 3 runs per arm per commit.

**Primary**
- **Efficiency:** `E_a = 10^6 · Σ_{v,r} caught_L1 / Σ_{v,r} T`, where T = all input (incl. cache
  reads/writes) + all output (incl. reasoning) tokens. Reported with tool calls and wall time as
  tokenizer-neutral companions.
- **False-alarm rate:** `FAR_a = Σ_{v,r} 1[L1 match on patched_v] / (N·R)`.

**Decision rule**
- Orion-LM beats frontier arm X on efficiency if the Holm-adjusted 95% CI of `log(E_lm / E_X)`
  (paired cluster bootstrap, resample repos, B = 10,000) is above 0.
- And `FAR_lm ≤ FAR_X + margin` (non-inferiority; margin in §8).

**Secondary (reported, not confirmatory):** recall (L1), right-type recall (L2), pair-correct,
Youden J = TPR − FPR on OWASP, path levels (fix traversal, entry hit, edge validity, waypoint F1),
pass@3 and pass^3, labeled false alarms per run with PPI-corrected precision, list-price dollars,
wall time, peak RAM (local arm), graph-build compute (separate).

**Statistics:** cluster bootstrap by repo; exact sign-flip test on per-repo paired differences;
exact McNemar on per-vuln majority as a sensitivity check; Wilson/Jeffreys intervals where there is
no clustering; minimum detectable effect computed from dev variance before the test (Miller eq. 9).
Sampling: each model's recommended non-greedy settings, seed = run number for local arms (distinct
runs, reproducible). Analysis script committed, run on dev output, and its hash put in the tag.

**Matching-rule extensions (added before the tag, logged in `eval/CHANGELOG.md`):** one-to-one
matching (a finding credits at most one vuln), CWE family = exact or one hop in CWE-1000, runs on the
patched commit. L1 itself is unchanged; path metrics are secondary and never change an L1 result.

## 7. Build order (few days)

| Day | Work | Proof it worked |
|---|---|---|
| 1 | Harness fixes 1–7; manifest v2 schema; time ~10 Joern build+load cycles; prompter + MLX runtime; bake-off on dev | Bake-off table with measured speed/memory |
| 2 | Pair builder + filters + leak check; graph builds; gold traces; SFT round 1 on cloud GPU; convert; dev score | Dev pair-correct for base vs round 1 |
| 3 | Rounds 2–3; validator/slicing polish; test-set path labeling (human); judge calibration; tag `orion-lm-prereg-v1` | Tag exists; κ reported |
| 4+ | Test run (sized from Day 1–3 timings; frontier arms run in parallel with local ones); report | Results table + Pareto plot |

Each step follows the existing working agreement: brief plain-language check-in, show real output,
then move on.

## 8. Decisions on the former open questions (Krish, 2026-10-18)

1. **Qwen stays excluded** (no published training cutoff → memorization risk on post-May CVEs).
2. **Second labeler** — Krish asked for a suggestion. **Proposed (Krish to confirm with them): Love
   Kush**, Orion's co-builder. They label every test vuln's answer key (sink, entry point, guard)
   independently from the advisory + fix diff, blind to Krish's labels and to all arm outputs;
   disagreements are resolved by discussion and both the raw agreement (κ) and the resolution are
   recorded. For judge calibration, Krish labels ≥100 blinded findings and the second labeler
   double-labels a random 30% of them. Fallback if Love Kush is unavailable: a security-literate
   peer who has not seen the arm outputs; last resort: single-labeler ground truth, stated as a
   limitation.
3. **False-alarm non-inferiority margin = 5 percentage points.**
4. **Scoring code is built on this branch** (`match.py`/`judge.py`/`report.py`, needed for dev
   scoring in the loop); **human labeling and the final test scoring run in a separate session.**

**From the builder check — decided by Krish 2026-10-18:**

5. **DECIDED: drop the AI-written part.** Context — where the "no Claude/GPT outputs in training" line sits. (a) ~38% of text2cypher-2025v1's
   train split is labelled GPT-4o/GPT-4-turbo/Claude-Opus synthetic, another ~14% Gemini synthetic
   (by `data_source`, checked 2026-10-18: gpt4turbo 5,611 · gpt4o 5,324 · gemini 4,980 · claudeopus
   2,659 · T5-model predictions 456 · provenance unverified 16,436 incl. functional_cypher 13,349 ·
   human crowdsourced/CySpider ≈480, of 35,946);
   (b) the builder is Claude Code, so any Cypher templates/examples it writes become training
   targets. Recommended: drop text2cypher's LLM-synthetic subsets (GPT, Claude, Gemini) and keep the
   rest only if its provenance checks out as non-LLM; Claude writes plumbing code only, while the
   small set of templates that become training targets (Cypher query templates, final-lead
   phrasing) is written or rewritten by Krish.
   **Decision:** all AI-written text2cypher rows (GPT, Claude, Gemini, T5 predictions) are dropped;
   unknown-provenance rows are used only if verified non-LLM (default: not used); Krish writes the
   target templates and the system prompt; Claude writes plumbing code only.
6. **DECIDED: grow the test set to ≈60 dataflow vulns** (Krish: "ok works"). Context — test-set size vs timeline. 29 candidates (≈21 dataflow + 8 access-control), none checked yet.
   Recommended: script-mine post-cutoff advisories (≈600 repos have them) to ≈60 dataflow vulns and
   gate the test run on their answer keys — costs ~1–2 extra days, mostly human labeling.
7. **Timeline slip — decided (Krish):** no cut list; full scope stays in. (Planning note: the test run
   itself is long — rough estimate ~4–8 days of continuous Mac time for the two local arms at
   N≈29–60, plus frontier subscription limits; Day-1 timings replace this estimate.)

## 9. Calls made without explicit sign-off (builder may revisit; Krish please check)

- Gemma 4 E4B as the default if the bake-off is inconclusive (12B too slow/large next to Neo4j).
- MLX-LM runtime (llama-cpp-python fallback); Kaggle/Colab T4 → RunPod fallback for training.
- 8k-token context cap, 25 rows per result, 40 actions per run.
- v1 tools = `run_cypher` + `read_code`; no verifier stage in v1.
- Dataflow (source→sink) bugs first; access-control reported separately.
- Orion upgrades in scope: Cypher validator, path slices + pruned schema (both inside the
  prompter). **Sink coverage is promoted to core:** today's profiles only define sink categories for
  code execution, SQL/NoSQL, redirect, render and log, so ~6 of the 9 target CWEs (22, 79, 502, 611,
  918, 1321) produce no CandidateFlows. An opt-in profile for the Orion-LM arms adds those sink
  categories (seeded from CodeQL models-as-data), measured on Day 1. It changes CandidateFlows only —
  FLOWS_TO and the default profile stay byte-identical. A verified-query library stays stretch.
- Session shape K = 5 flows per session, top-50 flows per scan; pair test = silent at the fix site
  with the anti-spray rule; OWASP as a 120-case targeted-judgement sample at R = 1; scale tier carried
  over; judge kept out of the training loop.
- Extend the existing `eval/` harness rather than migrate to Inspect (it already has 44 tests and a
  run log); borrow Inspect/LangSmith practices (one split per example, code scorers first, binary
  judge, repetitions, local logs).
- Superseding the three Ollama/`claude -p` arms on this branch.
- Old-CVE check = 20% held-out slice of OpenSSF + CWE-Bench-Java.

## 10. Left to the builder

Package layout (suggested: `orion/lm/` for runtime + prompter + tools, `train/` for dataset building,
training notebooks and conversion, `eval/` for the rest); exact prompt wording; LoRA
hyper-parameters; the share of text2cypher in the mix; how many rollouts per pair in rounds 2–3
(bounded by measured speed); bootstrap/plot implementation details; CLI flag names beyond
`--engine lm`.

## 11. Risks

- **Rollout speed.** Self-generated traces on the M4 (~40 actions × several samples × both commits ×
  hundreds of pairs) may take too long. Mitigation: round 1 is scripted-only; rounds 2–3 use a
  small subset, or run rollouts on the rented GPU box with Neo4j there.
- **Joern build time** caps the dataset size; unknown until measured.
- **Recall gap.** Published small-model work shows frontier models still catch more bugs; the
  headline is efficiency + false alarms for that reason, decided before any tuning.
- **Token counts differ by tokenizer**; hence tool calls + wall time as companions.
- **Gemma 4 12B released 2026-06-03** — its training cutoff must be checked before it can be a
  candidate.
- **Final test run length** (5 arms × N commits × 2 versions × 3 runs) may exceed the sprint; sized
  on Day 1.

## References (collected by research agents 2026-10-18 — verify before citing in the paper)

- IRIS https://arxiv.org/abs/2405.17238 · QLCoder https://arxiv.org/abs/2511.08462 ·
  LLMxCPG https://arxiv.org/abs/2507.16585 · VulAgentRL https://arxiv.org/abs/2607.26656 ·
  VulnLLM-R https://arxiv.org/abs/2512.07533 · ReST-EM https://arxiv.org/abs/2312.06585 ·
  PrimeVul https://arxiv.org/abs/2403.18624
- Error bars (Miller) https://arxiv.org/abs/2411.00640 · AI Agents That Matter
  https://arxiv.org/abs/2407.01502 · HAL https://arxiv.org/abs/2510.11977 · τ-bench pass^k
  https://arxiv.org/abs/2406.12045 · PPI https://arxiv.org/abs/2301.09633
- Data: CWE-Bench-Java https://github.com/iris-sast/cwe-bench-java · OpenSSF CVE Benchmark
  https://github.com/ossf-cve-benchmark/ossf-cve-benchmark · Vul4J https://github.com/tuhh-softsec/vul4j ·
  GHSA https://github.com/github/advisory-database · OSV exports
  https://google.github.io/osv.dev/data/ · OWASP Benchmark Java/Python
  https://github.com/OWASP-Benchmark · text2cypher https://huggingface.co/datasets/neo4j/text2cypher-2025v1
- Models/tools: Unsloth Gemma 4 https://unsloth.ai/docs/models/gemma-4 · Granite 4.1
  https://huggingface.co/ibm-granite/granite-4.1-8b · MLX-LM https://github.com/ml-explore/mlx-lm ·
  Outlines MLX https://dottxt-ai.github.io/outlines/latest/features/models/mlxlm/
- Dataset counting scripts, OWASP expected-results CSVs and paper extracts from the research run:
  `/Users/krishkuchroo/Documents/OrionLutherLeo/orion-lm-research/` (outside the repo; OSV zips not
  kept — re-download).

## Appendix A — Integration notes from codebase exploration (2026-10-18)

**A1. Discovery engine seam (orion/)**
- Seam: `cli.py` `_pipeline()` lines ~161–169 — `discover.discover(...)` at 163, `verify.verify_all(...)`
  at 167. Add `--engine {claude,lm}` (default `claude`) + `--model` near cli.py:~235; import MLX lazily
  inside the lm branch only (cli.py imports heavy modules lazily by design).
- New `orion/lm/engine.py`: `discover_lm(scan_id, repo_path, on_event, profile=None, model=None) ->
  list[Lead]`. `repo_for_verify` (`args.repo or "."`) is already in scope for the `read_code` sandbox.
- Verify skipped for lm: emit `verify/done "skipped"`, wrap leads as
  `Verdict(lead, "INCONCLUSIVE", "unverified (engine=lm)")` so `report.render` and `--json` work
  unchanged (or add an UNVERIFIED decision — check `report._ORDER`).
- `Lead` (`contracts.py:19`) has only index/shape/text/evidence/confidence/source_uid/sink_uid. Add
  optional `file, function, line, cwe, path` (default None) — existing constructors/tests keep working.
  Synthesize non-empty `text`/`evidence` (required by `_to_leads` and the verifier); set
  `source_uid`/`sink_uid` from the CandidateFlow so `discover._dedup` dedups structurally.
- Reuse: guard `graphdb._has_write_keyword` (pure regex, no DB); `GraphDB().run_cypher(scan_id, q,
  limit=25)` returns `{row_count, rows}` or `{error}` (prefer it over `mcp_server`, which imports
  fastmcp). EXPLAIN validation and the 25-row cap do NOT exist yet — add in the prompter. Hardening
  option: read-transaction mode (`session.execute_read`) for the lm path; `CALL` procedures are not
  blocked by the keyword guard. Schema text = `strategies.SCHEMA` (lines 15–62); `_PREAMBLE`/`_TRAILER`
  reference `mcp__orion__*` tools — write a fresh lm system prompt. `_profile_block` gives
  `source_examples`/`sink_hints` vocabulary.
- Progress events: reuse the contract in `contracts.py:47–56` (`phase="discover"`, `shape="LM"`,
  `turn=n`, events `query`/`tool`/`lead`/`warn`/`done`/`error`); `monitor` already renders `turn=`.
- The lm prompter must never call `claude_cli`; keep its error-sentinel discipline (a failure is an
  `error` event + zero leads, never a fabricated lead).
- Tests: token-free pytest + monkeypatch. Make the model a swappable `generate(messages) -> str`; drive it
  with scripted JSON actions (run_cypher, read_code incl. `../` rejection, final, malformed JSON, forced
  final at the action cap) against a stub with the `run_cypher(scan_id, q, limit)` signature. Add CLI
  tests: `--engine claude` stays default; lm skips verify. Baseline `pytest -m "not slow"` (75) stays
  green. Key files: cli.py, discover.py, graphdb.py, contracts.py, strategies.py, verify.py, report.py,
  monitor.py, tests/test_discover_parse.py, tests/test_graphdb_guard.py.

**A2. Graph build for the training factory (orion/graph/)**
- Programmatic entry: `graph_build.build(repo_path, language=None, on_event=None, *, stream=False,
  queue_size=64, scan_id=None, mem_stats_path=None, on_batch=None) -> scan_id` (graph_build.py:84).
  NOTE: `build()` defaults to `stream=False` — "streaming is default" is only the CLI flag default; the
  factory must pass `stream=True`. Pass `language=` explicitly (polyglot repos only get a warn event)
  and `scan_id=f"{cve}:{vuln|fixed}"`. Embedding runs only from the CLI, so the factory skips it.
- Multiple scans coexist: `persist._clear` (persist.py:132) deletes only the same `scan_id`; edges are
  scan-keyed. Per-scan cleanup: `MATCH (n {scan_id:$s}) DETACH DELETE n` (no helper exists).
- Traps: `ensure_cpg` reuses an existing `<repo>/cpg.bin` (joern_adapter.py:668-671) — never leave one
  in a checkout; stream temp dirs `orion_cpg_*`/`orion_stream_*` are not removed; `build()` is not
  atomic (a crashed persist leaves a partial scan) and joern-parse failures raise `RuntimeError` — wrap
  each build; run builds sequentially (never parallel Joern).
- Memory: Joern JVM `-Xmx` = 0.75 × RAM (~12 GB) by default → set `ORION_JOERN_HEAP_GB≈8` for batch
  builds with Docker up. Neo4j: 2 GB heap + 1 GB page cache (docker-compose.yml). No code phases Joern
  vs the model — the factory must do it.
- Timing: `_timed` (graph_build.py:30) emits `build/timing` events per phase + a TOTAL line via
  `on_event` — the Day-1 timing measurement hooks in here. No recorded durations exist.
- CandidateFlow props: `scan_id, uid, source_uid, sink_uid, sink_category, path_uids` (JSON string of
  CpgCall uids), `rank`. One BFS-shortest flow per sink; `_MAX_DEPTH=12`, `_MAX_FLOWS=300` are module
  constants; sinks = case-insensitive substring of `profile.sink_hints` (`_classify_sink`, :46).
- Slice material: CpgCall `uid, name, code, method_full_name, file_path, line, column,
  reachable_from_entry, hop_distance, centrality`; CpgMethod `full_name, name, file_path, line` (start
  line only — no end line); EntryPoint `uid, kind, method_full_name, exposure`. FLOWS_TO carries
  `arg_index`; provenance is dropped in `normalize`.
- Mapping a fix diff to nodes: calls via `(c:CpgCall {scan_id:$s, file_path:$f}) WHERE c.line IN
  [a..b]` (check repo-relative path form); enclosing method = greatest `m.line <= a` in the file (same
  trick as `runtime/correlate.py`); vulnerable side uses the diff's old line numbers, patched side the
  new ones. Gold flow = CandidateFlow whose `path_uids` contains a fix-site call uid (parse JSON in
  Python), else variable-length FLOWS_TO from EntryPoint-contained calls to the fix site.
- Opt-in sink profile (stretch): `dataclasses.replace(GENERIC, name=..., sink_hints=...)`; reachable
  only via a new `select_profile` rule or a new `profile=` arg on `build()` (none today). Don't touch
  `request_source_names`/`entrypoint_params_are_sources` (FLOWS_TO 217/1075). New sink categories need
  `_SINK_SEVERITY` entries (else default 3). Parity tripwires are all `@slow` in
  `tests/test_stream_build.py`.

**A3. Eval harness (eval/)**
- `run.main` (run.py:80-107) never calls `repo.prepare`/`repo.vulnerable_commit`; `repo_dir` comes
  from the manifest as-is. `run_one` discards the findings return value (:38). The Orion graph cache
  (:65-69) is keyed by repo only — must become (repo, commit).
- Bug fix shapes: (1) bare mirror cache + `export_tree(mirror, sha, dest)` via `git archive | tar -x`
  into a fresh per-run dir; `vulnerable_commit` must take `-C mirror` (today resolves `fix^` in cwd);
  (2) pass `run_no`+commit into the launcher, `runs/{arm}/{repo}/{commit}/{run_no}`, drop `tee -a` in
  `eval/shim/claude:17`; (3) copy `tree/findings.json` to `json_out`, missing file = failure, call the
  unused `prompt.validate_findings`; (4) `queue.pending` must skip any terminal status, stale
  `running` = crashed, plan tuple gains commit; (5) add an `on_start(proc)` callback to
  `stream_subprocess` so `PhaseSampler` gets the pid, parse each run's own `usage.jsonl` →
  `log_agent_call`, `log_resource` per phase, persist `convert.confirmed_verdicts`; (6) one
  `normalize_usage()` → `{uncached_in, cache_read, cache_write, out, reasoning}` with None when absent
  (Codex: uncached = input − cached; summed per turn; Claude `result` is cumulative) — capture one real
  Codex event as the fixture first; tests in `test_usage.py:18-23` encode the wrong shape; (7)/(8)
  new ARMS list with pinned models; remove Ollama branches in `plain.py:21-30`, `orion_env`, README arm
  table, preflight Ollama checks.
- DB: `CREATE ... IF NOT EXISTS` only, no migrations. Add `PRAGMA user_version` + an ALTER ladder;
  `runs` gains `commit_kind`, `commit_sha`, `UNIQUE(arm, repo, commit_sha, run_no)` (needs a versioned
  rebuild). New `steps` and `matches` tables; `log_step()` next to `log_resource`.
- New in-process arm: `eval/arms/lm.py` `orion_lm_arm(*, tree_dir, model, on_step, ...)`; dispatch on
  `arm in {"orion-lm","orion-lm-base"}` BEFORE the `orion-` prefix test (run.py:63); watchdog thread for
  hangs; launcher contract becomes a result object carrying usage + findings.
- `enrich.commit_meta` (enrich.py:16-21) already fetches the fix commit's file list — extend it to
  return hunks for fix sites. A small `eval/manifest.py` loader/validator shared by `run.main` and
  `check.py`.
- Tests: `from eval import ...`, fresh `tmp_path` SQLite per test, subprocesses faked by injection
  (`popen=`, `run=`, `_orion=`, `_plain=`; `FakePopen` in test_plain.py:5-17), no conftest. Untested
  today: `main`, requeue behaviour, crashed/hung runs. Runner: `./.venv/bin/pytest eval/tests -q`.
