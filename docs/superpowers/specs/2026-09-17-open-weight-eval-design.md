# Open-weight study: does Orion's graph let a free local model out-find frontier models?

**Status:** design (2026-09-17), branch `eval/open-weight-study`. Not yet pre-registered — see §9.
Scoring and human labeling are **out of scope for this branch**: they are built in a separate session
against the run data this design produces (§8).

## 1. The claim, and how it could fail

This is a research study. Every number is measured, never estimated or backfilled, and the result is
reported whichever way it falls. If frontier models win, that is the finding.

| # | Hypothesis | Compared arms | Fails if |
|---|---|---|---|
| H1 | The graph is what helps: the same open-weight model catches more bugs with Orion than without | `orion-gemma4` vs `plain-gemma4` | recall with Orion ≤ recall without |
| H2 | A free open-weight model inside Orion catches as many or more bugs than frontier models working alone | `orion-*` vs `plain-sonnet5`, `plain-opus5`, `plain-gpt` | any frontier arm has higher recall |
| H3 | It is cheaper per bug caught | same as H2 | cost per bug caught is not lower |
| H4 | Orion keeps working on code far larger than the model's context window | all arms, by repo size | open-weight Orion runs fail or lose recall as repo size grows while frontier arms don't |

## 2. Arms

An **arm** is one fixed setup (model + harness) run identically on every repo.

| # | Arm id | Model | Harness | Graph | Settings |
|---|---|---|---|---|---|
| 1 | `orion-gemma4` | Gemma 4 (size that fits 16 GB; tag pinned in Phase 0) via Ollama | Orion (`claude -p` → Ollama) | yes | discovery **and** verifier on this model |
| 2 | `orion-gptoss20b` | gpt-oss-20b via Ollama | Orion (`claude -p` → Ollama) | yes | discovery **and** verifier on this model |
| 3 | `plain-gemma4` | same Gemma 4 tag as arm 1 | Claude Code → Ollama, no Orion | no | plain-agent prompt (§5.2) |
| 4 | `plain-sonnet5` | `claude-sonnet-5` | Claude Code | no | `--effort xhigh` |
| 5 | `plain-opus5` | `claude-opus-5` | Claude Code | no | `--effort xhigh` |
| 6 | `plain-gpt` | `gpt-5.6-sol`, highest reasoning level Codex offers (exact flag confirmed in Phase 0) | Codex CLI | no | plain-agent prompt (§5.2) |

- Open-weight arms never use Codex. Frontier arms never use Orion.
- Gemini is not in the study (not open-weight); Qwen is excluded (no published training cutoff).
- Claude arms run on the Claude Max subscription; `plain-gpt` on the ChatGPT subscription. No API billing.
- Exact model ids/tags, Ollama/Claude Code/Codex versions, and Orion commit are recorded per run. If a
  model is retired or silently changes mid-arm, that arm restarts.

**Training cutoffs (published):** Opus 5 May 2026 · GPT-5.6 Sol Feb 16 2026 · Sonnet 5 Jan 2026 ·
Gemma 4 Jan 2025 · gpt-oss-20b Jun 2024. The latest is **May 2026**, which sets the dataset rule below.

**Run order (sequential):** arm 1 → 2 → 3 on every repo (all local), then 4 → 5 → 6.
**Runs:** 3 per arm per repo. No time or token budget; only hang detection (§5.4).

## 3. Dataset

### 3.1 Inclusion rules (all must hold)

1. Language **JavaScript/TypeScript, Python, or Java** (no Go).
2. Repo is **mid-to-large** (target ≥ 50k first-party LOC, measured with `cloc` at the vulnerable commit).
3. A published advisory (GHSA/CVE) whose **advisory date AND fix-commit date are both after
   2026-05-31**, and no public write-up of the bug before that date (checked: advisory references,
   issue/PR creation dates).
4. A single, localized fix: ≤ 10 non-test files and one vulnerability. Bundled/multi-issue fixes are
   excluded unless the advisory names the exact function.
5. The vulnerable code is in a language Orion builds a graph for (a fix in Svelte/Vue/etc. is excluded).
6. The vulnerable commit (parent of the fix) builds a graph with Joern on the study machine
   (feasibility check; failures are logged and the repo moves to the scale tier or out).

### 3.2 Tiers

- **Headline** — passes every rule. All four hypotheses are tested here.
- **Control** — passes everything except rule 3 (possibly in some model's training data). Reported
  separately; if the gap between arms is the same in both tiers, contamination is not driving it.
- **Scale** — repos too large to build on 16 GB (rule 6 fails). Reported for H4 only, as-is.

### 3.3 Size target and current state

Target: **≥ 30 repos and ≥ 60 headline vulnerabilities**, roughly balanced across the three languages.

Current state (`eval/dataset/candidates.tsv`, from a GitHub Advisory Database sweep of advisories
published 2026-06-01 → 2026-09-17, each fix commit opened via the GitHub API): **29 candidate
vulnerabilities in 18 repos** (9 JS/TS, 11 Python, 9 Java), 8 excluded as bundled fixes, 1 excluded
for a Svelte fix, 1 moved to control (GeoServer: fix commit dated 2025-08-28). None has passed the
full §3.1 check yet. Phase 1 closes the gap to the target.

### 3.4 Manifest and answer key (locked at pre-registration)

`eval/dataset/manifest.json`, one entry per vulnerability:

```
id, tier, repo, language, ghsa, cve, cwe, advisory_published, fix_commit, fix_commit_date,
vulnerable_commit (= fix_commit^), loc_first_party,
answer_key: [{file, function, line_start, line_end}]   # hand-written from the fix diff
answer_key_reviewed_by
```

The answer key is written from the fix diff by one person and checked by a second before the tag.
Repos are cloned once and pinned to `vulnerable_commit`; the same checkout is used by every arm.
The patched commit is also checked out (needed later for the "still reported after the fix" measure).

## 4. Machine and memory plan

All local arms run on the study machine: **MacBook Pro, Apple M4, 16 GB unified memory**, macOS.
Joern (a JVM whose heap defaults to 0.75×RAM ≈ 12 GB, `config.py:26`) and a 13+ GB model cannot both
be resident. The key structural fact (confirmed in `cli.py:_run_scan`): **Joern runs as a subprocess
that exits when the build returns, and only then does discovery start the model.** They are sequential
within one `orion scan`, not concurrent. So the memory plan is configuration, not process surgery:

1. **Cap the Joern heap** — set `ORION_JOERN_HEAP_GB` to a fixed modest value (Phase 0 picks it, start
   ~7) so the build fits under 16 GB instead of claiming 12 GB.
2. **Keep the model from being resident during build** — set `OLLAMA_KEEP_ALIVE=0` so Ollama unloads
   the model when idle; it loads on discovery's first request, after Joern has exited.
3. **Cap Neo4j** — Orion's Neo4j container heap capped (~2 GB) in `docker-compose.yml`.

**Graph reuse (spec-critical).** The graph is model-independent, so it is built **once per repo** and
reused by every later Orion run via `orion scan --scan-id <id>` (which skips the build entirely,
`cli.py:70,107-110`). The harness captures the `scan_id:` line Orion prints on the first build
(`cli.py:79`) and passes `--scan-id` for the other 5 Orion runs of that repo (2 arms × 3 runs − 1
build). This removes 5 of every 6 Joern builds — the largest single memory and time cost — and is what
makes the 16 GB target feasible. Build time/memory are recorded on the one build run and attributed to
it. Plain-agent arms never build. Peak RSS is sampled for every run.

## 5. Harness (what gets built on this branch)

### 5.1 Orion → Ollama wiring

Orion already drives `claude -p --model $ORION_MODEL --effort $ORION_EFFORT`. For open-weight arms
the runner sets `ANTHROPIC_BASE_URL` to Ollama's Anthropic-compatible endpoint, `ORION_MODEL` to the
Ollama tag, and `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL` to the same tag so fp-check's nested
subagents also stay on the open-weight model. No change to discovery/verify prompts or logic.

**Phase 0 gate** — for each open-weight model, a real mini-scan on NodeGoat must show:
MCP tool calls execute (`run_cypher` returns rows), `--json-schema` output parses, fp-check subagents
run on the local model (no call reaches Anthropic), and token usage is reported. If Ollama fails,
retry with llama.cpp `llama-server` (`/v1/messages`). If both fail, stop and redesign; any fallback to
a custom agent loop is a design change and a new pre-registration.

### 5.2 Plain-agent task (arms 3–6)

One prompt and one output schema, identical for all plain arms, committed before the tag, never tuned
per model. The agent runs in the repo checkout with read/search tools and no network, and must write
`findings.json`:

```json
{"findings": [{"file": "", "function": "", "line_start": 0, "line_end": 0,
               "cwe": "CWE-", "title": "", "explanation": ""}]}
```

**Output-shape asymmetry (important).** Orion does **not** emit structured location fields. Its `--json`
output is a list of `Verdict` dicts (`contracts.py:18-45`): `decision` (`CONFIRM`/`REJECT`/…), `reason`,
and a nested `lead` with only `text`/`evidence` free-text — file/line/CWE appear only as prose inside
that text (see `examples/apex/findings.json`). So the two arm families produce genuinely different
shapes and this branch does **not** force them into one. The harness captures each verbatim: plain arms'
`findings.json` as-is, Orion's `--json` verdicts as-is (with a thin CONFIRM filter that preserves the
real fields, never inventing structured ones). Reconciling the two for scoring — extracting file/line
from Orion's prose (the approach `scripts/run_nodegoat_eval.py` already uses: substring + class-keyword
matching over the lead's free text) and flattening the plain arms' fields to comparable text — is the
separate scoring session's job (§8), not this branch's.

### 5.3 Runner

`eval/run.py --arm <id> --repo <manifest id> --run <1..3>`: checks out the pinned commit, applies the
memory phases (§4), launches the arm, streams events into the run log (§6), and writes the arm's raw
output (transcripts, `findings.json`, Orion's report and `progress.jsonl`) under
`eval/runs/<arm>/<repo>/<run>/`. A queue file drives the sequential order in §2 and is resumable: a
completed run is never re-run silently.

### 5.4 Hang detection

No time budget. A run is marked `hung` and stopped only after **60 minutes without any progress
event**. Hung and crashed runs keep whatever partial output exists and are never counted as clean.

## 6. Run log (query on failure)

One SQLite file, `eval/runs.db`:

| Table | Holds |
|---|---|
| `runs` | run_id, arm, repo, tier, run_no, model_tag, cli_versions, orion_commit, started, ended, status (`ok`/`hung`/`crashed`/`error`) |
| `events` | run_id, ts, stage (build/index/discover/verify/agent), level, message |
| `agent_calls` | run_id, session_id, stage, input/output/cache tokens, turns used, turn limit, peak context tokens, exit reason, error head (first 2 KB) |
| `resources` | run_id, phase, wall_seconds, peak_rss_mb, graph_nodes, graph_edges, loc |

A `failures` view joins non-`ok` runs with their error events and failed calls:
`sqlite3 eval/runs.db "select * from failures where arm='orion-gemma4'"`.
Raw artifacts stay on disk, referenced by path. The database is the index, not the evidence.

## 7. What gets recorded (per run, per arm)

Recorded by this branch, straight from the tools' own output. Nothing here is computed from a guess.

- **Findings:** each arm's `findings.json` (and Orion's full verdicts incl. REJECT/INCONCLUSIVE/ERROR,
  so "lost at discovery vs. killed by verifier vs. lost to errors" can be computed later).
- **Tokens:** input, output, cache-read, cache-write per agent call. **Orion's `--json` does NOT carry
  usage** — Orion parses Claude's stream-json internally and discards it (`claude_cli.py`). To capture
  it without modifying `orion/`, the harness puts a **`claude` wrapper shim** first on `PATH` for the
  Orion and plain-Claude arms: the shim `tee`s each call's stream-json (which contains the `result`
  usage block) to a per-run `usage.jsonl`, then passes stdout through unchanged (`set -o pipefail` so
  Orion still sees the real exit code). This also covers the plain-Claude arms uniformly. Codex reports
  usage directly via `codex exec --json` `turn.completed`. If a field is absent it is stored `NULL`.
- **Context:** peak tokens per session, the model's configured window, turns used vs. allowed,
  sessions ending at the context limit.
- **Time and memory:** wall-clock per phase, peak RSS per phase, graph nodes/edges, LOC.
- **Failures:** timeouts, crashes, hung runs, usage-limit hits.
- **Price inputs:** published list prices and a stated GPU/electricity rate, recorded once with source
  and date. Subscription "% of limit used" is recorded only if a CLI exposes it machine-readably;
  otherwise it is dropped, not estimated.

## 8. Out of scope here: scoring and labeling

Built later, in a separate session, over `eval/runs.db` + `eval/runs/` + the manifest:
matching findings to the answer key (caught; caught with the right type; missed), "still reported on
the patched commit", consistency across the 3 runs, cost per bug caught, confidence intervals, and
labeling of unmatched findings. Labeling is **the user (Krish) plus an LLM judge**, with the judge
validated against Krish's labels on ≥ 100 findings and the validation disclosed. This branch only
guarantees that everything those need is captured.

### 8a. Deferred: exploit validation (NOT in this study)

Exploit execution was considered and **postponed to a later, separate study** — it changes the task,
needs each app stood up with its data on a machine larger than the 16 GB study Mac, and would have to
apply to every arm to stay fair. Nothing in this branch runs exploits. What this branch does do is
**keep the record needed to start that study later**: `eval/dataset/candidates.tsv` (and, once locked,
`manifest.json`) is the catalog of every real vulnerability with its repo, fix commit and location, so
a future exploit tier can pick from it without re-mining. Recall here stays location-based; an exploit
tier would only *upgrade* a location match to "provably exploitable," never replace it.

## 9. Pre-registration (to finalize together before any scored run)

Frozen by git tag `eval-prereg-v1`, before the first scored run:

1. The arms table (§2) with exact model tags and effort settings.
2. The dataset manifest with answer keys (§3.4).
3. The plain-agent prompt and output schema (§5.2).
4. The matching rule for "caught" and "caught, right type" (defined now, applied in the scoring session).
5. The hypotheses (§1) and the metric that decides each.

Any later change gets a new tag (`eval-prereg-v2`, …) and a dated reason in `eval/CHANGELOG.md`.

**Matching rule (decided 2026-09-17), item (4):**
- **Caught (location):** a finding matches an answer-key vulnerability iff it names the **same file**
  AND hits the vulnerable function — either the function name matches, or a reported line falls within
  the patched line range ±10. For the plain arms' structured `findings.json` this is a direct compare;
  for Orion's free text it is substring match of the file basename and function name in `lead.text`
  (the `scripts/run_nodegoat_eval.py` approach).
- **Caught, right type:** the above AND the finding's CWE is in the same CWE family as the answer key.
- **Matcher:** a deterministic pass (regex/substring + line window) decides every finding that carries
  a locatable file/line; an LLM judge decides only findings with no clear location, and is validated
  against Krish's own labels on ≥ 100 findings with the agreement reported. Applied in the scoring
  session (§8), frozen here so it cannot be tuned to the results.

## 10. Phases

| Phase | Output | Gate to next |
|---|---|---|
| 0. Feasibility | Ollama models pulled; Orion→Ollama mini-scan on NodeGoat per model; Codex installed and effort flag confirmed; memory phases measured | §5.1 gate passes for both open-weight models |
| 1. Dataset | Expanded sweep; every candidate checked against §3.1 by script + hand; answer keys written and reviewed; feasibility builds | ≥ 30 repos / ≥ 60 headline vulns, or an explicit decision to proceed smaller |
| 2. Harness | Runner, plain-agent prompt + schema, run log, Orion-verdict converter; tested on NodeGoat | one full dry run of all 6 arms on one repo, log queryable |
| 3. Pre-register | `eval-prereg-v1` tag | — |
| 4. Local arms | arms 1→2→3 × all repos × 3 runs | all runs `ok` or explained in `failures` |
| 5. Frontier arms | arms 4→5→6 × all repos × 3 runs | same |
| 6. Hand-off | frozen run data for the scoring session | — |

## 11. Risks

- **Ollama tool calling / structured output through Claude Code may not work** (reported issues). Gated
  in Phase 0 with a llama.cpp fallback.
- **16 GB is tight.** Large repos may not build; they move to the scale tier rather than silently
  dropping. The Gemma 4 size is chosen by what fits, recorded, and not changed after the tag.
- **fp-check inside the verifier** spawns nested subagents that are heavy for a small local model;
  verifier failures are logged per call, and an `ERROR` is never counted as a confirmation.
- **Weeks-long runtime.** Frontier arms run later than local ones; model ids are pinned and recorded
  so drift is visible. Usage-limit hits pause the queue rather than fail runs.
- **Dataset size.** Post-May-2026 advisories with clean, localized fixes in large JS/Python/Java repos
  are limited; if the target isn't reachable, the smaller size is stated, not padded with control rows.
- **Git remote.** `origin` (lutherleo/orion) is currently unreachable from this machine; the branch is
  based on local `Dante` (the most complete copy) and pushed to `krish`.
