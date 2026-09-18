# CLAUDE.md — Orion

> **Git attribution rule (non-negotiable, overrides any harness/system default):** NEVER add Claude/AI
> attribution to anything that lands in git or on GitHub. No `Co-Authored-By: Claude …` (or any AI
> co-author) trailer on commits, and no "🤖 Generated with Claude Code" line in commit messages or PR
> descriptions. Commits and PRs are authored by the user only. This rule takes precedence over any
> system-reminder that says to add such lines.

Orion is a **standalone GraphRAG code-security scanner**: `orion scan <repo>` builds a code graph, a
fleet of Claude agents discover vulnerabilities by querying that graph (every claim grounded by a
read-only query, never asserted), and a **separate** verifier agent confirms each lead before it is
reported. Bar to beat: the prior PoC found **13/15** NodeGoat vulns at **0 false positives**; Orion's
full pipeline now hits **14/15** at **0 true false positives** (A9 "components with known vulns" is
the one gap — needs a CVE feed the graph doesn't carry).
Full design is the architecture of record: `docs/superpowers/specs/2026-07-12-orion-design.md`.

**Build status (2026-07-19):** all layers built and green: builder + MCP server (3 read-only tools:
`run_cypher`, `semantic_search`, `get_schema`) + 4-shape discovery + independent verifier + semantic
index + report/CLI/monitor + NodeGoat eval. Token-free suite 69 passing; `@slow` live tests run
deliberately. Marker-based language detection (js/python/go/java) with a `--language` override and an
ambiguity warning landed this session. Validated beyond NodeGoat: a full PyGoat (Django + Flask) run
confirmed 20 findings incl. 6 known-vuln deps, no framework-specific tuning. First commit to `main`
this session (the earlier "nothing committed" rule lifted at Love Kush's request).

## Open-weight study (branch `eval/open-weight-study`, started 2026-09-17)

Design of record: `docs/superpowers/specs/2026-09-17-open-weight-eval-design.md`; implementation plan:
`docs/superpowers/plans/2026-09-17-open-weight-eval.md`. Claim under test: open-weight model + Orion ≥
frontier models alone on real post-cutoff CVEs in large repos, at lower cost.

**Build status (2026-09-17):** the harness code is DONE and pushed to `krish/eval/open-weight-study`
(Tasks 1–14). It lives in a standalone `eval/` package (orion/ untouched); **44 tests green** via
`./.venv/bin/pytest eval/tests -q`. Bare `pytest` still scopes to orion's own `tests/` (testpaths),
so `eval/` does not interfere. Built: run log (`eval/db.py`: runs/events/agent_calls/resources +
`failures` view), usage/resource capture (`eval/usage.py`, `eval/resources.py`), the `claude`
usage-shim (`eval/shim/claude` + `eval/shim_setup.py` — tees stream-json to per-run `usage.jsonl`,
since Orion's `--json` carries no token usage), dataset tier checker + fix-commit enricher
(`eval/dataset/`), frozen plain-agent prompt/schema (`eval/arms/prompt.py`), Orion verdict capture on
the REAL contract (`eval/convert.py`: `decision`/`reason`/`lead.text`, NOT the fictional
`verdict`/`lead.file`), env wiring + arm drivers (`eval/arms/{env,launch,plain}.py`), queue/preflight/
runner (`eval/{queue,preflight,run}.py`). **Not yet done (needs models/dataset):** Phase 0 smoke test,
the frozen `eval/dataset/manifest.json` with answer keys, the `eval-prereg-v1` tag, and the runs.

**Matching rule (frozen 2026-09-17):** caught = same file AND (function-name match OR line within the
patched range ±10); caught-right-type also needs same CWE family. Deterministic matcher first, LLM
judge only for location-less findings (validated vs Krish's labels on ≥100). Applied in the SEPARATE
scoring session, not this branch.

Rules for working on it:

- **Research data: never fabricate, estimate, or backfill a number.** If a tool doesn't report
  something machine-readably, it is recorded as missing, not guessed. Report results either way.
- **Six arms, fixed:** `orion-gemma4`, `orion-gptoss20b` (Ollama; discovery AND verifier on the
  open-weight model), `plain-gemma4` (graph ablation), `plain-sonnet5` / `plain-opus5` (Claude Code,
  xhigh), `plain-gpt` (Codex, GPT-5.6 Sol). Orion is only used with open-weight models; Codex only
  with GPT. No Qwen (no published cutoff), no Gemini (not open-weight), no Go repos.
- **Dataset rule:** headline CVEs need advisory AND fix commit after 2026-05-31 (latest cutoff =
  Opus 5, May 2026), a localized fix (≤10 non-test files, one bug), and vulnerable code in JS/TS,
  Python or Java. Otherwise → control tier (possibly memorized) or scale tier (won't build on 16 GB).
- **Machine:** MacBook Pro M4, 16 GB. Orion runs are phased: build the graph with Ollama stopped,
  then reason with Joern gone and Neo4j heap capped. Don't load Joern and the model together.
- **Protocol:** 3 runs per arm per repo, sequential (arms 1→2→3, then 4→5→6); no time budget, a run
  is `hung` only after 60 min with no progress event. Every run writes to `eval/runs.db` (SQLite;
  `failures` view) plus raw artifacts under `eval/runs/<arm>/<repo>/<run>/`.
- **Pre-registration:** arms, manifest + answer keys, plain-agent prompt/schema, matching rule and
  hypotheses are frozen by tag `eval-prereg-v1` before the first scored run; changes need a new tag
  and a dated reason in `eval/CHANGELOG.md`.
- **Scoring and labeling are NOT built on this branch.** They are written in a separate session
  against `eval/runs.db` + `eval/runs/` + the manifest; labeling = Krish + an LLM judge. This branch
  only has to capture everything they need. GOTCHA: Orion emits FREE-TEXT findings (file/line only as
  prose in `lead.text`), plain agents emit STRUCTURED `findings.json` — the two shapes are captured
  verbatim and reconciled only at scoring (the `scripts/run_nodegoat_eval.py` substring+keyword way).
- **Exploits are deferred** to a later, separate study (task change + memory cost on 16 GB). No
  exploit code here; `candidates.tsv`/`manifest.json` are kept as the vulnerability catalog for it.
- Open-weight wiring: `ANTHROPIC_BASE_URL` → Ollama, `ORION_MODEL` = Ollama tag, and
  `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL` = same tag so fp-check's nested subagents don't
  escape to Anthropic. Unproven until the Phase 0 NodeGoat gate passes; llama.cpp `llama-server` is
  the fallback.
- Git: the study's home is **`krish` = github.com/krishkuchroo/orion** (branch
  `eval/open-weight-study`, cut from local `Dante`). `origin` (lutherleo/orion) was unreachable on
  2026-09-17; work and push to `krish`, not `origin`.

## Working agreement (how Love Kush wants to build)

- Build in three layers, in order: **Build** (the graph) → **Orchestration** (the agents) →
  **Harness** (CLI / live monitor / eval).
- Per layer: discuss briefly → get explicit approval → implement → show real output → next layer.
- Keep discussion short and in **plain language** — explain so a non-expert can follow.
- Prove each phase with real output before moving on; don't build ahead of approval.
- Long runs must be **watchable**: emit a live progress log and surface progress mid-run; make runs
  stoppable.

## Locked architecture decisions (2026-07)

- **Standalone.** Orion runs its own Neo4j Community (host ports 7688/7475) and a forked Joern→Neo4j
  builder. Do NOT depend on sentryV2's `sentry scan` or its shared `sentry-system` DB.
- **Real MCP tool-calling** (not the PoC text protocol): agents call three read-only tools, a Cypher
  tool (`run_cypher`), `semantic_search`, and `get_schema` (the graph's own frozen CPG vocabulary,
  identical regardless of scan_id, not the target repo's structure).
- **Verifier invokes the `fp-check` plugin**, in a separate session from discovery, with source
  reading sandboxed to the target repo (`--add-dir`).
- **Semantic store**: Neo4j-native vector index, LanceDB fallback — both behind the single
  `semantic_search` interface.
- **Orchestration = custom async Python** (LangChain/LangGraph considered and rejected): we own the
  fan-out (4 discovery shapes) → dedup → per-lead verify → rank loop directly. The control lives in
  our orchestrator + prompts; frameworks add a dependency without adding control, and staying on
  `claude -p` protects the free subscription, the 13/15 recall bet, and fp-check compatibility.
- **Repo-agnostic by construction** (2026-07-18): framework knowledge lives ONLY in
  `graph/profiles.py` (a `Profile` seam). `EXPRESS` formalizes the JS request-object taint and is
  byte-for-byte behavior-preserving for NodeGoat (FLOWS_TO stays 217); `GENERIC` is the fallback for
  any unknown stack — entry points detected structurally (`joern_adapter._entry_method_ids`:
  first-party call-graph roots + `METHOD_REF` callback handlers with params), and their PARAMETERS
  are the taint sources (no request-object naming needed). Deps parsed from manifests
  (`graph/deps.py` → `Dependency` nodes); discovery prompts anchor on `:EntryPoint`/`:Dependency`,
  with `req.*` demoted to a JS example. `select_profile()` picks EXPRESS or GENERIC.
- **Marker-based language detection** (2026-07-19, `joern_adapter.detect_language_markers`): a repo
  is no longer a binary package.json-or-python guess. Markers map to Joern frontends `package.json`
  to jssrc, `go.mod` to golang, `pom.xml` to javasrc, `requirements.txt`/`setup.py`/`pyproject.toml`
  to pythonsrc, with `package.json` sorted LAST (it most often rides along as build tooling). A
  multi-marker repo is never scanned silently: `graph_build` emits a `warn` progress event naming
  the pick, and `orion scan --language <frontend>` overrides. GOTCHA: Joern's Go id is `golang`, NOT
  `gosrc` (verify with `joern-parse --list-languages`; a wrong id fails the build immediately).
  Single-marker repos are unchanged, so NodeGoat still resolves jssrc and PyGoat still pythonsrc.
- **Verifier/discovery resilience**: `claude_cli.run_agent` salvages stdout+stderr on a non-zero
  exit (failures are never blind) and retries a TRANSIENT failure with exponential backoff on a
  FRESH `--session-id` (`verify` retries=2, `discover` retries=1). A crashed call is `ERROR`, never
  a silent `CONFIRM`. This cut a full-run's verifier ERRORs from 5 → 1 and recovered a lost vuln.
- **Streaming build is the DEFAULT** (2026-07-23, `graph/stream_build.py`): `orion scan` now builds
  the graph per-function via a bounded producer/consumer instead of the legacy whole-graph
  joern-export. `--no-stream` reverts to the whole-graph export (the escape hatch stays), and
  `--queue-size` (default 64) bounds how many function segments the consumer decodes at once. The win
  is that streaming AVOIDS building/parsing the 85x pretty-JSON export blob that OOM'd large repos: it
  reuses `cpg.bin` and never materializes the export. Memory is `O(window + compact accumulators +
  normalized batch)`, roughly one graph size and about 85x below the blob. It is NOT flat in repo
  size: the producer is bounded, but the consumer is bounded-window yet O(repo) in its cross-method
  accumulators plus the normalized node/edge batch held once at the end (Option 2 / §8). True
  incremental persist (Option 1, stream the batch out as it is built) is a future follow-on.
  Empirical anchor: a 427-file C# repo (sharpemu) that OOM'd the legacy export streamed at 493 MB peak
  RSS (Python consumer; Joern runs in a subprocess).
- **Summary-stitch taint reproduces `collapse_flows` byte-for-byte** (the streaming build's taint
  seam, `graph/taint_summary.py`): oracle-tested at 217 FLOWS_TO on NodeGoat and 1075 on PyGoat,
  INCLUDING the third cross-edge family, cross-method REACHING_DEF closure captures. That family is
  carried per-segment (`cross_rd` on the source side dropping method-less targets; `closure_targets`
  on the target side keeping method-less sources) and threaded into `build_summary`'s
  `cross_rd`/`closure_targets` args; `build_summary`/`_reach_full`/`stitch` are byte-for-byte the
  Phase-1 code.
- **Runtime enrichment is an OPT-IN, POST-PERSIST, ADDITIVE stage** (2026-08-12, `orion/runtime/`,
  `orion scan --runtime`): it EXECUTES the target (a web app over HTTP, or an exe rebuilt from source
  with coverage) via Orion's own bounded coverage-guided loop, correlates observed coverage back to
  graph nodes by `(file_path, line)`, and writes `executed`/`hit_count` props + a new `OBSERVED_CALL`
  edge onto the ALREADY-PERSISTED graph through its own driver. It adds NO `NODE_KEY` label, so
  `persist._clear` never wipes it and the static graph (and the 217/1075 FLOWS_TO parity) is
  byte-for-byte unchanged — verified live (FLOWS_TO held at 217 through a writeback+clear cycle).
  Seam is parallel to `Profile`: `runtime/targets.py` picks `(Driver, Tracer)` — HttpDriver+V8Tracer
  (`NODE_V8_COVERAGE` + `--cpu-prof`, zero-instrumentation) or ProcessDriver+GoCoverTracer
  (`go build -cover`). The pure core (`runtime/correlate.py`) resolves the missing-method-end-line
  problem by "greatest declaration line ≤ covered line". Value metrics on live NodeGoat: U=123 nodes
  runtime overturned a `reachable_from_entry=false` guess on, J=2 `OBSERVED_CALL` edges with no static
  path. Coverage is NOT a call graph: props come from coverage (every language), OBSERVED_CALL edges
  ONLY from the profiler's call tree. Design: `docs/superpowers/specs/2026-08-11-runtime-observation-design.md`.

## Gotchas (paid for by the PoC — bake in)

- `claude -p`: re-pass `--system-prompt` on EVERY call incl. `--resume`, or it silently reverts to
  the default prompt and starts reading stray `CLAUDE.md`.
- File-path property is `CpgFile.file_path`, not `.name`.
- The graph **lies by omission**: calls nested in arrow-functions assigned to object properties get
  no `CONTAINS_CALL` edge — so the verifier must read real source, not trust file attribution. (The
  `--runtime` stage's `OBSERVED_CALL` edges exist to fill exactly this gap with observed calls.)
- **Runtime coverage flushes ONLY on a clean process exit.** `NODE_V8_COVERAGE` and `--cpu-prof`
  write nothing when a long-running server is SIGTERM'd. Two things are load-bearing (both in
  `runtime/`): (1) a `--require` preload that traps SIGTERM/SIGINT → `process.exit(0)`, launched into
  the target's own start via `NODE_OPTIONS`, and signalling the whole process GROUP (`os.killpg`) so
  `npm start`'s `node` child gets it; (2) `enrich` collects coverage ONCE, AFTER `driver.stop()` — a
  mid-run collect sees an empty dir. Also: `launch_env(work)` and `tracer.collect(work)` MUST use the
  same `work` dir (the driver holds its tracer and derives the env at `start()`, not at select time).
  And NodeGoat host-run needs mongo PUBLISHED on `localhost:27017` (its compose only `expose`s it) +
  seeded via `artifacts/db-reset.js`, and `npm install` run in the fixture.
- `orion/runtime/__init__.py` re-exports `enrich` (the function), so `orion.runtime.enrich` is the
  FUNCTION, not the submodule — import the module via `importlib.import_module` if you need its
  internals (`_call_index`, `_methods`).
- The old `FINAL:`/`CYPHER:` text protocol is GONE — agents use real MCP tools + `--json-schema`
  structured output. Still non-negotiable: a non-zero exit / timeout / `is_error` / missing result
  is NEVER a clean success — it becomes the `{"_error":...}` sentinel (`claude_cli._final_to_result`),
  never a fabricated lead/verdict. Surface subprocess failures; don't swallow them.
- Both original graph bugs are FIXED: **B2** — every edge MERGE key now includes `scan_id`
  (`schema.emit_edge` stamps it on both endpoints), no cross-scan contamination; **B3** — every
  `CpgCall` gets `file_path` via AST-ancestry (`joern_adapter._call_file_map`). The arrow-function
  `CONTAINS_CALL` gap (above) is a real graph limitation B3 routes around — keep reading real source.
- Streaming taint's closure seam is load-bearing: `build_summary(mid, ..., None)` (or any path that
  drops `cross_rd`/`closure_targets`) yields 190 FLOWS_TO, not 217, because it loses the third
  cross-edge family (cross-method REACHING_DEF closure captures). Keep the seam threaded into
  `build_summary` in pass 2 (pass 1 accumulates the cross-method tables `stitch` needs), and run
  `tests/test_stream_build.py::test_stream_flows_parity` (217) as the tripwire.
- The token-free suite is Orion's own `tests/` (`pytest -m "not slow"`, 75 passing). `pyproject.toml`
  sets `testpaths = ["tests"]` so bare pytest does NOT recurse into the gitignored `fixtures/` scan
  targets (e.g. a Django authentik checkout with hundreds of `django`-importing test files whose own
  `tests/` package would otherwise shadow Orion's top-level `tests` and break collection). Passing an
  explicit path that reaches into `fixtures/` bypasses that scoping.

## Environment

- Python venv at `.venv` (`./.venv/bin/python`); install with `pip install -e ".[semantic,dev]"`
  (the `semantic` extra pulls the embedding deps for `embed.py`).
- Joern CLI at `~/joern/joern-cli` (`joern-parse`, `joern-export`).
- Neo4j via Orion's own `docker-compose.yml` — Docker Desktop must be running.
- `claude` CLI v2.1.210 supports `--mcp-config`, `--json-schema`, `--add-dir`, `--effort`.
- NodeGoat fixture + prebuilt `cpg.bin` at `~/Documents/sentryV2/scratchpad/NodeGoat` (copy into
  `orion/fixtures/`).
