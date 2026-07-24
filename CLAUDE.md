# CLAUDE.md — Orion

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
this session (the earlier "nothing committed" rule lifted at Krish's request).

## Working agreement (how Krish wants to build)

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

## Gotchas (paid for by the PoC — bake in)

- `claude -p`: re-pass `--system-prompt` on EVERY call incl. `--resume`, or it silently reverts to
  the default prompt and starts reading stray `CLAUDE.md`.
- File-path property is `CpgFile.file_path`, not `.name`.
- The graph **lies by omission**: calls nested in arrow-functions assigned to object properties get
  no `CONTAINS_CALL` edge — so the verifier must read real source, not trust file attribution.
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
  cross-edge family (cross-method REACHING_DEF closure captures). Keep the seam wired through BOTH
  passes of `build_envelope`, and run `tests/test_stream_build.py::test_stream_flows_parity` (217) as
  the tripwire.
- The token-free suite is Orion's own `tests/` (run `pytest tests -m "not slow"`, 75 passing). The
  bare `pytest -m "not slow"` recurses into the gitignored `fixtures/` scan targets (e.g. a Django
  authentik checkout with hundreds of `django`-importing test files), whose own `tests/` package also
  shadows Orion's top-level `tests` package and makes even Orion's tests fail to collect. Always scope
  to `tests/`.

## Environment

- Python venv at `.venv` (`./.venv/bin/python`); install with `pip install -e ".[semantic,dev]"`
  (the `semantic` extra pulls the embedding deps for `embed.py`).
- Joern CLI at `~/joern/joern-cli` (`joern-parse`, `joern-export`).
- Neo4j via Orion's own `docker-compose.yml` — Docker Desktop must be running.
- `claude` CLI v2.1.210 supports `--mcp-config`, `--json-schema`, `--add-dir`, `--effort`.
- NodeGoat fixture + prebuilt `cpg.bin` at `~/Documents/sentryV2/scratchpad/NodeGoat` (copy into
  `orion/fixtures/`).
