# Orion Full Build — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Tasks A–F in Phase 1 are **parallel-safe** (disjoint files, frozen interfaces) and may each be executed in its own session.

**Goal:** Ship `orion scan <repo>` end-to-end — a standalone GraphRAG code-security scanner that builds its own code graph, runs a fleet of Claude agents that discover vulnerabilities by querying the graph over MCP, has a separate fp-check verifier confirm each lead, and prints a ranked, evidence-cited report — proven at ≥13/15 recall on NodeGoat at zero false positives.

**Architecture:** Three layers. **Build** (repo → Joern CPG → Orion's own Neo4j Community). **Orchestration** (4 discovery agents fan out in parallel over MCP tools → dedup → per-lead fp-check verifier → rank), all driven by a custom async-Python orchestrator on `claude -p` (no LangChain). **Harness** (`orion scan` CLI + live stream monitor + eval + tests).

**Tech Stack:** Python 3.12+ (venv at `.venv`), Neo4j 5.x **Community** (Docker, ports 7688/7475), Joern (`~/joern/joern-cli`), `claude` CLI v2.1.210 (`--print --mcp-config --output-format stream-json --json-schema`), FastMCP for the tool server, `sentence-transformers` (`jinaai/jina-embeddings-v2-base-code`) + Neo4j-native vector index (LanceDB fallback), `neo4j` Python driver 6.x, pytest.

## Global Constraints

- **Standalone only.** No dependency on sentryV2's `sentry scan` or its `sentry-system` DB. Orion runs its own Neo4j on **bolt://localhost:7688** (HTTP 7475).
- **Single-scan lifecycle.** Each `orion scan` clears its own scan partition and reloads. No cross-scan accumulation.
- **Read-only agents.** Every agent tool is read-only, enforced at the MCP/CLI layer, not by instruction. No tool writes a "trusted finding"; only `report.py` renders output, from text the agents produced. No evidence → not reported.
- **Trust invariant.** Discovery and verification are different `claude -p` sessions (different `--session-id`). The verifier never receives the discovery transcript — only the lead text + fresh tool access.
- **`claude -p` gotchas (non-negotiable):** re-pass `--system-prompt` on EVERY call incl. resumed; never treat a subprocess timeout or a pre-ambled reply as a clean success; surface subprocess failures.
- **Graph truth:** file-path property is `CpgFile.file_path` (never `.name`); **stamp `file_path` directly onto every `CpgCall`** so attribution never depends on the fragile `CONTAINS_CALL` edge.
- **Two graph bugs fixed in the fork:** (B2) add `scan_id` to the MERGE match keys for `RESOLVES_TO`/`CONTAINS_CALL`/`DEFINED_IN`; (B3) the arrow-function-nested `CONTAINS_CALL` gap — mitigated by the `file_path`-on-`CpgCall` rule above.
- **Model config (carried from the validated PoC):** `MODEL=sonnet`, `EFFORT=high`, discovery `MAX_TURNS=40`, verify `MAX_TURNS=10`, per-call `timeout=180s`.

---

## File Structure

```
orion/
  docker-compose.yml            # Neo4j 5.x Community, ports 7688/7475            [Task 0]
  .mcp/orion.json               # --mcp-config wiring run_cypher + semantic_search [Task 0/B]
  orion/
    config.py                   # env config, Orion's own DB defaults              [Task 0]
    contracts.py                # Lead, Verdict, Shape, ProgressEvent (frozen)      [Task 0]
    graphdb.py                  # read-only Neo4j access + clear_scan               [Task 0]
    graph/
      schema.py                 # canonical node/edge labels + emit/validate/uid    [Task A]
      joern_adapter.py          # FORK of sentryV2 (trimmed, 2 bugs fixed)          [Task A]
      persist.py                # MERGE writer, single-scan clear-and-load          [Task A]
    graph_build.py              # repo -> ~/joern -> Orion Neo4j -> scan_id          [Task A]
    mcp_server.py               # FastMCP: run_cypher + semantic_search             [Task B]
    claude_cli.py               # claude -p driver w/ MCP + stream-json parsing     [Task C]
    strategies.py               # Shape A/B/C/D system prompts (adapt existing)     [Task C]
    discover.py                 # async fan-out of 4 shapes -> list[Lead]           [Task C]
    verify.py                   # fp-check verifier, one session per lead           [Task D]
    embed.py                    # semantic index + search                          [Task E]
    monitor.py                  # progress-log reader / live streamer               [Task F]
    report.py                   # ranked, evidence-cited render                     [Task F]
    cli.py                      # orion scan <repo> [--watch] [--json]              [Task F]
  fixtures/NodeGoat/            # copied + prebuilt cpg.bin                          [Task 0]
  scripts/run_nodegoat_eval.py  # full-pipeline recall vs 15-vuln ground truth      [Task G]
  tests/
    test_smoke.py               # graph reachable + read-only (exists, extend)      [Task 0]
    test_graph_build.py         # node/edge counts, no cross-scan bleed, B3 fix     [Task A]
    test_mcp_readonly.py        # write-keyword rejected via MCP                     [Task B]
    test_discover_parse.py      # structured-lead parsing, robust FINAL/timeouts    [Task C]
    test_verifier_rejects_bad_lead.py  # seeded bad lead -> REJECT                  [Task D]
    test_embed.py               # index + search returns relevant chunk             [Task E]
    test_report_ranking.py      # confirmed first, evidence rendered                [Task F]
```

## Execution Model (how the parallelism works)

```
   Phase 0 — SPINE  (single session, ~first)
   freeze contracts.py + config.py + graphdb.py + schema-of-record,
   stand up Neo4j (7688), load a real NodeGoat graph, copy fixture
                 │  (everything below builds against the frozen spine)
   ┌─────────────┼───────────────────────────────────────────────┐
   ▼             ▼             ▼            ▼           ▼          ▼
 Task A       Task B        Task C       Task D      Task E     Task F      Phase 1 — PARALLEL
 builder      MCP server    discovery    verifier    embed      report+CLI  (6 sessions at once)
   └─────────────┴───────────────┴────────────┴───────────┴──────────┘
                 │
                 ▼
   Phase 2 — INTEGRATE + PROVE  (single session)
   Task G eval + Task H end-to-end wiring; prove ≥13/15
```

**Dependency rule:** Tasks A–F depend ONLY on Phase 0's frozen files (`contracts.py`, `config.py`, `graphdb.py`, the schema-of-record, and the `.mcp/orion.json` tool signatures). They do **not** depend on each other's implementations — each consumes the *frozen interface*, stubbing a neighbor where needed. This is what makes them parallel-safe. Files are disjoint per task (see File Structure column).

---

## Phase 0 — The Spine (single session, do first)

### Task 0: Freeze contracts + stand up infra

**Files:**
- Create: `orion/contracts.py`, `docker-compose.yml`, `.mcp/orion.json` (skeleton)
- Modify: `orion/config.py` (own-DB defaults), `orion/graphdb.py` (add `clear_scan`, widen row limit), `tests/test_smoke.py`
- Create: `fixtures/NodeGoat/` (copy from `~/Documents/sentryV2/scratchpad/NodeGoat`)

**Interfaces — Produces (FROZEN; every other task consumes these):**

```python
# orion/contracts.py
from dataclasses import dataclass
from typing import Literal, Callable

Shape = Literal["A", "B", "C", "D"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
Decision = Literal["CONFIRM", "REJECT", "INCONCLUSIVE", "ERROR"]

@dataclass
class Lead:
    index: int
    shape: Shape
    text: str            # the human-readable candidate-lead statement
    evidence: str        # the Cypher/snippet the discoverer cited
    confidence: Confidence

@dataclass
class Verdict:
    lead: Lead
    decision: Decision
    reason: str
    evidence: str = ""   # what the verifier itself queried/read

# A progress event is a plain dict written one-per-line to the run's JSONL log.
# Keys: ts(str ISO), phase("build"|"discover"|"verify"|"report"),
#       shape(str|None), lead(int|None), turn(int|None),
#       event("start"|"query"|"tool"|"lead"|"verdict"|"done"|"error"), detail(str)
ProgressEvent = dict
OnEvent = Callable[[ProgressEvent], None]   # orchestrators call this to emit progress
```

```python
# orion/config.py  (frozen values)
NEO4J_URI      = env("NEO4J_URI", "bolt://localhost:7688")
NEO4J_AUTH     = (env("NEO4J_USER","neo4j"), env("NEO4J_PASSWORD","orion_dev_changeme"))
NEO4J_DATABASE = env("NEO4J_DATABASE", "neo4j")            # Community = single default DB
MODEL="sonnet"; EFFORT="high"; MAX_TURNS=40; VERIFY_MAX_TURNS=10; CALL_TIMEOUT=180
MCP_CONFIG = ".mcp/orion.json"
JOERN_HOME = env("JOERN_HOME", "~/joern/joern-cli")
```

```python
# orion/graphdb.py  (frozen read API; already ~exists, extend)
class GraphDB:
    def ping(self) -> bool: ...
    def files(self, scan_id: str) -> list[str]: ...                 # CpgFile.file_path, sorted
    def run_cypher(self, scan_id: str, query: str, limit: int = 50) -> dict:
        # {"row_count": int, "rows": list[dict]} | {"error": str}; blocks write keywords
    def clear_scan(self, scan_id: str) -> None:                     # NEW: single-scan lifecycle
        # DETACH DELETE all nodes with this scan_id (idempotent)
```

**Schema-of-record (FROZEN — Task A persists exactly this; Task C's prompt text must match it):**

```
Nodes (all carry scan_id):
  (:CpgFile   {scan_id, uid, file_path})
  (:CpgMethod {scan_id, full_name, name, is_external, file_path, line})
  (:CpgCall   {scan_id, uid, name, code, method_full_name, file_path, line, column})  # file_path stamped directly
  (:CpgModule {scan_id, import_name, language})
  (:CpgParameter {scan_id, uid, name, index})
  (:CpgReturn {scan_id, uid})
  (:EntryPoint {scan_id, uid, method_full_name, exposure, kind})
  (:Dependency {scan_id, name, version})          # may be empty for a given scan
Edges (relationship props carry scan_id):
  (:CpgMethod)-[:CONTAINS_CALL]->(:CpgCall)
  (:CpgCall)-[:RESOLVES_TO]->(:CpgMethod)
  (:CpgMethod)-[:DEFINED_IN]->(:CpgFile)
  (:CpgCall)-[:FLOWS_TO {arg_index}]->(:CpgCall)
  (:EntryPoint)-[:ENTERS_AT]->(:CpgMethod)
File attribution: use CpgCall.file_path (stamped) — do NOT rely on CONTAINS_CALL alone.
```

- [ ] **Step 1:** Write `orion/contracts.py` exactly as above.
- [ ] **Step 2:** Update `orion/config.py` to the frozen values (Orion's own DB, not sentry-system).
- [ ] **Step 3:** Write `docker-compose.yml`: `neo4j:5.26-community`, `ports: ["7688:7687","7475:7474"]`, `NEO4J_AUTH=neo4j/orion_dev_changeme`, `NEO4J_PLUGINS=[]`, a named volume. Bring it up: `docker compose up -d`.
- [ ] **Step 4:** Verify vector-index support on Community (R2 check):
  Run: `./.venv/bin/python -c "from neo4j import GraphDatabase as G; d=G.driver('bolt://localhost:7688',auth=('neo4j','orion_dev_changeme')); s=d.session(); print([r['name'] for r in s.run(\"SHOW PROCEDURES YIELD name WHERE name CONTAINS 'vector' RETURN name\")])"`
  Expected: a non-empty list incl. `db.index.vector.queryNodes`. If empty → set `SEMANTIC_BACKEND=lancedb` in the Task E note and proceed (interface is identical).
- [ ] **Step 5:** Add `clear_scan` to `GraphDB` and widen default `run_cypher` limit to 50.
- [ ] **Step 6:** Copy the fixture: `cp -R ~/Documents/sentryV2/scratchpad/NodeGoat fixtures/NodeGoat` (includes its prebuilt `cpg.bin`).
- [ ] **Step 7:** Write `.mcp/orion.json` skeleton (Task B fills the command): `{"mcpServers":{"orion":{"command":"./.venv/bin/python","args":["-m","orion.mcp_server"]}}}`.
- [ ] **Step 8:** Extend `tests/test_smoke.py`: `test_ping` (against 7688) and `test_run_cypher_is_read_only` (a `CREATE` query returns `{"error": ...}`).
- [ ] **Step 9:** Run `./.venv/bin/python -m pytest tests/test_smoke.py -q`. Expected: PASS (or clean skip if DB down — but DB should be up now).
- [ ] **Step 10:** Commit: `git add -A && git commit -m "spine: freeze contracts, stand up Orion Neo4j, load NodeGoat fixture"`.

**Deliverable:** Orion's own Neo4j is up on 7688, `contracts.py`/`config.py`/`graphdb.py` are frozen, the NodeGoat fixture is in-repo, smoke test green.

---

## Phase 1 — Parallel component tasks (one session each)

### Task A: Graph builder fork (Layer 1)

**Files:**
- Create: `orion/graph/schema.py`, `orion/graph/joern_adapter.py`, `orion/graph/persist.py`, `orion/graph_build.py`, `tests/test_graph_build.py`
- Reference (read, adapt — do NOT import): `~/Documents/sentryV2/collectors/joern_adapter.py`, `collectors/framework.py`, `collectors/graph_persist.py`, `collectors/system_store.py`, `dispatch/driver.py:73-75` (`_scan_id`)

**Interfaces:**
- Consumes: `config.JOERN_HOME`, `config.NEO4J_*`, the frozen schema-of-record, `GraphDB`.
- Produces: `graph_build.build(repo_path: str, language: str | None = None) -> str` (returns `scan_id`; clears then loads that scan into Orion's Neo4j, stamping `file_path` on every `CpgCall`).

**Implementation notes:**
- Fork `joern_adapter.py` trimmed to the 7 CPG node labels + 5 edges of the schema-of-record; drop the Dependency/Secret/Finding/etc. universe and the `schema.json` validation — replace with a ~40-line `schema.py` (`emit_node`/`emit_edge`/`synthesize_uid`/`dispatch_to_provenance`).
- `scan_id = sha1(abspath(repo) + "|" + commit_sha_or_'nocommit')` (deterministic, from `dispatch/driver.py:73-75`).
- **Bug B2:** in every edge emit, put `scan_id` into BOTH `from_key` and `to_key` (sentry omits it at `joern_adapter.py:477-478,487-489,494-495`). The persist MERGE MATCH must bind `scan_id` on both endpoints.
- **Bug B3 mitigation:** compute each `CALL`'s owning file from Joern's line/file mapping and stamp it as `CpgCall.file_path` during projection, so file attribution never depends on the `CONTAINS_CALL` edge.
- `persist.py`: `clear_scan(scan_id)` then MERGE all nodes, then all edges; `database="neo4j"`.

- [ ] **Step 1 (test):** `tests/test_graph_build.py::test_build_nodegoat` — call `build("fixtures/NodeGoat")`, assert `>200` CpgCall nodes and `>0` FLOWS_TO edges for the returned scan_id.
- [ ] **Step 2:** Run it: `pytest tests/test_graph_build.py::test_build_nodegoat -v` → FAIL (no `build`).
- [ ] **Step 3:** Implement `schema.py`, `joern_adapter.py` (fork+trim+B2+B3), `persist.py`, `graph_build.py`.
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5 (test B2):** `test_no_cross_scan_bleed` — build twice, assert every `RESOLVES_TO` edge's endpoint `CpgMethod.scan_id` equals the edge's `scan_id`. Run → PASS.
- [ ] **Step 6 (test B3):** `test_call_file_attribution` — assert the `eval(` call node in `contributions.js` has non-null `file_path`. Run → PASS.
- [ ] **Step 7:** Commit `feat(graph): standalone Joern->Neo4j builder with scan_id + file_path fixes`.

**Deliverable:** `build("fixtures/NodeGoat")` populates Orion's graph with correct, scan-isolated, file-attributed nodes.

---

### Task B: MCP tool server (grounding)

**Files:**
- Create: `orion/mcp_server.py`, `tests/test_mcp_readonly.py`; finalize `.mcp/orion.json`
- Depends on package: `fastmcp` (add to `pyproject.toml` optional `mcp` extra)

**Interfaces:**
- Consumes: `GraphDB.run_cypher`, `embed.search` (import lazily; if `embed` raises `NotImplementedError`, `semantic_search` returns `[]` with an `_note`).
- Produces two MCP tools:
  - `run_cypher(query: str, scan_id: str) -> dict` → `{"row_count": int, "rows": list}` | `{"error": str}` (read-only; scan-scoped).
  - `semantic_search(query: str, scan_id: str, k: int = 5) -> list[dict]` → `[{"file","span","text","score"}]`.

**Implementation notes:**
- FastMCP server exposing exactly those two tools; `run_cypher` delegates to `GraphDB(...).run_cypher(scan_id, query)` (write-keyword guard already there). Bind `scan_id` as a Cypher parameter, never string-interpolated.
- `.mcp/orion.json` runs `python -m orion.mcp_server` over stdio.

- [ ] **Step 1 (test):** `test_run_cypher_blocks_writes` — call the tool fn with `"CREATE (n) RETURN n"`, assert `"error"` in result. Run → FAIL.
- [ ] **Step 2:** Implement `mcp_server.py`. Run → PASS.
- [ ] **Step 3 (test):** `test_run_cypher_returns_rows` — a `MATCH (f:CpgFile {scan_id:$scan_id}) RETURN count(f)` returns `row_count>=1` against the loaded NodeGoat scan. Run → PASS.
- [ ] **Step 4:** Manual MCP round-trip: `claude -p --mcp-config .mcp/orion.json --strict-mcp-config --allowedTools "mcp__orion__run_cypher" "call run_cypher to count CpgFile nodes for scan_id X"` → returns a count. Record the exact tool name string (`mcp__orion__run_cypher`) for Task C.
- [ ] **Step 5:** Commit `feat(mcp): read-only Cypher + semantic_search FastMCP server`.

**Deliverable:** an agent can call `mcp__orion__run_cypher` and `mcp__orion__semantic_search`; writes are rejected.

---

### Task C: Discovery fleet (Layer 2 core)

**Files:**
- Modify/rewrite: `orion/claude_cli.py`, `orion/discover.py`, `orion/strategies.py`; Create `tests/test_discover_parse.py`

**Interfaces:**
- Consumes: `contracts.Lead/Shape/OnEvent`, `config.*`, MCP tool names from Task B (`mcp__orion__run_cypher`, `mcp__orion__semantic_search`), `.mcp/orion.json`.
- Produces:
  - `claude_cli.run_agent(session_id, system, message, *, add_dir=None, extra_allowed=(), on_event=None) -> dict` — runs `claude -p` with `--mcp-config .mcp/orion.json --strict-mcp-config --output-format stream-json --json-schema <schema>`, re-passing `--system-prompt` every call, parsing streamed events into `on_event`, returning the final structured JSON.
  - `discover.discover(scan_id: str, on_event: OnEvent) -> list[Lead]` — fans out the 4 shapes concurrently (`asyncio.gather` over `run_agent` in threads), dedups, returns leads.

**Implementation notes:**
- With real MCP tool-calling the CYPHER:/FINAL: text loop is GONE: each shape is ONE `run_agent` call; Claude Code loops internally calling `run_cypher`. `--json-schema` forces the leads array (kills C1/C2). `stream-json` events feed the live monitor: emit `{"event":"tool","detail":query}` on each `run_cypher` tool call, `{"event":"lead",...}` on the final result.
- Disallow native tools for discovery: `--disallowedTools Bash,Read,Write,Edit,Grep,Glob,WebFetch,WebSearch,Agent,Task,NotebookEdit`; allow only the two `mcp__orion__*` tools.
- **Never** treat a subprocess non-zero/timeout as leads — return an explicit error event and an empty list for that shape (fix C3).
- `strategies.py`: keep the existing 4-shape `DISCOVERY_SYSTEM`; update its `SCHEMA` block to the frozen schema-of-record (esp. `CpgCall.file_path`, `CpgMethod-CONTAINS_CALL->CpgCall`). Add the leads JSON schema.
- Dedup rule: leads are the same if `(shape, first 80 chars of text)` collide.

- [ ] **Step 1 (test):** `test_leads_from_structured_output` — feed a sample stream-json final payload to the parser, assert it yields `list[Lead]` with correct shapes. Run → FAIL.
- [ ] **Step 2:** Implement the stream-json parser + `run_agent` + `discover`. Run → PASS.
- [ ] **Step 3 (test):** `test_timeout_is_not_a_lead` — simulate a subprocess timeout, assert `discover` emits an error event and drops that shape (no phantom lead). Run → PASS.
- [ ] **Step 4 (live, cheap):** run ONE shape (A) against the loaded NodeGoat scan; confirm ≥1 grounded lead with a cited query. (Not a unit test — real tokens.)
- [ ] **Step 5:** Commit `feat(discover): async 4-shape fleet over MCP with structured leads`.

**Deliverable:** `discover(scan_id, on_event)` returns grounded, deduped `Lead`s and streams progress.

---

### Task D: Independent verifier (Layer 2 judge)

**Files:**
- Rewrite: `orion/verify.py`; Create `tests/test_verifier_rejects_bad_lead.py`

**Interfaces:**
- Consumes: `contracts.Lead/Verdict/OnEvent`, `claude_cli.run_agent`, MCP tools, the target `repo_path` (for `--add-dir`).
- Produces: `verify.verify_all(scan_id: str, leads: list[Lead], repo_path: str, on_event: OnEvent) -> list[Verdict]` — one fresh session per lead.

**Implementation notes:**
- **De-risk fp-check FIRST (R1):** before building the loop, run one probe — `claude -p --add-dir fixtures/NodeGoat --mcp-config .mcp/orion.json "Use the fp-check skill to verify: <seeded lead>"` — confirm the skill actually loads and runs headless. If it does NOT, fall back: paste fp-check's gate-review checklist (from `~/.claude/plugins/marketplaces/trailofbits/plugins/fp-check/skills/fp-check/references/gate-reviews.md`) into `VERIFY_SYSTEM` as static text. Record which path was taken in the commit message.
- Verifier session: separate `--session-id`; gets MCP tools + `--add-dir <repo_path>` (sandboxed `Read`/`Grep`/`Glob`; if invoking fp-check, also allow `Task`); still NO `Write`/`Edit`/`Bash`.
- Verdict parsing: force `--json-schema {decision, reason, evidence}`; map to `Verdict`.

- [ ] **Step 1 (test):** `test_seeded_bad_lead_rejected` — construct a `Lead` claiming a vuln in a file/line that does not exist in the NodeGoat graph; assert `verify_all` returns `decision == "REJECT"`. (Real tokens — mark `@pytest.mark.slow`, run explicitly.)
- [ ] **Step 2:** Run the fp-check probe; implement `verify_all` on the chosen path. Run the slow test → PASS (REJECT).
- [ ] **Step 3 (test):** `test_verdict_schema_parsing` (pure unit, no tokens) — parse a sample verdict payload → `Verdict`. Run → PASS.
- [ ] **Step 4:** Commit `feat(verify): independent fp-check verifier with sandboxed source read`.

**Deliverable:** `verify_all(...)` confirms/rejects each lead in an isolated session and visibly rejects a bogus one.

---

### Task E: Semantic index (Layer 2 retrieval)

**Files:**
- Rewrite: `orion/embed.py`; Create `tests/test_embed.py`; add `semantic` extra deps.

**Interfaces:**
- Consumes: `config.*`, `GraphDB` (to read `CpgMethod`/`CpgFile` spans), backend flag `SEMANTIC_BACKEND` (`neo4j`|`lancedb`).
- Produces: `embed.index(repo_path: str, scan_id: str) -> None`; `embed.search(query: str, scan_id: str, k: int = 5) -> list[dict]` → `[{"file","span","text","score"}]` (the exact shape Task B's `semantic_search` returns).

**Implementation notes:**
- Chunk per method (use `CpgMethod.file_path`+`line` for spans) or per file if no methods; embed with `sentence-transformers` `jinaai/jina-embeddings-v2-base-code` (local, no API key).
- Backend behind one interface: `neo4j` → write `embedding` on nodes + `db.index.vector.queryNodes`; `lancedb` → a local table. Chosen by Phase 0 Step 4's result.

- [ ] **Step 1 (test):** `test_index_and_search` — index `fixtures/NodeGoat` for a scan_id, `search("where are user passwords compared", scan_id)` returns a chunk whose `file` contains `user-dao`. (Mark `@pytest.mark.slow`.)
- [ ] **Step 2:** Run → FAIL. Implement `index`/`search`. Run → PASS.
- [ ] **Step 3:** Commit `feat(embed): local code-embedding semantic index + search`.

**Deliverable:** `search(...)` returns relevant code chunks; wired into Task B's `semantic_search`.

---

### Task F: Report + CLI + live monitor (Layer 3)

**Files:**
- Create: `orion/monitor.py`; Rewrite: `orion/report.py`, `orion/cli.py`; Create `tests/test_report_ranking.py`

**Interfaces:**
- Consumes: `contracts.Verdict/ProgressEvent/OnEvent`, `discover.discover`, `verify.verify_all`, `graph_build.build`, `embed.index`.
- Produces:
  - `monitor.run_logger(run_dir: str) -> OnEvent` — returns an `on_event` that appends JSONL to `run_dir/progress.jsonl` AND prints a one-line human summary.
  - `monitor.tail(run_dir: str) -> None` — live `--watch` view (re-reads the JSONL, renders turns/leads/verdicts).
  - `report.render(verdicts: list[Verdict]) -> str` — confirmed first, evidence under each.
  - `cli.main()` — `orion scan <repo> [--scan-id ID] [--watch] [--json OUT] [--quiet]`.

**Implementation notes:**
- `cli.scan` flow: `build(repo)` (unless `--scan-id`) → `embed.index` → `on_event=run_logger(...)` → `discover` → `verify_all` → `report.render` → print + optional JSON. When `--watch`, run the pipeline in a thread and `monitor.tail` in the foreground.
- `report` order: `CONFIRM < INCONCLUSIVE < REJECT < ERROR`; show shape tag, confidence, evidence.

- [ ] **Step 1 (test):** `test_report_ranks_confirmed_first` — feed mixed `Verdict`s, assert CONFIRM appears before REJECT and evidence is present. Run → FAIL.
- [ ] **Step 2:** Implement `report.py`, `monitor.py`, `cli.py`. Run → PASS.
- [ ] **Step 3 (test):** `test_monitor_roundtrip` — write 3 events via `run_logger`, assert `tail` renders them. Run → PASS.
- [ ] **Step 4:** Commit `feat(harness): orion scan CLI, live monitor, ranked report`.

**Deliverable:** `orion scan --watch` runs the pipeline with a live, stoppable monitor and prints a ranked report.

---

## Phase 2 — Integrate + Prove (single session)

### Task G: NodeGoat eval harness

**Files:** Create `scripts/run_nodegoat_eval.py`, `tests/ground_truth_nodegoat.py` (the 15-vuln list).

**Interfaces:** Consumes the whole pipeline. Produces a recall report vs the 15 ground-truth vulns.

- [ ] **Step 1:** Encode the 15 ground-truth vulns (from the design spec / NodeGoat tutorial) as `{id, name, file_hint}`.
- [ ] **Step 2:** `run_nodegoat_eval.py`: run `orion scan fixtures/NodeGoat`, match confirmed findings to ground truth by file+class, print `N/15` + which missed.
- [ ] **Step 3:** Commit `test(eval): NodeGoat recall harness`.

### Task H: End-to-end wiring + proof

- [ ] **Step 1:** `orion scan fixtures/NodeGoat --watch` runs clean end-to-end (build → discover → verify → report) with the live monitor.
- [ ] **Step 2:** Run `scripts/run_nodegoat_eval.py`; **target ≥13/15 at zero obvious false positives**. If short, inspect misses (expect A9/deps as a known data-gap) and tune the shape prompts, not the graph.
- [ ] **Step 3:** Full suite green: `pytest -q` (fast tests) + the `@slow` tests run explicitly.
- [ ] **Step 4:** Update `README.md` run instructions (7688, `orion scan`, `--watch`). Commit `docs: standalone run instructions`.

**Deliverable:** one command, watchable, proven at the recall bar.

---

## Self-Review

**Spec coverage:** Build (Task A + 0) ✓; own Neo4j (0) ✓; 2 bug fixes (A) ✓; real MCP (B) ✓; 4-shape parallel discovery (C) ✓; fp-check verifier + source read (D) ✓; semantic index + RRF hook (E — RRF fusion lands where `semantic_search` entry points feed discovery; noted as a follow-up if time) ✓; report+CLI+monitor (F) ✓; eval ≥13/15 (G/H) ✓; tests (each task) ✓; single-scan lifecycle (0/A) ✓; trust invariant (C/D separate sessions) ✓.

**Placeholder scan:** none — every task has exact files, frozen interface signatures, and an exact test command. Ported code is "adapt from `<path:lines>`" with the specific transformation named (trim to schema-of-record; add scan_id to keys; stamp file_path).

**Type consistency:** `Lead`/`Verdict`/`Shape`/`OnEvent` defined once in `contracts.py`; `run_cypher`/`semantic_search`/`search`/`build`/`discover`/`verify_all`/`render` signatures are stated identically in producer and consumer blocks. `semantic_search` (B) and `search` (E) share the `{file,span,text,score}` shape.

**Known follow-up (not blocking the bar):** RRF fusion of semantic + graph entry points is a discovery-quality enhancement; the 13/15 bar was hit graph-only, so it ships as a tuning step in Task H, not a gate.
