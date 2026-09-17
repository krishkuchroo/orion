# Orion — resume-build prompt

Paste the block below into a **fresh Claude Code session opened in `~/Documents/orion`** (VSCode) to
continue the build exactly where the last session stopped. The spine is done; Tasks A–F remain.

```
You are continuing the build of Orion, a standalone GraphRAG code-security scanner, in
~/Documents/orion. A previous session finished the foundation ("the spine"). Your job is to build
the rest (Tasks A–F) and prove it end-to-end. Do NOT re-litigate architecture — the decisions are
locked (see CLAUDE.md).

READ FIRST (source of truth, in this order):
1. CLAUDE.md — locked decisions + hard-won gotchas (auto-loaded).
2. docs/superpowers/plans/2026-07-18-orion-full-build.md — THE implementation plan and your task
   list. Work it task by task. Each task section has exact files, frozen interfaces
   (Consumes/Produces), TDD steps, and the test to pass.
3. orion/contracts.py, orion/config.py, orion/graphdb.py — the FROZEN spine. Build against these
   exactly; do NOT modify them.

ENVIRONMENT (already set up — verify, don't rebuild):
- Python: ALWAYS use ./.venv/bin/python. All deps installed (neo4j, fastmcp, sentence-transformers,
  lancedb). Do NOT run pip install.
- Neo4j is UP: bolt://localhost:7688 (user neo4j / pass orion_dev_changeme), Community 5.26, native
  VECTOR INDEX confirmed working. Browser at http://localhost:7475. If it's down: `docker compose
  up -d`. Docker Desktop can wedge — if `docker` commands hang, restart Docker Desktop, then retry.
- Joern CLI at ~/joern/joern-cli (joern-parse, joern-export).
- NodeGoat fixture at fixtures/NodeGoat/ with a prebuilt cpg.bin. The graph is NOT loaded into Neo4j
  yet — Task A loads it (you may joern-export the existing cpg.bin instead of re-parsing, to save time).
- `claude` CLI (v2.1.210 here) supports --mcp-config --strict-mcp-config --output-format stream-json
  --json-schema --add-dir --effort.

STATE OF THE FILES:
- DONE, frozen, correct: contracts.py, config.py, graphdb.py, docker-compose.yml, .mcp/orion.json,
  pyproject.toml, CLAUDE.md, tests/test_smoke.py (passes), tests/ground_truth_nodegoat.py, the plan
  doc, orion/graph/__init__.py.
- STALE old skeleton on disk — you will REPLACE these per the plan; do NOT trust their current
  contents: orion/discover.py, verify.py, strategies.py, claude_cli.py, cli.py, report.py, embed.py,
  graph_build.py.
- NOT created yet (the plan adds them): orion/graph/schema.py, joern_adapter.py, persist.py;
  orion/mcp_server.py; orion/monitor.py.

BUILD ORDER (prove each with real output before the next):
1. Task A — fork the Joern→Neo4j builder into orion/graph/, fix the two bugs (add scan_id to the
   RESOLVES_TO/CONTAINS_CALL/DEFINED_IN MERGE keys; stamp file_path onto every CpgCall), single-scan
   clear-and-load. Build the NodeGoat graph and verify counts (CpgFile/CpgCall/FLOWS_TO > 0, no
   cross-scan bleed, the eval() call in contributions.js has a file_path).
2. Task B — FastMCP server (orion/mcp_server.py): read-only run_cypher + semantic_search tools.
3. Task C — async 4-shape discovery fleet over MCP with structured (--json-schema) leads. Never
   treat a subprocess timeout or a pre-ambled reply as a clean FINAL.
4. Task D — independent verifier: fresh claude -p session per lead, --add-dir <repo> for source
   reading, invoking the fp-check plugin. De-risk fp-check-headless FIRST (one probe) before building
   the loop; if it won't load headless, fall back to fp-check's gate-review checklist as prompt text.
5. Task E — semantic index: local jina code embeddings → Neo4j native vector index; wire into
   semantic_search.
6. Task F — report.py + cli.py + monitor.py: `orion scan <repo> [--watch] [--json]` with a live,
   stoppable progress monitor.
7. Integrate + prove — `orion scan fixtures/NodeGoat --watch` end-to-end; run
   scripts/run_nodegoat_eval.py; target >=13/15 vs tests/ground_truth_nodegoat.py at zero obvious
   false positives.

HOW TO EXECUTE:
- Recommended: use the superpowers:subagent-driven-development skill (fresh subagent per task, review
  between tasks). Or superpowers:executing-plans for inline batch execution.
- Tasks B–F are parallel-safe (disjoint files, frozen interfaces) once Task A's graph is loaded — you
  may fan them out with the Agent tool if you want them built simultaneously.

RULES:
- Use ./.venv/bin/python for everything. Run tests with `./.venv/bin/python -m pytest`.
- Tests that spend real Claude tokens (a live claude -p call): write them, mark @pytest.mark.slow,
  run them deliberately (they cost tokens) — not on every iteration.
- Do NOT git commit unless the user asks.
- Prove each phase with real output before moving on. Start with Task A.
```
