# Orion kickoff prompt

Paste the block below into a fresh Claude Code session opened in `~/Documents/orion` to continue the
build. The scaffold already exists; this tells the session what it is and where to start.

```
You are continuing Orion, a GraphRAG code-security-intelligence demo in ~/Documents/orion. The
scaffold is already written. Read README.md and STARTER_PROMPT.md first, then the code under orion/.

What exists (skeleton, adapted from a validated PoC):
- orion/graphdb.py     read-only Neo4j access (the grounding tool)
- orion/strategies.py  the multi-shape discovery prompt + the separate verifier prompt
- orion/claude_cli.py  headless `claude -p` driver (isolation + resume lessons baked in)
- orion/discover.py    discovery loop -> candidate leads
- orion/verify.py      independent verifier -> a verdict per lead (separate session, no self-grading)
- orion/graph_build.py builds the graph by reusing Sentry's `sentry scan` (Phase 0)
- orion/cli.py         `orion scan <repo>`
- orion/embed.py       Phase 3 semantic index (stub)
- tests/test_smoke.py  Phase 0 smoke test

Do this in order, proving each phase runs before the next:
1. Phase 0: copy .env.example to .env and set SENTRY_REPO + NEO4J_*. Bring up the Neo4j graph store.
   Run `python -m pytest tests/ -q` and confirm the smoke test passes (graph reachable, run_cypher is
   read-only). If it skips, the DB is not up; fix that first.
2. Phase 1: build a graph and run discovery. `orion scan ./NodeGoat` (needs a NodeGoat checkout and a
   `claude` CLI on PATH). Confirm it produces grounded candidate leads. Target: reproduce the PoC's
   recall (it found 13/15 NodeGoat vulns at 0 false positives).
3. Phase 2: confirm the independent verifier runs and that discovery and verification are genuinely
   separate sessions. Show it REJECT at least one weak lead. Optional: swap the text protocol for
   Neo4j's official MCP Cypher server.
4. Phase 3: build orion/embed.py (semantic index + a semantic_search tool for the agent) and run the
   fleet in parallel, one agent per shape.

Rules: the agents get query and search tools only, never a tool that writes a trusted finding. Every
reported lead cites queried evidence. Keep discovery and verification as separate agent sessions.
Reuse from ~/Documents/sentryV2: the graph builder (it is what graph_build.py shells to) and the
`fp-check` skill for verification. Prove each phase with real output before moving on.
```
