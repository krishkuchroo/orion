# Orion — Design Spec

## Overview

Orion is a standalone GraphRAG code-security-intelligence tool: point it at any codebase
(`orion scan <path>`) and it prints a ranked list of real security findings, each backed by
concrete evidence — a Cypher path from a code property graph and/or a semantically retrieved
source snippet. It is a production tool for personal/internal use, not a demo or PoC.

It exists because the prior PoC (built inside `~/Documents/sentryV2`, a separate, unrelated
production project) proved that an LLM agent reasoning directly over a code graph — instead of
matching against a fixed catalog of sink/source rules — closes a real recall gap: sentryV2's
deterministic scanner found 0 of NodeGoat's ~15 documented vulnerabilities; a single Claude agent
with one read-only Cypher tool and a multi-shape prompt found 13/15 at zero false positives. Orion
is that PoC rebuilt properly: real MCP tool-calling instead of a hand-parsed text protocol, a
fleet of agents (one per investigation shape) instead of one, a semantic index alongside the
graph, and an independent verifier session instead of self-grading.

## Success Criteria

- `orion scan <path>` runs end-to-end against NodeGoat and matches or beats the PoC's 13/15
  recall, with no obvious false positives.
- At least one reported finding cites a grounded Cypher path; at least one cites a semantically
  retrieved snippet.
- The verifier visibly rejects at least one bogus candidate lead, with its reasoning shown — this
  is the evidence that output is trustworthy without a human reviewing every scan.
- The tool works standalone: cloning just the `orion` repo and running its own setup (no
  dependency on `sentryV2` being present or running) is sufficient.

## Trust Invariant (non-negotiable)

Discovery and verification are different `claude -p` sessions — different `--session-id`s, and
the verifier never receives the discoverer's transcript, only the candidate lead text plus its
own fresh tool access. An agent that checks its own claim against the same graph it used to
generate that claim is grading its own homework; that reduces hallucination, not bias. Every tool
an agent can call is read-only, enforced at the CLI invocation level, not by instruction:

- **Discovery** sessions get `--disallowedTools Bash,Read,Write,Edit,Grep,Glob,WebFetch,WebSearch`
  (matching the PoC) — the Cypher and `semantic_search` MCP tools are the *only* way in. This is
  deliberate, not an oversight: forcing the agent off direct source access is what makes it reason
  over the graph/semantic index rather than just re-deriving a text-search scan.
- **Verification** sessions add sandboxed `Read` access (`--add-dir <target-repo>`, still no
  `Write`/`Edit`/`Bash`) on top of the same Cypher/`semantic_search` tools — specifically so the
  verifier can catch cases where the graph itself lies (see the `CONTAINS_CALL` gap below), which
  a graph-only session structurally cannot catch.

No tool available to any agent, at either stage, can write a "trusted" finding directly — the only
thing that renders output is `report.py`, working from text the agents produced. A finding with no
queried or read evidence is not reported.

## Key Decisions

The starter prompt flagged four open decisions. All four are resolved below; the first two follow
the prompt's own stated plan, the third came from a direct question, the fourth I decided from
facts discovered while exploring the environment (documented so it can be challenged).

### 1. Agent runtime: `claude -p` headless CLI, not the Claude Agent SDK

Orion is personal/internal use only (confirmed with the user). The Claude Agent SDK's
authentication requires an `ANTHROPIC_API_KEY` from the Console — per `code.claude.com/docs`,
Anthropic's terms explicitly prohibit third-party tools running on a Claude Pro/Max subscription's
OAuth token ("does not allow third party developers to offer claude.ai login... for their
products, including agents built on the Claude Agent SDK"). For a personal tool that would only
add billing and ToS risk with no benefit. The installed CLI (`claude` v2.1.207) supports
`--mcp-config` and `--strict-mcp-config` in `--print` mode, so real MCP tool-calling is available
without the SDK — we lose nothing versus the SDK for this use case, and this is the exact
mechanism the validated 13/15 PoC already used (`docs/research/graphrag_agent/graph_agent_poc.py`
in sentryV2).

### 2. MCP Cypher server: try the official server first

Try `neo4j-contrib/mcp-neo4j` (`mcp-neo4j-cypher`) off the shelf, per the starter prompt's own
plan. Fall back to a small hand-rolled `run_cypher` MCP tool (reusing the PoC's write-keyword
regex guard, `_WRITE_KEYWORDS = re.compile(r"\b(CREATE|MERGE|DELETE|SET|REMOVE|DROP|DETACH)\b")`)
if either of these holds: (a) `NEO4J_READ_ONLY=true` can't be verified to actually block writes,
or (b) integrating it via `--mcp-config` costs more time than hand-rolling would.

### 3. Neo4j: fresh, standalone instance — not sentryV2's live graph

Decided from concrete facts found while exploring, not preference:

- sentryV2's `sentry-neo4j` container is running *right now* on the default ports (7474 HTTP,
  7687 Bolt) — a direct collision if Orion tried to stand up its own instance on the same ports.
- It's Neo4j **Enterprise**, multi-database (`sentry-system`, `sentry-reference`,
  `sentry-version`, `sentry-fabric`), and tied to sentryV2's own governance discipline (its
  CLAUDE.md describes a "Wall"/gate-first system that this graph is part of).
- `sentry-system` has a known live bug — `RESOLVES_TO` edges cross-contaminate between scans (90%
  of one scan's edges pointed at a different scan's nodes) — that stems directly from sharing one
  database across many accumulated scans. Reusing that persistence model would inherit the bug
  class, not just the container.
- Orion's whole premise is pointing at *any* codebase, standalone. Coupling its runtime to a
  separate project's production instance is the wrong shape for that, independent of the bug and
  the port collision.

Plan: copy and trim `sentryV2/infra/docker-compose.yml` to Neo4j **Community** Edition (Orion
needs none of Enterprise's multi-database/Fabric/RBAC/clustering features), on different host
ports (7475/7688) so both containers can coexist if ever needed. Orion's graph is scoped to the
**current scan only** — cleared and reloaded at the start of each `orion scan` run, rather than
accumulated across scans like sentryV2's model. This sidesteps the cross-partition bug class by
construction instead of inheriting it, and matches a single-command CLI tool's natural lifecycle.

### 4. Embeddings: Neo4j's native vector index, local embedding model

One datastore instead of two, and it enables genuinely hybrid Cypher queries (graph traversal +
vector similarity in a single query) rather than keeping a second store in sync. Whether vector
indexes are available on Neo4j Community Edition (vs. Enterprise-gated) was ambiguous in current
docs — **this must be verified empirically as the first Phase 0 step**, before anything is built
on top of the assumption. If it turns out to be Enterprise-only, LanceDB is the clean fallback,
since `semantic_search` is exposed as a single tool/function either way — the rest of the system
doesn't need to know which backend answers it.

For the embedding model itself: a local `sentence-transformers`-compatible model, defaulting to
`jinaai/jina-embeddings-v2-base-code` (purpose-built for code, no API key, no added cost or ToS
surface — same reasoning as decision #1). Confirm it actually installs and performs acceptably
during implementation; this is a low-stakes, easily swapped choice behind the single
`semantic_search` interface if it doesn't pan out.

## Components

1. **`graph_build.py`** — repo → Joern CPG → Neo4j. Adapted from sentryV2's
   `collectors/joern_adapter.py` and `collectors/graph_persist.py`, but with a single-scan
   lifecycle (clear-and-load, not accumulate). While porting, fix the known `CONTAINS_CALL`
   collector gap: Joern's collector doesn't wire a `CONTAINS_CALL` edge from `CpgFile` through
   calls nested inside an arrow function assigned to an object property (e.g.
   `this.handler = (req, res) => { eval(req.body.x) }`) — this caused three different wrong
   file-attributions across the PoC's runs. This is a real, independent defect worth fixing
   properly in Orion's copy, not just working around.

2. **`embed.py`** — chunks source per function/file, embeds locally, writes to Neo4j's vector
   index (or LanceDB, per decision #4's fallback), exposes a `semantic_search` MCP tool.

3. **`strategies.py`** — the four investigation-shape system prompts, ported near-verbatim from
   `graph_agent_poc.py`'s `SYSTEM` template (this is what took the PoC from 6/15 to 13/15 recall):
   - **Shape A — data flow**: attacker-controlled input reaching a dangerous sink. Trace
     `FLOWS_TO` edges breadth-first across the whole graph before going deep on any one lead.
   - **Shape B — absence of a control**: nothing to trace; enumerate standard protections
     (CSRF, security headers, output escaping, authz checks, encryption at rest, secure session
     handling) and check each for presence, not assume absence.
   - **Shape C — disabled/reverted protection**: mine `CpgCall.code` and comments for
     "fix/disabled/insecure/todo/temporary/workaround" sitting next to live code.
   - **Shape D — pattern-in-a-literal + dependency sweep**: ReDoS-shaped regex literals
     (nested/overlapping quantifiers) and outdated `:Dependency` versions — neither has anything
     to do with request flow, so a flow-only sweep structurally never finds them.

4. **`discover.py`** — runs each shape as its own `claude -p` session (own `--session-id`), all
   four in parallel. The harness (not the agent) fetches the real file list via Cypher up front
   (`CpgFile.file_path`, not `.name` — a real bug the PoC hit) so turn 1 isn't spent discovering
   what exists. `--system-prompt` is re-passed on *every* call including `--resume`d ones — the
   PoC found that `--resume` alone silently falls back to the default system prompt and starts
   reading whatever repo's `CLAUDE.md` is on disk. Output uses `--output-format json` with
   `--json-schema` for structured candidate leads, replacing the PoC's brittle
   `reply.strip().startswith("FINAL:")` matching (which broke once when the model added a
   preamble sentence). `MODEL=sonnet`, `EFFORT=high`, `MAX_TURNS=40` carried forward unchanged
   from the validated PoC config — no reason to change a number that already produced 13/15 at
   zero false positives.

5. **`verify.py`** — for each surviving candidate lead, a fresh `claude -p` session (new
   `--session-id`, no access to the discoverer's transcript) re-derives it from scratch: reruns
   the grounding query, reads real source via a `Read` tool sandboxed to the target repo (not just
   the graph's file-attribution, because of the `CONTAINS_CALL` gap above — the PoC's own
   mislabeling is direct proof the graph lies by omission), and returns CONFIRMED or REJECTED with
   its own evidence. Modeled on the installed `fp-check` skill's prove/disprove discipline; may
   invoke it directly rather than reimplementing the same logic.

6. **`report.py` + `cli.py`** — ranks confirmed findings, tags each with its shape and
   confidence, cites its evidence (Cypher path and/or semantic snippet), prints to the CLI and
   optionally writes JSON. Explicitly **not** building the resume doc's proposed
   "promotion into a catalog/gate" stage — that machinery exists in the sentryV2 hybrid-
   architecture proposal to feed *sentryV2's own* catalog. Orion doesn't have a catalog of its own
   to promote into yet; building that pipeline now would be premature. If Orion later grows one,
   this is where it would plug in.

## Error Handling

- Neo4j connectivity is checked at CLI startup, before any agent turns run — no point burning
  turns against an unreachable database.
- The Cypher MCP tool catches and returns Cypher errors as tool results (so the agent can adapt
  its next query), rather than crashing the session.
- `claude -p` subprocess failures (non-zero return code, timeout) are caught and surfaced with
  the actual stderr/stdout, not swallowed.
- Structured JSON output is validated against the schema; malformed or incomplete replies are
  logged and surfaced to the user, never silently dropped.
- Joern build failures (unsupported language, timeout on a large repo) fail the scan clearly
  rather than persisting a partial graph silently.

## Testing Strategy

Fast, free, deterministic — real pytest:
- `test_smoke.py` — graph builds and one Cypher query returns rows (Phase 0 exit criterion).
- MCP read-only enforcement — a write-keyword query is rejected.
- Report ranking/formatting logic.
- A **seeded-bad-lead test**: a hand-crafted false candidate is fed directly into `verify.py`
  (bypassing discovery) and must come back REJECTED — this proves the "verifier rejects a bogus
  lead" success criterion without needing a full, costly discovery run to (maybe) produce a bad
  lead to test against.

Slow, real-usage, non-deterministic — a separate eval script, not a unit test:
- `scripts/run_nodegoat_eval.py` — runs the full pipeline against NodeGoat and logs recall against
  the 13/15 bar. Same shape as how the PoC itself was validated (`run_multishape_13of15.log`), and
  for the same reason: it burns real turns and its output isn't deterministic run to run, so it
  doesn't belong in a CI-run test suite.

## Reuse Map (from `~/Documents/sentryV2`)

- `collectors/joern_adapter.py`, `collectors/graph_persist.py` — starting point for
  `graph_build.py` (adapted, not copied as-is — the persistence model changes per decision #3).
- `docs/research/graphrag_agent/graph_agent_poc.py` — direct ancestor of `discover.py`; the
  multi-shape system prompt, the BFS-scaffold-from-harness pattern, and the isolation lessons all
  carry forward.
- `docs/research/graphrag_agent/run_multishape_13of15.log`,
  `docs/research/graphrag_agent/run_shapeA_only_6of15.log` — the recall bar to beat, and a
  reference for what a full transcript actually looks like.
- The installed `fp-check` skill — discipline for `verify.py`.
- `scratchpad/NodeGoat` (already cloned, already has a Joern `cpg.bin` built) — copied into
  Orion's own `fixtures/` rather than referenced in place, so Orion doesn't depend on sentryV2's
  scratchpad (an ephemeral working area, not a stable dependency) surviving or staying in sync.

## Explicit Scope Cuts (YAGNI)

- No promotion/catalog pipeline in `report.py` (see Component 6) — nothing exists yet for it to
  promote into.
- No cross-scan persistence or scan history — each `orion scan` run is self-contained; the graph
  is cleared and reloaded per run (see decision #3). Revisit only if a real need for historical
  comparison across scans shows up.
- No multi-tenant/billing scaffolding — out of scope per decision #1 (personal/internal use).

## Directory Scaffold

```
orion/
  pyproject.toml
  README.md
  .env.example              # NEO4J_URI/USER/PASSWORD only — no ANTHROPIC_API_KEY needed,
                             # claude -p uses the existing OAuth-authenticated CLI session
  docker-compose.yml        # standalone Neo4j Community, ports 7475/7688
  .mcp/
    neo4j-cypher.json        # --mcp-config file wiring the Cypher MCP server
  orion/
    __init__.py
    graph_build.py           # repo -> Joern CPG -> Neo4j (single-scan lifecycle)
    embed.py                 # repo -> Neo4j vector index (+ semantic_search tool)
    mcp_cypher_server.py      # hand-rolled fallback MCP Cypher server (only if needed)
    strategies.py             # Shape A/B/C/D system prompts
    discover.py                # discovery fleet: one claude -p session per shape, parallel
    verify.py                  # independent verifier: fresh claude -p session per lead
    report.py                  # ranked, evidence-cited output
    cli.py                      # `orion scan <path>`
  fixtures/
    NodeGoat/                  # copied from sentryV2/scratchpad/NodeGoat
  tests/
    test_smoke.py
    test_mcp_readonly.py
    test_verifier_rejects_bad_lead.py
    test_report_ranking.py
  scripts/
    run_nodegoat_eval.py      # slow, real-usage recall check against the 13/15 bar
```

## Build Order

Kept as a build/validation sequence, not a "stop early, later phases are optional" scope cut —
the success criteria above require all of it:

1. Verify Neo4j vector index support on Community Edition. Build the graph (Neo4j Community up,
   Joern CPG for NodeGoat persisted, single-scan lifecycle). Stand up the MCP Cypher server.
   Confirm one Cypher query runs end-to-end through it. Exit criterion: `test_smoke.py` passes.
2. One discovery shape running via `claude -p` + real MCP tool-calling, producing grounded,
   structured candidate leads. Exit criterion: reproduces close to the PoC's per-shape recall.
3. `verify.py` as an independent session; prove it rejects a seeded bad lead.
4. All four shapes running in parallel; `embed.py` + `semantic_search` wired in.
5. `report.py` + `cli.py` polish: ranked output, evidence citations, JSON export.
