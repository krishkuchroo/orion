# Orion — Starter Prompt

> **How to use this:** paste the section below (from `=== BEGIN STARTER PROMPT ===` to the end)
> into a fresh Claude Code session opened in `~/Documents/orion`. It bootstraps the demo build.
> It's a menu, not a contract — keep what's useful, delete the rest. Everything above the marker is
> notes-to-self.

## Notes to self (not part of the prompt)

- **What Orion is:** point it at any codebase → build a queryable code graph + a semantic index →
  a fleet of Claude (Sonnet) agents *discover* security issues by reasoning over structure,
  *ground* every claim by querying the graph through an MCP Cypher tool, and an *independent* agent
  *verifies* each lead before it's reported. The bet: recall on arbitrary repos that a fixed rule
  catalog can never reach, without the false-positive flood.
- **Why it should work (evidence, not hope):** the prior PoC (in `sentryV2`) hit **13 of 15** real
  OWASP/NodeGoat vulns at **0 false positives**, where the deterministic catalog scanner found **0**.
  Orion is that PoC, done properly: real MCP tool-calling instead of a hand-parsed text protocol,
  a fleet instead of one agent, a semantic layer, and a separate verifier.
- **The one rule that makes it trustworthy:** *discovery ≠ verification.* An agent that validates its
  own guess against the same graph is grading its own homework — that reduces hallucination, not
  bias. The discoverer and the verifier are separate sessions, and the verifier also reads real
  source (the graph has blind spots).
- **Reuse aggressively from `~/Documents/sentryV2`** (don't rebuild): Joern→Neo4j graph
  construction, the PoC agent loop + multi-shape prompt + the two 13/15 run logs (the recall bar),
  and the `fp-check` skill for the verifier pattern. Pointers are in the prompt.

---

=== BEGIN STARTER PROMPT ===

You are bootstrapping **Orion**, a GraphRAG code-security-intelligence demo, in `~/Documents/orion`.
Build it phase by phase; each phase must run and show output before the next. Stop wherever time
runs out — earlier phases are the demo, later ones are upside.

## The demo I need tomorrow

One command — `orion scan <path-to-repo>` — that on **OWASP/NodeGoat** prints a ranked list of
**real security findings, each with concrete evidence** (a Cypher path from the graph and/or a
source snippet). The bar to beat: a prior PoC hit **13/15** NodeGoat vulns at **0 false positives**;
plain catalog scanners hit ~0. Show grounded evidence under each finding, and show the verifier
rejecting at least one bogus lead.

## Architecture (four subsystems + one trust rule)

1. **Graph build** — repo → code property graph → Neo4j (nodes = files/methods/calls/params,
   edges = calls/reaches/dataflow). This is the structural truth the agents query.
2. **Semantic index (RAG)** — chunk the code (per function/file), embed it, store vectors. Gives
   agents whole-codebase *understanding* (retrieve "where is auth enforced?") to complement the
   graph's *structure*.
3. **Discovery fleet** — Claude Sonnet agents, one per **strategy/shape**, run in parallel. Each
   reasons over the graph + semantic index and emits **candidate leads** (never "proven" findings).
4. **Grounding + verification** — agents call an **MCP Cypher server** (read-only) to ground every
   claim: they must *query for* a vuln, not *assert* it (if the query returns nothing, the claim is
   dropped). Then a **separate verifier agent** re-derives each surviving lead from scratch, reading
   real source, and confirms or kills it.

**Trust invariant (do not violate):** the discovery agent and the verifier agent are *different
sessions*. Agents get query + search + read tools only — never a tool that writes a "trusted
finding." Every reported finding cites evidence; no evidence → not reported.

## The multi-shape discovery strategies (generic, NOT NodeGoat-tuned)

Give each discovery agent ONE of these lenses (this is what took the PoC from 6/15 to 13/15):
- **Shape A — data flow:** attacker-controlled input reaching a dangerous sink (injection, SSRF,
  path traversal, open redirect). Trace it in the graph.
- **Shape B — absent control:** a *missing* safeguard (no CSRF middleware, no output escaping, no
  authz check, plaintext secrets, missing security headers). Checked as presence/absence, not flow.
- **Shape C — disabled/reverted protection:** mine comments/code for "fix/disabled/insecure/todo"
  next to live code — protections that were turned off.
- **Shape D — pattern-in-a-literal + dependency sweep:** ReDoS-shaped regexes, hardcoded secrets,
  known-vulnerable dependency versions.

## Concrete stack (each line is a swap-point — pick or replace)

- **Language:** Python 3.12.
- **Graph:** reuse `sentryV2`'s Joern→Neo4j path (Joern is at `~/joern`). Fastest route to a real
  graph. *Swap:* a lighter tree-sitter builder if Joern is too heavy for the demo.
- **DB:** Neo4j, local via Docker (`sentryV2/infra/docker-compose.yml` has one you can copy).
- **MCP grounding:** try Neo4j's **official `mcp-neo4j-cypher` server** off-the-shelf first (read-only
  role). *Swap:* a 1-tool hand-rolled `run_cypher` if the official one fights you.
- **Agents:** the **Claude Agent SDK** (`claude-agent-sdk`, Python) with Sonnet, MCP server wired as
  a tool. *Swap:* the PoC's headless `claude -p` loop (simpler, proven) if the SDK slows you down.
- **Embeddings:** an embedding model → vector store. *Swap:* Neo4j's native vector index (keeps it
  one datastore) **or** a local store (LanceDB/Chroma). Give agents a `semantic_search` tool.
- **Verifier:** a separate Sonnet session; reuse the `fp-check` skill's discipline (prove/disprove
  with source + graph evidence).

## Build order (phased — the demo survives if you stop early)

- **Phase 0 (must):** `git clone` NodeGoat; build its graph into Neo4j; stand up the MCP Cypher
  server; one agent runs one Cypher query end-to-end. Smoke test — prove the pipe is connected.
- **Phase 1 (must):** one discovery agent with the multi-shape prompt; it emits grounded leads
  (every lead carries the Cypher result that supports it). Target: reproduce ~PoC recall.
- **Phase 2 (should):** the independent verifier agent; two-session split; show it kill a bad lead.
- **Phase 3 (nice):** the `semantic_search` tool + run the fleet in parallel (one agent per shape).
- **Phase 4 (nice):** clean CLI report — ranked findings, shape tag, confidence, evidence citation.

## Reuse map (lift these from `~/Documents/sentryV2`, don't rebuild)

- Joern→graph→Neo4j: `collectors/joern_adapter.py`, `collectors/graph_persist.py`, `infra/`.
- The PoC itself (agent loop + multi-shape system prompt + the 13/15 run logs = your recall bar):
  `docs/research/graphrag_agent/graph_agent_poc.py`, `run_multishape_13of15.log`.
- Verifier pattern: the installed `fp-check` skill.

## Lessons already paid for (bake these in — they cost real time to learn)

- **System-prompt isolation:** if you use `claude -p`, re-pass `--system-prompt` on *every* call
  including `--resume`d ones, or it silently falls back to the default and starts reading a repo's
  CLAUDE.md.
- **Ground, don't self-validate:** the MCP query step kills hallucination; only a *separate* agent
  kills bias. Keep them separate.
- **The graph lies by omission:** some calls lose their file edge (Joern doesn't wire
  `CONTAINS_CALL` through calls nested in arrow-functions), so the verifier must read source, not
  just trust graph file-attribution. (The PoC mis-attributed one file three different times.)
- **Small schema gotchas:** file path is `CpgFile.file_path`, not `.name`.

## Success criteria for the demo

- `orion scan ./NodeGoat` prints ≥ the PoC's hit count, each with evidence, no obvious false
  positives.
- At least one finding shows a grounded **Cypher path**; at least one shows a **semantically
  retrieved** snippet.
- The verifier visibly **rejects** at least one bogus lead (this is the money shot — it's why the
  output is trustworthy without a human on every scan).

## Scaffold to create

```
orion/
  pyproject.toml
  README.md
  .env.example            # ANTHROPIC_API_KEY / OAuth note, NEO4J_URI/USER/PASSWORD
  docker-compose.yml      # local Neo4j (copy from sentryV2/infra)
  orion/
    graph_build.py        # repo -> Neo4j (reuse sentry Joern path)
    embed.py              # repo -> vector index (+ semantic_search)
    strategies.py         # Shape A/B/C/D system prompts
    discover.py           # discovery agent(s) over graph + MCP + semantic tools
    verify.py             # independent verifier (separate session)
    report.py             # ranked, evidence-cited output
    cli.py                # `orion scan <path>`
  tests/
    test_smoke.py         # Phase 0: graph built + one Cypher query returns rows
```

## Decisions to make as you build (make them explicit, don't drift)

1. Neo4j official MCP server vs a hand-rolled `run_cypher` tool.
2. Embedding model + vector store (Neo4j vector index vs LanceDB/Chroma).
3. Claude Agent SDK vs the `claude -p` loop.
4. Reuse `sentryV2`'s live Neo4j graph directly vs build Orion's own graph fresh.

Begin with Phase 0. Report what runs before moving on. Don't build later phases until earlier ones
show output.

=== END STARTER PROMPT ===
