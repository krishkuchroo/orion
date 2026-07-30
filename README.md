# Orion

A standalone GraphRAG code-security scanner. Point it at a repository: Orion builds a code graph
from a [Joern](https://joern.io) CPG, a fleet of Claude agents discovers security issues by
reasoning over that graph (grounding every claim with a read-only Cypher query rather than asserting
from memory), and a separate verifier agent independently confirms each lead before it is reported.

The goal is recall on an arbitrary codebase that a fixed rule catalog cannot reach, without the
false-positive flood. On the OWASP NodeGoat benchmark Orion finds 14 of 15 vulnerabilities at zero
false positives, where a deterministic catalog scanner finds none. (The 15th, "components with known
vulnerabilities," needs a CVE feed the current graph does not carry.)

## The one rule that makes it trustworthy

Discovery and verification are different jobs, run by different `claude -p` sessions. The discovery
fleet proposes candidate leads. A separate verifier, which never sees the discovery transcript,
re-derives each lead against the real source (via the `fp-check` skill) and the graph, then returns
`CONFIRM`, `REJECT`, `INCONCLUSIVE`, or `ERROR`. An agent that validates its own guess is grading its
own homework; the session separation is what makes the output defensible without a human on every
scan. A verifier call that crashes becomes `ERROR`, never a silent `CONFIRM`.

## How it works

Three layers:

1. **Build.** `graph_build.build(repo)` runs Joern on the repository (reusing a prebuilt `cpg.bin`
   when present, otherwise `joern-parse` on the source) and normalizes the CPG into a canonical
   8-node, 5-edge schema in Neo4j: `CpgFile`, `CpgMethod`, `CpgCall`, `CpgModule`, `CpgParameter`,
   `CpgReturn`, `EntryPoint`, `Dependency`, with `CONTAINS_CALL`, `RESOLVES_TO`, `DEFINED_IN`,
   `FLOWS_TO`, and `ENTERS_AT` edges. Every node and edge carries a `scan_id` for scan isolation.
2. **Orchestration.** `discover.discover` fans out four discovery "shapes" concurrently (A data-flow,
   B absent-control, C disabled or reverted fix, D pattern and dependency). Each shape is a single
   `claude -p` session that calls the read-only MCP tools `run_cypher`, `semantic_search`, and
   `get_schema`. Leads are deduplicated, then `verify.verify_all` verifies each in its own fresh
   session, several at a time under a concurrency cap.
3. **Harness.** `cli.py` wires it end to end with a live, stoppable progress monitor. `report.py`
   renders a ranked, evidence-cited report, and `scripts/run_nodegoat_eval.py` scores recall.

### Framework-agnostic by construction

Orion ships no framework catalog. Language and framework knowledge lives in one place,
`graph/profiles.py`:

- A profile answers three questions: what counts as an attacker-controlled source, what an entry
  point looks like, and the vocabulary the discovery prompts speak.
- `EXPRESS` formalizes the JavaScript/Express request-object model (`req.*`).
- `GENERIC` is the fallback for any unknown stack. Entry points are detected structurally
  (first-party call-graph roots and callback handlers that take parameters), and those parameters
  are the taint sources, so no request-object naming convention is required. `select_profile()`
  picks EXPRESS when the repository clearly is one, otherwise GENERIC.

Language detection is marker-based (`graph/joern_adapter.py`): `package.json` maps to the JavaScript
frontend, `go.mod` to Go, `pom.xml` to Java, and `requirements.txt` / `setup.py` / `pyproject.toml`
to Python. A repository with more than one marker is flagged rather than guessed silently, and
`orion scan --language <frontend>` overrides detection when needed. Dependencies are parsed from the
same manifests into `Dependency` nodes (`graph/deps.py`), and the discovery prompts anchor on the
populated `:EntryPoint` and `:Dependency` nodes, so an unknown-framework repository works without
anyone writing a profile for it.

Beyond NodeGoat (Express), Orion has been run against PyGoat, a deliberately vulnerable Django and
Flask application it had never seen. The GENERIC profile confirmed 20 findings across both frameworks
in the same repository, including remote code execution, insecure deserialization, server-side
request forgery, server-side template injection, and six known-vulnerable dependencies, with no
framework-specific tuning.

## Getting started on your machine

A full run has four prerequisites. Install them once, then any scan is a single command.

### 1. Install the prerequisites

- **Docker Desktop**, for the graph database. Install it (https://docs.docker.com/get-docker/) and
  make sure it is running. Orion brings up its own Neo4j container, so you do not install Neo4j
  yourself.
- **Python 3.12 or newer.** Check with `python3 --version`.
- **Joern**, the code-analysis engine that produces the CPG. Install it from
  https://docs.joern.io/installation. Orion looks for `joern-parse` and `joern-export` under
  `~/joern/joern-cli`; if yours lives elsewhere, set `JOERN_HOME` to point at it.
- **The Claude Code CLI**, which Orion drives headlessly to do the discovery and verification
  reasoning. Install it with `npm install -g @anthropic-ai/claude-code` (version 2.1.210 or newer),
  then sign in once by running `claude` and following the prompt. A Claude subscription or an API key
  both work.

### 2. Clone Orion

```bash
git clone https://github.com/krishkuchroo/orion.git
cd orion
```

### 3. Start the graph database

```bash
docker compose up -d
```

This starts Orion's own Neo4j Community instance on ports 7688 (Bolt) and 7475 (HTTP), already wired
with a local development password. There is nothing to configure. Open http://localhost:7475 to
confirm it is up.

### 4. Install Orion

```bash
python3 -m venv .venv
./.venv/bin/pip install -e ".[semantic,dev]"
```

Create the virtual environment as `.venv` in the project root exactly as shown: the agents' tool
config (`.mcp/orion.json`) launches the MCP server via `./.venv/bin/python`, so that path has to
exist. The `[semantic]` extra pulls the local embedding model used for semantic search.

Copying the environment file is optional, because every setting already has a working localhost
default:

```bash
cp .env.example .env      # optional
```

### 5. Scan a repository

Point Orion at any local source tree and let it build, discover, verify, and report:

```bash
./.venv/bin/orion scan /path/to/some/repo --watch
```

`--watch` follows the live progress and is stoppable with Ctrl-C. The first scan also downloads the
code-embedding model (a few hundred MB) the first time it indexes, so that step is slower once and is
cached afterward. If you activate the environment with `source .venv/bin/activate`, you can drop the
`./.venv/bin/` prefix and just run `orion scan ...`.

When it finishes, the ranked, evidence-cited report prints to the terminal. Add `--json findings.json`
to also write the verdicts as JSON, and every run records its progress events under
`.orion/runs/<scan_id>/<timestamp>/progress.jsonl`.

### Command reference

```bash
orion scan ./repo                    # build, discover, verify, report
orion scan ./repo --watch            # follow live progress (stoppable with Ctrl-C)
orion scan ./repo --json out.json    # also write verdicts as JSON
orion scan ./repo --language golang  # override language auto-detection
orion scan ./repo --quiet            # suppress per-event prints (still logs to file)
orion scan --scan-id <id>            # re-run against an already-built scan graph
```

### NodeGoat evaluation

Test fixtures (the NodeGoat sample app and its prebuilt CPG) are not committed. Place a repository
with a prebuilt `cpg.bin` under `fixtures/NodeGoat/` to run the build and evaluation locally, then:

```bash
./.venv/bin/python scripts/run_nodegoat_eval.py                  # build and score fixtures/NodeGoat
./.venv/bin/python scripts/run_nodegoat_eval.py --scan-id <id>   # score an existing scan
```

This prints an N-of-15 recall table matched against `tests/ground_truth_nodegoat.py`, plus any
confirmed findings that match no ground-truth item (false-positive candidates).

## Layout

```
orion/
  contracts.py     frozen data contracts (Lead, Verdict, ProgressEvent): the integration spine
  config.py        environment config (Neo4j 7688, model, timeouts, MCP config path)
  graphdb.py       read-only Neo4j access (write Cypher is rejected)
  graph/
    joern_adapter.py  Joern CPG to canonical schema (B2/B3 fixes; entry-point and language detection)
    profiles.py       language and framework profiles: the one place framework knowledge lives
    deps.py           manifest to Dependency nodes (package.json, requirements, pom, go.mod)
    schema.py         canonical node and edge identity plus the batched writer
    persist.py        atomic clear-and-load into Neo4j
  graph_build.py   build orchestration to scan_id
  mcp_server.py    FastMCP server exposing run_cypher, semantic_search, get_schema (all read-only)
  claude_cli.py    headless claude -p driver (MCP, retries with backoff, diagnostics salvage)
  strategies.py    the four discovery shape prompts (framework-agnostic, profile-parameterized)
  discover.py      async four-shape discovery fleet to candidate leads
  verify.py        independent per-lead verifier (fp-check) to a verdict per lead
  embed.py         semantic index (jina code embeddings into a Neo4j native vector index)
  report.py        ranked, evidence-cited output
  monitor.py       live progress log plus the --watch tail
  cli.py           orion scan <repo>
scripts/run_nodegoat_eval.py   full-pipeline recall harness against the 15-vuln ground truth
```

## Testing

```bash
./.venv/bin/python -m pytest -m "not slow"    # fast suite (no Claude tokens); needs Neo4j up
./.venv/bin/python -m pytest -m slow          # live tests that spend real Claude tokens
```

The fast suite covers the builder, the read-only graph guard, the MCP tools, profile and language
selection, report ranking, and the progress monitor. It skips cleanly when Neo4j is not reachable.
