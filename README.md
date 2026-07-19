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
   session.
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

## Setup

Prerequisites:

- **Neo4j.** Orion runs its own Neo4j Community instance via `docker-compose.yml` (host ports 7688
  for Bolt and 7475 for HTTP). Docker Desktop must be running.
- **Joern** CLI at `~/joern/joern-cli` (`joern-parse`, `joern-export`). Set `JOERN_HOME` if it lives
  elsewhere.
- **`claude` CLI** version 2.1.210 or newer on `PATH`, running headless (supports `--mcp-config`,
  `--json-schema`, `--add-dir`).
- **Python** 3.11 or newer, with a virtual environment.

```bash
docker compose up -d                                      # Neo4j on 7688 and 7475
python -m venv .venv && ./.venv/bin/pip install -e ".[semantic,dev]"
cp .env.example .env                                      # optional: defaults already work
```

Test fixtures (the NodeGoat sample app and its prebuilt CPG) are not committed; place a repository
with a prebuilt `cpg.bin` under `fixtures/NodeGoat/` to run the build and evaluation tests locally.

## Run

```bash
orion scan ./path/to/repo                  # build, discover, verify, report
orion scan ./repo --watch                  # follow live progress (stoppable with Ctrl-C)
orion scan ./repo --json findings.json     # also write verdicts as JSON
orion scan ./repo --language golang        # override language detection
orion scan --scan-id <id>                  # re-run against an already-built scan graph
orion scan ./repo --quiet                  # suppress per-event prints (still logs to file)
```

Every run logs its progress events to `.orion/runs/<scan_id>/<timestamp>/progress.jsonl`.

### NodeGoat evaluation

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
