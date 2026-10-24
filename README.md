# Orion

A standalone GraphRAG code-security scanner. Point it at a repository and Orion turns the code into a
graph, has agents look for vulnerabilities by querying that graph, and has a separate verifier
confirm each one before it is reported.

```bash
orion scan /path/to/repo --watch
```

## What it does

1. **Builds a code graph.** [Joern](https://joern.io) parses the repository into a code property graph,
   which Orion loads into its own Neo4j as a small fixed schema (files, methods, calls, parameters,
   entry points, dependencies, and the data flows between calls). At build time it also works out
   which code an attacker can reach from an entry point, which functions are chokepoints, and a
   ranked list of concrete source → sink candidate flows.
2. **Discovers.** Four discovery agents run in parallel, each looking for a different kind of bug:
   data flow, a missing check, a disabled or reverted fix, and risky patterns or dependencies. They
   can only read the graph through three read-only tools (`run_cypher`, `semantic_search`,
   `get_schema`), so every claim is backed by a query result, never asserted from memory.
3. **Verifies.** Each lead goes to a separate verifier that never sees the discovery transcript. It
   re-checks the lead against the real source and the graph and returns `CONFIRM`, `REJECT`,
   `INCONCLUSIVE` or `ERROR`. A verifier call that crashes is `ERROR`, never a silent `CONFIRM`.
4. **Reports.** A ranked, evidence-cited report, plus JSON verdicts and a live, stoppable progress log.

It is framework-agnostic: language and framework knowledge lives in one place
(`orion/graph/profiles.py`), and an unknown stack falls back to a generic profile that treats the
parameters of entry points as untrusted input. Languages are detected from the repository's
manifests (JavaScript/TypeScript, Python, Java, Go); `--language` overrides.

Optional: `--runtime` runs the target after the build and marks the code that actually executed, plus
the calls the static graph missed (off by default; it executes the target on your machine).

**Evidence.** A full scan of the TypeScript project [`pensarai/apex`](https://github.com/pensarai/apex)
(a 160,814-node graph, code Orion had never seen) confirmed 5 vulnerabilities, including a HIGH shell
command injection, and correctly rejected a false positive. The unedited output is in
[`examples/`](examples/).

## How we're upgrading it: Orion-LM

Today discovery and verification run on Claude. The upgrade is **Orion-LM**: a small open-weight model
that runs inside Orion on a laptop, with no cloud model in the loop, and that is trained to use
Orion's graph. `orion scan --engine lm --model <path>` already runs it in place of the Claude discovery
agents (the verifier is skipped for now, so its leads are reported `INCONCLUSIVE`).

| Part | Status |
|---|---|
| **Data**: 4,850 real vulnerability fixes from 13 public sources (no AI-written labels). Each fix becomes the vulnerable function, the same function after the fix, and unrelated functions from the same repo, each with Orion's own context and sink lines. Train and dev are split by repository. | Built: 17,086 examples (`train/`) |
| **Training**: Qwen3.5-4B with LoRA, on a 16 GB Apple M4 through Unsloth's MLX trainer, under a memory guard. First run on a balanced 7,000-row set. | Run C1 in progress |
| **Graph rows**: train on real Orion graphs, so the model learns to read source → sink paths and write its own Cypher. | Next (Stage 2) |
| **Evaluation**: CVEs published after 2026-05-31 (after the training cutoff of every compared model) in real JavaScript/TypeScript, Python and Java repositories, on both the vulnerable and the fixed commit, plus the OWASP Benchmark for false alarms. Orion-LM against frontier models working alone, scored on vulnerabilities found per million tokens and on false-alarm rate. Pre-registered; the test set is run once. | Harness built (`eval/`); no results yet |

Graph work that supports this is done: deterministic precompute, recorded scans (`orion gc`,
`orion reanalyze`), and checks that what Neo4j wrote matches what was built.

## Getting started

You need Docker Desktop (for Neo4j), Python 3.12+, [Joern](https://docs.joern.io/installation)
(looked up under `~/joern/joern-cli`, or set `JOERN_HOME`), and the Claude Code CLI
(`npm install -g @anthropic-ai/claude-code`, signed in once) for the default engine.

```bash
git clone https://github.com/krishkuchroo/orion.git && cd orion
docker compose up -d                                   # Orion's own Neo4j on ports 7688 / 7475
python3 -m venv .venv && ./.venv/bin/pip install -e ".[semantic,dev]"
./.venv/bin/orion scan /path/to/repo --watch
```

Keep the virtual environment at `.venv`: the agents' tool config (`.mcp/orion.json`) starts the MCP
server from `./.venv/bin/python`. Every setting has a working localhost default (`.env.example`).

```bash
orion scan ./repo                          # build, discover, verify, report
orion scan ./repo --json out.json          # also write verdicts as JSON
orion scan ./repo --language golang        # override language detection
orion scan --scan-id <id>                  # re-run on an already-built graph
orion scan ./repo --engine lm --model PATH # Orion-LM (install with .[lm]) instead of Claude
orion gc --keep 5 --dry-run                # list old scan graphs to delete
```

## Layout

```
orion/          the scanner: graph build (graph/), discovery and verification agents, MCP tools,
                report, CLI, runtime stage (runtime/), Orion-LM inference (lm/)
train/          Orion-LM data and training: fix mining, splits, Stage 1 examples, balanced export,
                Mac training (mlx_train.py, guard.py, start_c1.sh)
eval/           the pre-registered evaluation harness: test set, arms, matching, scoring
examples/       committed output of a real scan (apex)
bench/          scripts for running a full scan on a remote machine
docs/           design specs and plans (docs/superpowers/), measured notes (docs/notes/)
```

## Tests

```bash
./.venv/bin/python -m pytest -m "not slow" tests train/tests eval/tests   # no tokens spent
./.venv/bin/python -m pytest -m slow                                     # live, spends real tokens
```

Tests that need Neo4j skip cleanly when it is not running.
