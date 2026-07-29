# Orion remote scan kit

Run a **full Orion vulnerability scan** on a remote Ubuntu box with an NVIDIA GPU.

Orion builds a code graph of a target repository (Joern → Neo4j), a fleet of Claude agents discovers
candidate vulnerabilities by querying that graph, and a **separate** verifier agent independently
re-derives each lead against the real source before it is reported. This kit provisions the machine
and drives that pipeline end to end.

This branch (`remote-bench`) is the `Grendel` build of Orion plus this `bench/` directory. **No Orion
source is modified** — the one transformers-compat shim needed for the GPU embedding model lives in
`bench/orion_scan.py`, not in `orion/`.

---

## 1. Clone and provision (one time)

```bash
git clone https://github.com/lutherleo/orion.git
cd orion
git checkout remote-bench
bash bench/setup.sh
```

`bench/setup.sh` installs, all user-local except Docker: **JDK 21** (Temurin), **Joern**
(`~/joern/joern-cli`), **uv** + a project `.venv` (Orion + semantic extras, with `transformers<5`
pinned for the jina embedding model), the **Claude Code CLI** (`~/.local/bin/claude`), and brings up
**Neo4j** via the repo's `docker-compose.yml` (Bolt on `localhost:7688`). It prints
`CUDA available: True` if the GPU is wired up for embeddings, and writes `bench/env.sh` for the run
scripts.

Prerequisites it assumes: Ubuntu, `sudo`, and an NVIDIA driver already installed (`nvidia-smi`
works). Docker is installed for you if absent.

## 2. Authenticate the Claude CLI (one time)

The discovery and verifier agents drive the headless `claude` CLI, so it must be logged in on this
box. Either:

```bash
claude          # interactive OAuth login (Claude subscription), OR
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> bench/env.sh   # API-key billing
```

Verify:

```bash
claude -p --output-format stream-json --verbose "reply OK"
```

A clean `"result":"OK"` means you're set.

## 3. Run a scan

```bash
bash bench/scan.sh /path/to/target/repo
```

Watch it live in a second shell:

```bash
./.venv/bin/python bench/scan_watch.py
```

Options (anything after the repo path passes through to `orion scan`):

| Flag | Effect |
|---|---|
| `--no-semantic` | Skip the GPU semantic index — graph-only discovery. Faster/lighter; slightly lower recall. |
| `--language jssrc` | Pin the Joern frontend (`jssrc` / `pythonsrc` / `golang` / `javasrc`) instead of auto-detecting. |
| `--queue-size N` | Functions held in flight by the streaming build (default 64). |

## 4. Read the results

Each run writes to `bench/runs/<timestamp>/`:

- **`findings.json`** — one verdict per candidate lead: `CONFIRM` (a real, independently verified
  vulnerability, with cited file/line + the query that grounds it), `REJECT`, `INCONCLUSIVE`, or
  `ERROR`. The **CONFIRMs are the findings.**
- **`report.log`** — the ranked, human-readable report Orion prints at the end.
- **`scan.stderr.log`** — diagnostics.

The live log (`.orion/runs/<scan_id>/<ts>/progress.jsonl`) has every build timing, discovery lead,
and verifier verdict as structured JSONL if you want to post-process a run.

---

## How it works (the pipeline `scan.sh` runs)

1. **Build** — Joern parses the target into a CPG, streamed per-function into a canonical
   8-node/5-edge graph in Neo4j (every node/edge stamped with a `scan_id`). This is the Grendel
   build: a chunked, bounded-transaction persist that scales to large repos where the older
   whole-graph persist runs Neo4j out of transaction memory.
2. **Semantic index** — code chunks are embedded (GPU) into a Neo4j-native vector index, powering the
   agents' `semantic_search` tool. `--no-semantic` skips this.
3. **Discovery** — four agent "shapes" run concurrently, each a `claude -p` session with three
   read-only tools (`run_cypher`, `semantic_search`, `get_schema`): A data-flow, B absent-control,
   C disabled/reverted fix, D pattern + dependencies. Every claim must be grounded by a query.
4. **Verification** — each candidate lead gets its **own** fresh `claude -p` session (no discovery
   transcript), which re-derives it against the real source (via the `fp-check` skill, sandboxed to
   the target with `--add-dir`) and the graph. A crashed verifier is `ERROR`, never a silent
   `CONFIRM`.
5. **Report** — verdicts are ranked and rendered.

## Notes / knobs

- **Model & effort:** discovery/verification default to `sonnet` at `high` effort
  (`ORION_MODEL`, `ORION_EFFORT`). Discovery per-shape timeout scales with graph size
  (`orion/config.py`).
- **Rate limits:** a full scan on a large repo spawns many concurrent `claude` sessions. On a
  subscription with overage disabled, hitting the 5-hour limit surfaces as `ERROR` verdicts (Orion
  retries transient failures with backoff). An API key with headroom avoids this.
- **Exploit corpus** (optional): `./.venv/bin/python -m orion.cli index-exploits` builds the
  Metasploit reference corpus that the verifier's advisory `exploit_search` tool uses. Not required
  for CONFIRM/REJECT.
- **Neo4j lifecycle:** `docker compose up -d` / `down`. Browser UI at `http://localhost:7475`.
- **The sirius-vs-Grendel A/B benchmark** (measuring the six perf commits) is a separate rig that
  needs two clones and two Neo4j instances; it is not included here. Ask if you want it ported.
