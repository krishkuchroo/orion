# Open-weight study harness (`eval/`)

Runs the 6 study arms over the CVE dataset and records findings, tokens, memory and failures into
`eval/runs.db` (+ raw artifacts under `eval/runs/`). It does **not** score — scoring/labeling is a
separate session. Design: `../docs/superpowers/specs/2026-09-17-open-weight-eval-design.md`.
Plan: `../docs/superpowers/plans/2026-09-17-open-weight-eval.md`.

## Arms

| id | model | harness | graph |
|---|---|---|---|
| `orion-gemma4` | `gemma3:12b` (Ollama) | Orion | yes |
| `orion-gptoss20b` | `gpt-oss:20b` (Ollama) | Orion | yes |
| `plain-gemma4` | `gemma3:12b` (Ollama) | Claude Code, no graph | no |
| `plain-sonnet5` | `claude-sonnet-5` | Claude Code | no |
| `plain-opus5` | `claude-opus-5` | Claude Code | no |
| `plain-gpt` | `gpt-5.6-sol` | Codex CLI | no |

## Phase 0 — feasibility (run once, before any scored run)

1. **Ollama + models**
   ```bash
   ollama serve &                 # or launch the app
   ollama pull gemma3:12b         # confirm the exact Gemma tag that fits 16 GB
   ollama pull gpt-oss:20b
   ```
2. **Codex** — `npm i -g @openai/codex` (or `brew install codex`), then `codex` and sign in with
   your ChatGPT account.
3. **Preflight** — `./.venv/bin/python -m eval.preflight` — must show `ALL PRESENT` (checks ollama,
   ollama-serve, codex, claude, docker, joern, neo4j, cloc).
4. **Orion → Ollama smoke test (the gate).** Point Orion at a small repo (NodeGoat) through the
   Ollama env and confirm, on a real run:
   - the MCP tool executes (`run_cypher` returns rows),
   - `--json-schema` structured output parses,
   - fp-check's subagents stay on the local model (no call reaches Anthropic),
   - the `claude` usage shim wrote `usage.jsonl`,
   - the Joern build fits under 16 GB with `ORION_JOERN_HEAP_GB=7`.

   If Ollama fails the tool/structured-output checks, retry with llama.cpp `llama-server`
   (`/v1/messages`). If both fail it is a design change, not a code fix — stop and re-register.

## Memory plan (16 GB M4)

Joern (JVM) runs as a subprocess that **exits before** discovery starts the model, so build and model
are sequential, not co-resident. The env builders set `ORION_JOERN_HEAP_GB=7` (cap the build) and
`OLLAMA_KEEP_ALIVE=0` (unload the model when idle). The graph is built once per repo and reused across
the other 5 Orion runs via `--scan-id` (captured from Orion's `scan_id:` line).

## Run the study

```bash
./.venv/bin/python -m eval.run --runs 3                 # all arms, sequential, resumable
./.venv/bin/python -m eval.run --arm orion-gemma4       # one arm
```

Needs `eval/dataset/manifest.json` (`{"repos":[{id, repo_dir, tier, ...}]}`) — produced in Phase 1
and frozen at `eval-prereg-v1`.

## Inspect

```bash
sqlite3 eval/runs.db "select * from failures"                    # what broke
sqlite3 eval/runs.db "select arm, repo, status from runs"        # run status
```

Raw per-run artifacts (Orion `findings.orion.json` / plain `findings.json`, `usage.jsonl`) live under
`eval/runs/<arm>/<repo>/`.
