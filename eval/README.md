# Orion-LM study harness (`eval/`)

Runs the 5 study arms over the CVE dataset and records findings, tokens, memory and failures into
`eval/runs.db` (+ raw artifacts under `eval/runs/`). It does **not** score — scoring/labeling is a
separate session. Design: `../docs/superpowers/specs/2026-10-18-orion-lm-design.md`.

## Arms

| id | model (`runs.model_tag`) | effort (`runs.effort`) | harness | graph |
|---|---|---|---|---|
| `orion-lm` | fine-tuned local model (path set in Part F) | — | Orion, in-process (MLX-LM) | yes |
| `orion-lm-base` | the same base model, untuned | — | Orion, in-process | yes |
| `plain-sonnet5` | `claude-sonnet-5` | `xhigh` | Claude Code CLI | no |
| `plain-opus5` | `claude-opus-5` | `xhigh` | Claude Code CLI | no |
| `plain-gpt` | `gpt-5.6-sol` | `xhigh` | Codex CLI | no |

Model ids were verified against the installed CLIs on 2026-10-18 (`claude` 2.1.302, `codex-cli`
0.155.1): `claude --model <id>` runs and reports the same id in its `system` init event and
`modelUsage`; `codex exec -m gpt-5.6-sol` runs (the id is also in Codex's `models_cache.json`).
Negative controls: `claude --model claude-nonexistent-xyz` returns `is_error: true` ("There's an
issue with the selected model"); `codex exec -m gpt-nonexistent-xyz` does **not** fail fast — it
reconnects indefinitely (killed by hand after ~3 h), so a wrong Codex tag would surface as a `hung`
run, not an error.

### What the frontier arms run (`eval/arms/plain.py::_build_cmd`)

Claude arms:

```
claude -p <TASK_PROMPT> --output-format stream-json --verbose
       --model <tag> --effort xhigh
       --setting-sources "" --strict-mcp-config
       --disallowedTools WebFetch WebSearch
       --settings eval/arms/claude_settings.json
       --add-dir <tree> --permission-mode bypassPermissions
```

Codex arm:

```
codex exec --json -m gpt-5.6-sol -c model_reasoning_effort=xhigh
     --sandbox workspace-write -c sandbox_workspace_write.network_access=false
     --disable plugins --disable remote_plugin --disable apps
     -c web_search=disabled -c approval_policy=never
     --skip-git-repo-check --cd <tree> <TASK_PROMPT>
```

What each piece buys, and why (all measured on 2026-10-18, transcripts below):

- **Pinned model + effort.** Both recorded per run (`runs.model_tag`, `runs.effort`).
- **Clean config homes.** `CLAUDE_CONFIG_DIR=eval/.config/claude` and `CODEX_HOME=eval/.config/codex`
  replace `~/.claude` / `~/.codex`, so none of the operator's plugins, hooks, MCP servers, memory or
  settings load. `--setting-sources ""` additionally drops user/project/local settings files and
  `--strict-mcp-config` ignores every MCP configuration. Both directories are gitignored — they hold
  a copy of the login (one-time step below).
- **No web tools.** `--disallowedTools WebFetch WebSearch` (plus a `permissions.deny` in the settings
  file); the init event's tool list has neither. Codex: `web_search=disabled` — Codex's built-in
  search tool defaults to `cached` and runs *outside* the shell sandbox; with the sandbox on and this
  flag absent it searched the web (second Codex transcript below). `--disable apps` removes the
  `codex_apps` MCP server through which account-side plugins (netlify, sites, …) appeared even
  under a clean `CODEX_HOME`; `--disable plugins --disable remote_plugin` stop the remote plugin
  catalog from being pulled into the clean home.
- **No network below the tool layer (Bash included).** Claude: `claude_settings.json` enables the
  Claude Code sandbox (Seatbelt on macOS) with an **empty** `network.allowedDomains` and
  `strictAllowlist: true` — load-bearing, because in `bypassPermissions` mode non-allowlisted hosts
  are otherwise allowed. `allowUnsandboxedCommands: false` removes the "retry unsandboxed" escape
  hatch and `failIfUnavailable: true` makes `claude` exit rather than run unsandboxed if the sandbox
  cannot start. The `claude` process itself is outside the sandbox, so `api.anthropic.com` needs no
  entry. Codex: `workspace-write` with `network_access=false`. `--sandbox read-only` also blocks the
  network but **rejects the `findings.json` write** ("patch rejected: writing is blocked by read-only
  sandbox"), which would make every `plain-gpt` run a miss — measured, hence workspace-write.
- `--skip-git-repo-check` because the exported tree has no `.git` (answer-leak guard);
  `approval_policy=never` because nothing may wait on a prompt in a non-interactive run.

## Setup

1. **CLIs** — `claude` (Claude Code, logged in with the study subscription) and `codex`
   (`npm i -g @openai/codex`, `codex` → sign in with ChatGPT). Check: `claude --version`,
   `codex --version`.
2. **One-time auth copy into the clean homes.** An empty config home has no login, so copy *only*
   the credential into it — never settings, plugins or memory. Run from the repo root:

   ```bash
   mkdir -p eval/.config/claude eval/.config/codex && chmod 700 eval/.config/claude eval/.config/codex

   # Claude Code. macOS keeps the login in the keychain (service "Claude Code-credentials"),
   # not in a file; export just the claudeAiOauth block to <config_dir>/.credentials.json.
   security find-generic-password -s "Claude Code-credentials" -w \
     | python3 -c 'import json,sys; d=json.load(sys.stdin); json.dump({"claudeAiOauth": d["claudeAiOauth"]}, open("eval/.config/claude/.credentials.json","w"))'
   chmod 600 eval/.config/claude/.credentials.json
   # (Linux: cp ~/.claude/.credentials.json eval/.config/claude/ -- same file, same content.)

   # Codex: the login is the file ~/.codex/auth.json. The harness writes a minimal config.toml
   # on first run (eval/arms/env.py::ensure_codex_home); nothing else is copied.
   cp ~/.codex/auth.json eval/.config/codex/auth.json && chmod 600 eval/.config/codex/auth.json
   ```

   Verify (tiny prompts, a few cents):

   ```bash
   CLAUDE_CONFIG_DIR=$PWD/eval/.config/claude claude -p "reply ok" --setting-sources "" --strict-mcp-config < /dev/null
   CODEX_HOME=$PWD/eval/.config/codex codex exec --skip-git-repo-check "reply ok" < /dev/null
   ```

   Files copied, exactly: `eval/.config/claude/.credentials.json` (the `claudeAiOauth` object from
   the keychain item — the keychain export also carries `mcpOAuth` tokens for plugins, which are
   dropped) and `eval/.config/codex/auth.json`. Caveat: the copied OAuth tokens are refreshed
   independently of the ones in `~/.claude`/`~/.codex`; if a run ever reports "Not logged in",
   redo this step.
3. **Preflight** — `./.venv/bin/python -m eval.preflight` — checks codex, claude, docker, joern,
   neo4j, cloc (`ALL PRESENT` before a scored run).

## Run the study

```bash
./.venv/bin/python -m eval.run --runs 3                 # all arms, sequential, resumable
./.venv/bin/python -m eval.run --arm plain-opus5        # one arm
```

Needs `eval/dataset/manifest.json` (`{"repos":[{id, repo_url, tier, vulnerable_commit,
patched_commit, ...}]}`), frozen at `orion-lm-prereg-v1`.

## Inspect

```bash
sqlite3 eval/runs.db "select * from failures"                    # what broke
sqlite3 eval/runs.db "select arm, repo, status from runs"        # run status
```

Raw per-run artifacts (plain `findings.json`, `usage.jsonl`) live under
`eval/runs/<arm>/<repo>/<commit>/<case>/<run>/`.

## Network / isolation smoke tests (2026-10-18)

Run from a throwaway directory with the exact `_build_cmd` output (only the task prompt swapped for
the smoke prompt) and the exact env builders, against clean config homes holding only the copied
credential. Condensed stream transcripts; `TOOL_USE`/`TOOL_RESULT`/`CODEX_CMD`/`CODEX_OUT` lines
are the raw tool inputs and outputs.

### `plain-sonnet5` — `curl` from Bash (blocked)

```
CMD: claude -p "Run `curl -sS https://example.com | head -c 100` and report the output verbatim." --output-format stream-json --verbose --model claude-sonnet-5 --effort xhigh --setting-sources "" --strict-mcp-config --disallowedTools WebFetch WebSearch --settings .../eval/arms/claude_settings.json --add-dir .../work-claude --permission-mode bypassPermissions
INIT model=claude-sonnet-5 mcp_servers=[] plugins=['cc-plugin-agents-md', 'cc-plugin-telemetry', 'cc-plugin-plugin-authoring']
INIT tools=['Task', 'Bash', 'CronCreate', 'CronDelete', 'CronList', 'DesignSync', 'Edit', 'EnterWorktree', 'ExitWorktree', 'ListAgents', 'Monitor', 'NotebookEdit', 'PushNotification', 'Read', 'RemoteTrigger', 'ReportFindings', 'ScheduleWakeup', 'SendMessage', 'Skill', 'TaskStop', 'Workflow', 'Write']
TOOL_USE: Bash {"command": "curl -sS https://example.com | head -c 100", "description": "Fetch example.com and print first 100 bytes", "allowed_domains": ["example.com"]}
TOOL_RESULT: <tool_use_error>allowed_domains cannot widen network access in this session: the configured sandbox allowlist is the whole allowlist here (a managed-domains-only or strictAllowlist policy, or a confined evaluation run). Remove allowed_domains and use a host the configured allowlist already covers.</tool_use_error>
TOOL_USE: Bash {"command": "curl -sS https://example.com | head -c 100", "description": "Fetch example.com and print first 100 bytes"}
TOOL_RESULT: curl: (56) CONNECT tunnel failed, response 403
<sandbox_violations>
deny network-outbound example.com:443 (host is not on the allow list)
</sandbox_violations>
ASSISTANT: The command couldn't run: the sandbox's network proxy denied the connection to `example.com:443` ("host is not on the allow list"), and this session's allowlist is fixed — I can't widen it myself. The exact output was:

```
curl: (56) CONNECT tunnel failed, response 403
```
RESULT is_error=False cost_usd=0.24239760000000005 modelUsage=['claude-sonnet-5']
```

Verdict: **blocked**. The three builtin `cc-plugin-*` entries ship inside the CLI (`path: builtin`);
no user plugin, hook or MCP server loaded. `WebFetch`/`WebSearch` are absent from the tool list.

### `plain-opus5` — `curl` from Bash (blocked)

```
CMD: claude -p "Run `curl -sS https://example.com | head -c 100` and report the output verbatim." ... --model claude-opus-5 --effort xhigh ... (same flags)
INIT model=claude-opus-5 mcp_servers=[] plugins=['cc-plugin-agents-md', 'cc-plugin-telemetry', 'cc-plugin-plugin-authoring']
ASSISTANT: I'll run that command.
TOOL_USE: Bash {"command": "curl -sS https://example.com | head -c 100", "description": "Fetch example.com and show first 100 bytes", "allowed_domains": ["example.com"]}
TOOL_RESULT: <tool_use_error>allowed_domains cannot widen network access in this session: the configured sandbox allowlist is the whole allowlist here (a managed-domains-only or strictAllowlist policy, or a confined evaluation run). Remove allowed_domains and use a host the configured allowlist already covers.</tool_use_error>
TOOL_USE: Bash {"command": "curl -sS https://example.com | head -c 100", "description": "Fetch example.com and show first 100 bytes"}
TOOL_RESULT: curl: (56) CONNECT tunnel failed, response 403
<sandbox_violations>
deny network-outbound example.com:443 (host is not on the allow list)
</sandbox_violations>
ASSISTANT: The command ran but produced no page content — the sandbox blocked the request.

Output verbatim:

```
curl: (56) CONNECT tunnel failed, response 403
```

The sandbox reported: `deny network-outbound example.com:443 (host is not on the allow list)`.
RESULT is_error=False cost_usd=0.48348100000000005 modelUsage=['claude-opus-5']
```

Verdict: **blocked**.

### `plain-sonnet5` — "list your MCP servers and plugins"

```
CMD: claude -p "list your MCP servers and plugins" ... --model claude-sonnet-5 ... (same flags)
INIT model=claude-sonnet-5 mcp_servers=[] plugins=['cc-plugin-agents-md', 'cc-plugin-telemetry', 'cc-plugin-plugin-authoring']
TOOL_USE: Bash {"command": "claude mcp list 2>&1", "description": "List configured MCP servers"}
TOOL_RESULT: No MCP servers configured. Use `claude mcp add` to add a server.
<sandbox_violations>
deny network-outbound api.anthropic.com:443 (host is not on the allow list)
deny network-outbound api.anthropic.com:443 (host is not on the allow list)
deny network-outbound api.anthropic.com:443 (host is not on the allow list)
deny network-outbound http-intake.logs.us5.datadoghq.com:443 (host is not on the allow list)
deny network-outbound api.anthropic.com:443 (host is not on the allow list)
</sandbox_violations>
TOOL_USE: Bash {"command": "ls -la .../claude-cfg/plugins 2>&1", "description": "List plugins directory contents"}
TOOL_RESULT: Exit code 1
ls: .../claude-cfg/plugins: No such file or directory
ASSISTANT: No MCP servers or project-level config found. Here's what's actually configured in this environment:

**MCP servers:** None. `claude mcp list` reports no servers configured.

**Plugins:** Only built-in plugins show usage history (none actually invoked yet):
- `cc-plugin-agents-md` (builtin)
- `cc-plugin-telemetry` (builtin)
- `cc-plugin-plugin-authoring` (builtin)

There's no `plugins` directory and no `mcpServers` entry in the config file (`.claude.json`).
RESULT is_error=False cost_usd=0.10499579999999999 modelUsage=['claude-sonnet-5']
```

Verdict: **none**. (Bonus evidence: a nested `claude` launched *from Bash* could not reach
`api.anthropic.com` either — the lockout holds for child processes.)

### `plain-gpt` — `curl` from the shell (blocked), final command

```
CMD: codex exec --json -m gpt-5.6-sol -c model_reasoning_effort=xhigh --sandbox workspace-write -c sandbox_workspace_write.network_access=false --disable plugins --disable remote_plugin --disable apps -c web_search=disabled -c approval_policy=never --skip-git-repo-check --cd .../work-codex "Run `curl -sS https://example.com | head -c 100` and report the output verbatim."
CODEX_EVENT: {"type":"thread.started","thread_id":"01a14f33-a210-7a31-8b52-485caa7c7c35"}
CODEX_MSG: I'll run that exact pipeline and return its first 100 bytes unchanged.
CODEX_CMD: /bin/zsh -lc 'curl -sS https://example.com | head -c 100' | exit 0
CODEX_OUT: curl: (6) Could not resolve host: example.com
CODEX_MSG: ```text
curl: (6) Could not resolve host: example.com
```
CODEX_EVENT: {"type":"turn.completed","usage":{"input_tokens":19842,"cached_input_tokens":9600,"cache_write_input_tokens":0,"output_tokens":189,"reasoning_output_tokens":30}}
```

Verdict: **blocked**.

### `plain-gpt` — sandbox mode comparison (why not `read-only`)

Prompt: create `probe.txt`, then run the `curl`, report both.

```
--sandbox read-only:
  ERROR codex_core::tools::router: error=patch rejected: writing is blocked by read-only sandbox; rejected by user approval settings
  CODEX_CMD: /bin/zsh -lc 'curl -sS https://example.com | head -c 100' | exit 0
  CODEX_OUT: curl: (6) Could not resolve host: example.com
  CODEX_MSG: ... The file write did not succeed because the sandbox is read-only.
  probe-ro.txt exists: no

--sandbox workspace-write -c sandbox_workspace_write.network_access=false:
  item: file_change probe-ww.txt (add) status=completed
  CODEX_CMD: /bin/zsh -lc 'wc -c probe-ww.txt && od -An -tx1 probe-ww.txt && curl -sS https://example.com | head -c 100' | exit 0
  CODEX_OUT:        3 probe-ww.txt / 68 69 0a / curl: (6) Could not resolve host: example.com
  probe-ww.txt exists: yes; content: hi
```

### `plain-gpt` — "list your MCP servers and plugins" (before and after the fix)

**Before** (`--disable plugins --disable remote_plugin` only, no `--disable apps`, no
`web_search=disabled`) — this run is the reason those two flags exist:

```
CODEX_ITEM: {"type": "web_search", "query": "site:developers.openai.com/codex MCP servers plugins", ...}
CODEX_MCP_CALL: {"server": "codex", "tool": "list_mcp_resources", ... "resources":[{"server":"codex_apps","uri":"plugin://plugin_connector_1p_...","title":"Default templates", ...
CODEX_MSG: ### MCP servers
- `codex_apps` — session-provided MCP server hosting connected plugins and utilities.
- Standalone user-configured MCP servers: none (`codex mcp list` reports none).
### Plugins
- `openai-templates` ... - `netlify` ... - `work-pets` ... - `plugin-management` ... - `sites` ...
```

Verdict: **leak** — the built-in web search ran with the shell sandbox on, and account-side plugins
arrived through `codex_apps`.

**After** (the final command; `CODEX_HOME` reset to `auth.json` + `config.toml` first):

```
CMD: codex exec --json -m gpt-5.6-sol -c model_reasoning_effort=xhigh --sandbox workspace-write -c sandbox_workspace_write.network_access=false --disable plugins --disable remote_plugin --disable apps -c web_search=disabled --skip-git-repo-check --cd .../work-codex "List your MCP servers and plugins. Then use your web search tool to search for \"OpenAI Codex CLI\" and report the first result title verbatim, or the exact error if you cannot search. Do not read any files."
CODEX_MSG: The live inventory exposes no web-search tool. I'll still make a direct search-tool call so I can report the exact runtime error, as requested.
CODEX_MSG: - MCP/tool servers exposed: `functions`, `collaboration`, `image_gen`
- Plugins/skills exposed: `imagegen`, `openai-docs`, `plugin-creator`, `skill-creator`, `skill-installer`
- Web search: unavailable. Exact error: `TypeError: tools.web_search is not a function`
CODEX_EVENT: {"type":"turn.completed","usage":{"input_tokens":34786,"cached_input_tokens":21760,"cache_write_input_tokens":0,"output_tokens":951,"reasoning_output_tokens":709}}
plugins/ cache in CODEX_HOME afterwards: none
```

Verdict: **none / unavailable**. What remains is bundled with the CLI itself: the `.system` skills
(`imagegen`, `openai-docs`, `plugin-creator`, `skill-creator`, `skill-installer`) and the
`image_gen` tool (server-side image generation, not a lookup channel). `openai-docs` instructs the
model to web-search, which now fails.
