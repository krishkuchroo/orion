"""Process environments for the frontier (plain-*) arms.

Both CLIs are pointed at a clean config home so none of the operator's plugins, hooks, MCP
servers, memory or settings load into a run (they add tokens and change behaviour). The homes
live under eval/.config/ (gitignored) and hold only a copy of the login; see eval/README.md
for the one-time auth-copy step.
"""
import os

# Minimal Codex config for the clean home. The model/effort are also pinned on the command
# line (-m / -c model_reasoning_effort=...), so this file only has to exist and be sane.
CODEX_CONFIG_TOML = (
    '# eval harness: clean CODEX_HOME for the plain-gpt arm (see eval/README.md)\n'
    'model = "gpt-5.6-sol"\n'
    'model_reasoning_effort = "xhigh"\n'
)


def _with_shim(env: dict, usage_log: str, shim_dir: str) -> None:
    env["EVAL_USAGE_LOG"] = usage_log
    env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"


def plain_claude_env(base, *, usage_log, shim_dir, config_dir) -> dict:
    """Env for the Claude Code arms: usage shim on PATH + CLAUDE_CONFIG_DIR=<config_dir>.
    The config dir replaces ~/.claude, so the operator's plugins/hooks/memory/MCP never
    load; it must carry a copy of the login (eval/README.md, one-time step)."""
    env = dict(base)
    env["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] = "1"
    env["CLAUDE_CONFIG_DIR"] = config_dir
    _with_shim(env, usage_log, shim_dir)
    return env


def codex_env(base, *, home) -> dict:
    """Env for the Codex arm: CODEX_HOME=<home> replaces ~/.codex (config, plugins, state).
    Codex reports usage in its own --json stream, so no shim."""
    env = dict(base)
    env["CODEX_HOME"] = home
    return env


def ensure_codex_home(home: str) -> str:
    """Create the clean CODEX_HOME with a minimal config.toml (never overwrites one that is
    already there, e.g. after the operator copied auth.json in)."""
    os.makedirs(home, exist_ok=True)
    cfg = os.path.join(home, "config.toml")
    if not os.path.exists(cfg):
        with open(cfg, "w") as fh:
            fh.write(CODEX_CONFIG_TOML)
    return home
