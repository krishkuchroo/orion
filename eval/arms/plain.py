import os
import subprocess

from .env import plain_claude_env
from .launch import stream_subprocess
from .prompt import TASK_PROMPT


def _build_cmd(arm: str, repo_dir: str) -> list[str]:
    if arm == "plain-gpt":
        # Codex: non-interactive, JSON events (carry token usage), cwd = repo.
        return ["codex", "exec", "--json", "--cd", repo_dir, TASK_PROMPT]
    # Claude Code arms (plain-sonnet5 / plain-opus5 / plain-gemma4).
    return ["claude", "-p", TASK_PROMPT, "--output-format", "stream-json", "--verbose",
            "--add-dir", repo_dir, "--permission-mode", "bypassPermissions"]


def plain_arm(*, arm, repo_dir, ollama_url, model_tag, json_out, usage_log, shim_dir,
              base_env, on_line, popen=subprocess.Popen):
    os.makedirs(os.path.dirname(json_out), exist_ok=True)
    if arm == "plain-gpt":
        env = dict(base_env)  # Codex reports usage itself; no claude shim
        cwd = repo_dir
    else:
        # plain-gemma4 routes Claude Code to Ollama; frontier Claude arms do not.
        ollama = ollama_url if arm == "plain-gemma4" else None
        tag = model_tag if arm == "plain-gemma4" else None
        env = plain_claude_env(base_env, usage_log=usage_log, shim_dir=shim_dir,
                               ollama_url=ollama, model_tag=tag)
        cwd = repo_dir
    cmd = _build_cmd(arm, repo_dir)
    status = stream_subprocess(cmd, env=env, cwd=cwd, on_line=on_line, popen=popen)
    return status, json_out
