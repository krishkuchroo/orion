import json
import os
import shutil
import subprocess

from . import ArmResult
from ..usage import normalize_usage
from .env import plain_claude_env
from .launch import stream_subprocess
from .prompt import TASK_PROMPT, validate_findings

# The event type that carries a model-call usage summary, per CLI.
_USAGE_EVENT = {"codex": "turn.completed", "claude": "result"}


def _build_cmd(arm: str, repo_dir: str, model_tag: str, effort: str) -> list[str]:
    # model_tag / effort are accepted now; Task A6 adds the real --model / --effort flags.
    if arm == "plain-gpt":
        # Codex: non-interactive, JSON events (carry token usage), cwd = repo.
        return ["codex", "exec", "--json", "--cd", repo_dir, TASK_PROMPT]
    # Claude Code arms (plain-sonnet5 / plain-opus5).
    return ["claude", "-p", TASK_PROMPT, "--output-format", "stream-json", "--verbose",
            "--add-dir", repo_dir, "--permission-mode", "bypassPermissions"]


def _usage_source(arm: str) -> str:
    return "codex" if arm == "plain-gpt" else "claude"


def read_usage(usage_log: str, *, source: str) -> list[dict]:
    """Normalized usage blocks from a run's usage.jsonl: one per usage-carrying event.
    Missing file / no events -> [] (nothing measured, nothing invented)."""
    if not os.path.exists(usage_log):
        return []
    want = _USAGE_EVENT[source]
    blocks = []
    with open(usage_log) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue  # the shim tees everything claude prints; non-JSON lines are noise
            if isinstance(ev, dict) and ev.get("type") == want:
                blocks.append(normalize_usage(ev, source=source))
    return blocks


def _capture_findings(repo_dir: str, json_out: str, on_line) -> "str | None":
    """Copy the agent's findings.json out of the (soon-deleted) tree. Returns the per-run
    path when the file exists and validates; None (a miss) otherwise -- never raises."""
    src = os.path.join(repo_dir, "findings.json")
    if not os.path.exists(src):
        return None
    shutil.copy2(src, json_out)  # raw artifact is kept verbatim even if it fails validation
    try:
        obj = json.loads(open(json_out).read())
    except ValueError as e:
        on_line(f"warning: findings.json is not valid JSON ({e}); scored as a miss")
        return None
    if not isinstance(obj, dict):
        on_line("warning: findings.json is not a JSON object; scored as a miss")
        return None
    problems = validate_findings(obj)
    if problems:
        on_line(f"warning: findings.json failed schema check ({'; '.join(problems[:5])}); "
                "scored as a miss")
        return None
    return json_out


def plain_arm(*, arm, repo_dir, model_tag, effort, json_out, usage_log, shim_dir, base_env,
              on_line, popen=subprocess.Popen, on_start=None) -> ArmResult:
    os.makedirs(os.path.dirname(json_out), exist_ok=True)
    source = _usage_source(arm)
    _on_line = on_line
    if source == "codex":
        env = dict(base_env)  # Codex reports usage in its own --json stream; no claude shim
        # No shim tees Codex's stdout, so the arm keeps the raw event stream itself.
        os.makedirs(os.path.dirname(usage_log), exist_ok=True)
        log = open(usage_log, "w")

        def _on_line(line):
            log.write(line + "\n")
            log.flush()
            on_line(line)
    else:
        env = plain_claude_env(base_env, usage_log=usage_log, shim_dir=shim_dir)
        log = None
    cmd = _build_cmd(arm, repo_dir, model_tag, effort)
    try:
        status = stream_subprocess(cmd, env=env, cwd=repo_dir, on_line=_on_line,
                                   on_start=on_start, popen=popen)
    finally:
        if log is not None:
            log.close()
    findings_path = _capture_findings(repo_dir, json_out, on_line)
    return ArmResult(status=status, findings_path=findings_path,
                     usage=read_usage(usage_log, source=source))
