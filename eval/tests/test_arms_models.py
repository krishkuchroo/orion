import json
import os

from eval import run
from eval.arms import env, plain


def test_claude_arm_pins_model_effort_and_isolates_config():
    cmd = plain._build_cmd("plain-opus5", "/repo", "claude-opus-5", "xhigh")
    s = " ".join(cmd)
    assert "--model claude-opus-5" in s and "--effort xhigh" in s
    assert "--setting-sources" in s and "--strict-mcp-config" in s
    assert "WebFetch" in s and "WebSearch" in s and "--settings" in s


def test_codex_arm_pins_model_effort_and_sandboxes():
    cmd = plain._build_cmd("plain-gpt", "/repo", "gpt-5.6-sol", "xhigh")
    s = " ".join(cmd)
    assert "-m gpt-5.6-sol" in s and "model_reasoning_effort=xhigh" in s
    # workspace-write + network_access=false, not read-only: measured 2026-10-18 that
    # read-only also rejects the findings.json write (eval/README.md smoke test)
    assert "--sandbox workspace-write" in s and "sandbox_workspace_write.network_access=false" in s
    assert "--skip-git-repo-check" in s
    # account-side remote plugins / the codex_apps MCP server load even under a clean
    # CODEX_HOME, and the built-in web_search tool runs outside the shell sandbox
    assert "--disable plugins" in s and "--disable remote_plugin" in s and "--disable apps" in s
    assert "web_search=disabled" in s
    assert "approval_policy=never" in s


def test_envs_point_at_clean_homes(tmp_path):
    e = env.plain_claude_env({"PATH": "/bin"}, usage_log="u", shim_dir="/s",
                             config_dir=str(tmp_path / "c"))
    assert e["CLAUDE_CONFIG_DIR"] == str(tmp_path / "c")
    assert env.codex_env({"PATH": "/bin"}, home=str(tmp_path / "h"))["CODEX_HOME"] == str(tmp_path / "h")


def test_claude_arm_allowlists_audit_tools_and_denies_network_and_agent_tools():
    cmd = plain._build_cmd("plain-opus5", "/repo", "claude-opus-5", "xhigh")
    assert cmd[cmd.index("--tools") + 1] == "Bash,Read,Edit,Write,Grep,Glob,NotebookEdit"
    i = cmd.index("--disallowedTools") + 1
    denied = cmd[i:cmd.index("--settings")]
    # every built-in from the 2.1.302 init list that reaches the network or spawns agents
    for t in ("WebFetch", "WebSearch", "Task", "RemoteTrigger", "DesignSync", "PushNotification",
              "Workflow", "CronCreate", "CronList", "CronDelete", "ScheduleWakeup", "Monitor",
              "ListAgents", "SendMessage", "TaskStop", "EnterWorktree", "ExitWorktree",
              "ReportFindings", "Skill", "ToolSearch"):
        assert t in denied
    assert not set(plain.CLAUDE_TOOLS) & set(plain.CLAUDE_DISALLOWED)
    assert "--no-session-persistence" in cmd   # no transcripts pile up in the shared config home


def test_claude_arm_keeps_bypass_and_add_dir_and_setting_sources_is_empty():
    cmd = plain._build_cmd("plain-sonnet5", "/repo", "claude-sonnet-5", "xhigh")
    assert cmd[cmd.index("--add-dir") + 1] == "/repo"
    assert cmd[cmd.index("--permission-mode") + 1] == "bypassPermissions"
    assert cmd[cmd.index("--setting-sources") + 1] == ""   # no user/project/local settings
    assert cmd[cmd.index("--settings") + 1] == plain.CLAUDE_SETTINGS
    assert os.path.isabs(plain.CLAUDE_SETTINGS) and os.path.exists(plain.CLAUDE_SETTINGS)


def test_codex_arm_runs_in_repo():
    cmd = plain._build_cmd("plain-gpt", "/repo", "gpt-5.6-sol", "xhigh")
    assert cmd[:3] == ["codex", "exec", "--json"]
    assert cmd[cmd.index("--cd") + 1] == "/repo"


def test_claude_settings_lock_the_sandbox_network():
    cfg = json.load(open(plain.CLAUDE_SETTINGS))
    sb = cfg["sandbox"]
    assert sb["enabled"] is True
    # bypassPermissions lets non-allowlisted hosts through unless the allowlist is strict
    assert sb["network"]["strictAllowlist"] is True
    assert sb["network"]["allowedDomains"] == []
    # no "retry unsandboxed" escape hatch, and refuse to start rather than run unsandboxed
    assert sb["allowUnsandboxedCommands"] is False
    assert sb["failIfUnavailable"] is True


def test_arms_table_is_the_five_study_arms():
    assert run.ARMS == ["orion-lm", "orion-lm-base", "plain-sonnet5", "plain-opus5", "plain-gpt"]
    assert run.MODEL_TAGS["plain-sonnet5"] == "claude-sonnet-5"
    assert run.MODEL_TAGS["plain-opus5"] == "claude-opus-5"
    assert run.MODEL_TAGS["plain-gpt"] == "gpt-5.6-sol"
    assert run.EFFORT == {"plain-sonnet5": "xhigh", "plain-opus5": "xhigh", "plain-gpt": "xhigh"}
    assert not any("gemma" in a or "gptoss" in a for a in run.ARMS)
    assert not any("gemma" in t or "gpt-oss" in t for t in run.MODEL_TAGS.values())


def test_source_for_matches_arms():
    assert run._source_for("plain-gpt") == "codex"
    assert run._source_for("plain-sonnet5") == "claude"
    assert run._source_for("plain-opus5") == "claude"
    assert run._source_for("orion-lm") == "lm"
    assert run._source_for("orion-lm-base") == "lm"


def test_codex_home_gets_a_minimal_config(tmp_path):
    home = str(tmp_path / "codex")
    env.ensure_codex_home(home)
    cfg = open(os.path.join(home, "config.toml")).read()
    assert 'model = "gpt-5.6-sol"' in cfg
    env.ensure_codex_home(home)  # idempotent: never clobbers an existing (operator-edited) file
    assert os.path.exists(os.path.join(home, "config.toml"))
