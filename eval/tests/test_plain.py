import io
import os

from eval.arms import plain, ArmResult


class FakePopen:
    def __init__(self, lines=("done",), **kw):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.returncode = 0
        self.pid = 4321

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def test_claude_arm_builds_claude_cmd_with_prompt(tmp_path):
    cap = {}

    def fake_popen(cmd, **kw):
        cap["cmd"] = cmd
        cap["env"] = kw.get("env")
        cap["cwd"] = kw.get("cwd")
        return FakePopen()
    res = plain.plain_arm(arm="plain-opus5", repo_dir=str(tmp_path / "repo"),
                          model_tag="claude-opus-5", effort="xhigh",
                          json_out=str(tmp_path / "o/findings.json"),
                          usage_log=str(tmp_path / "u.jsonl"), shim_dir="/shim",
                          base_env={"PATH": "/bin", "CLAUDE_CONFIG_DIR": "/Users/me/.claude"},
                          on_line=lambda l: None, popen=fake_popen,
                          config_root=str(tmp_path / "cfg"))
    assert isinstance(res, ArmResult) and res.status == "ok"
    assert cap["cmd"][0] == "claude"
    assert plain.TASK_PROMPT in cap["cmd"]
    assert cap["cmd"][cap["cmd"].index("--model") + 1] == "claude-opus-5"
    assert cap["cmd"][cap["cmd"].index("--effort") + 1] == "xhigh"
    assert cap["env"]["PATH"].startswith("/shim:")       # usage shim active
    assert cap["env"]["EVAL_USAGE_LOG"] == str(tmp_path / "u.jsonl")
    assert "ANTHROPIC_BASE_URL" not in cap["env"]        # talks to Anthropic directly
    # clean config home: the operator's ~/.claude (plugins, hooks, memory, MCP) never loads
    assert cap["env"]["CLAUDE_CONFIG_DIR"] == str(tmp_path / "cfg/claude")
    assert os.path.isdir(tmp_path / "cfg/claude")
    assert cap["cwd"] == str(tmp_path / "repo")          # agent runs inside the exported tree
    assert (tmp_path / "o").is_dir()


def test_gpt_arm_builds_codex_cmd(tmp_path):
    cap = {}

    def fake_popen(cmd, **kw):
        cap["cmd"] = cmd
        cap["env"] = kw.get("env")
        return FakePopen()
    res = plain.plain_arm(arm="plain-gpt", repo_dir=str(tmp_path / "repo"),
                          model_tag="gpt-5.6-sol", effort="xhigh",
                          json_out=str(tmp_path / "o/findings.json"),
                          usage_log=str(tmp_path / "u.jsonl"), shim_dir="/shim",
                          base_env={"PATH": "/bin", "CODEX_HOME": "/Users/me/.codex"},
                          on_line=lambda l: None, popen=fake_popen,
                          config_root=str(tmp_path / "cfg"))
    assert res.status == "ok"
    assert cap["cmd"][:3] == ["codex", "exec", "--json"]
    assert cap["cmd"][cap["cmd"].index("-m") + 1] == "gpt-5.6-sol"
    assert plain.TASK_PROMPT in cap["cmd"]
    assert cap["env"]["PATH"] == "/bin"                  # Codex reports usage itself; no shim
    assert "EVAL_USAGE_LOG" not in cap["env"]
    # clean CODEX_HOME with the minimal config written once
    assert cap["env"]["CODEX_HOME"] == str(tmp_path / "cfg/codex")
    assert 'model = "gpt-5.6-sol"' in (tmp_path / "cfg/codex/config.toml").read_text()


def test_build_cmd_accepts_model_and_effort():
    cmd = plain._build_cmd("plain-opus5", "/r", "claude-opus-5", "xhigh")
    assert cmd[0] == "claude"


def test_build_cmd_omits_effort_flag_when_unset():
    assert "--effort" not in plain._build_cmd("plain-opus5", "/r", "claude-opus-5", "")
    assert not any(a.startswith("model_reasoning_effort") for a in
                   plain._build_cmd("plain-gpt", "/r", "gpt-5.6-sol", ""))


def test_config_home_is_per_cli():
    assert plain.config_home("plain-gpt", "/c") == "/c/codex"
    assert plain.config_home("plain-opus5", "/c") == "/c/claude"
    assert plain.config_home("plain-sonnet5", "/c") == "/c/claude"
    assert plain.CONFIG_ROOT.endswith(os.path.join("eval", ".config"))


CASE = {"case_id": "BenchmarkTest00001", "category": "sqli", "real": False, "cwe": "CWE-89",
        "file": "testcode/BenchmarkTest00001.py",
        "entry": "POST /benchmark/sqli-00/BenchmarkTest00001 -> BenchmarkTest00001_post"}


def _cmd_for(tmp_path, arm, model_tag, **kw):
    cap = {}

    def fake_popen(cmd, **k):
        cap["cmd"] = cmd
        return FakePopen()
    plain.plain_arm(arm=arm, repo_dir=str(tmp_path / "repo"), model_tag=model_tag, effort="xhigh",
                    json_out=str(tmp_path / "o/findings.json"), usage_log=str(tmp_path / "u.jsonl"),
                    shim_dir="/shim", base_env={"PATH": "/bin"}, on_line=lambda l: None,
                    popen=fake_popen, config_root=str(tmp_path / "cfg"), **kw)
    return cap["cmd"]


def test_plain_arms_use_the_case_prompt_when_the_item_has_a_case(tmp_path):
    from eval.arms.prompt import case_prompt
    for arm, tag in (("plain-opus5", "claude-opus-5"), ("plain-gpt", "gpt-5.6-sol")):
        cmd = _cmd_for(tmp_path, arm, tag, case=CASE)
        assert case_prompt(CASE) in cmd and plain.TASK_PROMPT not in cmd
        cmd = _cmd_for(tmp_path, arm, tag)                  # no case: the whole-repo task
        assert plain.TASK_PROMPT in cmd
