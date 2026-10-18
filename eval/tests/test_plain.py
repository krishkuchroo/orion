import io
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
                          base_env={"PATH": "/bin"}, on_line=lambda l: None,
                          popen=fake_popen)
    assert isinstance(res, ArmResult) and res.status == "ok"
    assert cap["cmd"][0] == "claude"
    assert plain.TASK_PROMPT in cap["cmd"]
    assert cap["env"]["PATH"].startswith("/shim:")       # usage shim active
    assert cap["env"]["EVAL_USAGE_LOG"] == str(tmp_path / "u.jsonl")
    assert "ANTHROPIC_BASE_URL" not in cap["env"]        # never routed to Ollama
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
                          base_env={"PATH": "/bin"}, on_line=lambda l: None, popen=fake_popen)
    assert res.status == "ok"
    assert cap["cmd"][:3] == ["codex", "exec", "--json"]
    assert plain.TASK_PROMPT in cap["cmd"]
    assert cap["env"] == {"PATH": "/bin"}                # Codex reports usage itself; no shim


def test_build_cmd_accepts_model_and_effort():
    cmd = plain._build_cmd("plain-opus5", "/r", "claude-opus-5", "xhigh")
    assert cmd[0] == "claude"
