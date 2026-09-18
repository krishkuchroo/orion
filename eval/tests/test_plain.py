import io
from eval.arms import plain


class FakePopen:
    def __init__(self, lines=("done",), **kw):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.returncode = 0

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
        return FakePopen()
    status, out = plain.plain_arm(arm="plain-opus5", repo_dir=str(tmp_path / "repo"),
                                  ollama_url="u", model_tag="claude-opus-5",
                                  json_out=str(tmp_path / "o/findings.json"),
                                  usage_log=str(tmp_path / "u.jsonl"), shim_dir="/shim",
                                  base_env={"PATH": "/bin"}, on_line=lambda l: None,
                                  popen=fake_popen)
    assert status == "ok"
    assert cap["cmd"][0] == "claude"
    assert plain.TASK_PROMPT in cap["cmd"]
    assert cap["env"]["PATH"].startswith("/shim:")       # usage shim active
    assert "ANTHROPIC_BASE_URL" not in cap["env"]        # frontier arm not routed to Ollama
    assert (tmp_path / "o").is_dir()


def test_gemma_arm_routes_to_ollama(tmp_path):
    cap = {}

    def fake_popen(cmd, **kw):
        cap["env"] = kw.get("env")
        return FakePopen()
    plain.plain_arm(arm="plain-gemma4", repo_dir=str(tmp_path / "repo"),
                    ollama_url="http://127.0.0.1:11434", model_tag="gemma3:12b",
                    json_out=str(tmp_path / "o/findings.json"),
                    usage_log=str(tmp_path / "u.jsonl"), shim_dir="/shim",
                    base_env={"PATH": "/bin"}, on_line=lambda l: None, popen=fake_popen)
    assert cap["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:11434"
    assert cap["env"]["ORION_MODEL"] == "gemma3:12b"


def test_gpt_arm_builds_codex_cmd(tmp_path):
    cap = {}

    def fake_popen(cmd, **kw):
        cap["cmd"] = cmd
        return FakePopen()
    plain.plain_arm(arm="plain-gpt", repo_dir=str(tmp_path / "repo"), ollama_url="u",
                    model_tag="gpt-5.6-sol", json_out=str(tmp_path / "o/findings.json"),
                    usage_log=str(tmp_path / "u.jsonl"), shim_dir="/shim",
                    base_env={"PATH": "/bin"}, on_line=lambda l: None, popen=fake_popen)
    assert cap["cmd"][:3] == ["codex", "exec", "--json"]
    assert plain.TASK_PROMPT in cap["cmd"]
