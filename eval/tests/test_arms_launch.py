import io
from eval.arms import launch


class FakePopen:
    def __init__(self, lines, cmd=None, **kw):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.returncode = 0
        self._lines = lines

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def test_stream_calls_on_line_and_returns_ok():
    seen = []

    def fake_popen(cmd, **kw):
        return FakePopen(["a", "b", "c"])
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=seen.append,
                                      popen=fake_popen)
    assert status == "ok"
    assert seen == ["a", "b", "c"]


def test_crashed_when_returncode_nonzero():
    class Bad(FakePopen):
        def __init__(self, *a, **k):
            super().__init__(["oops"])
            self.returncode = 1
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=lambda l: None,
                                      popen=lambda cmd, **kw: Bad())
    assert status == "crashed"


def test_orion_arm_uses_real_flags_and_captures_scan_id(tmp_path):
    captured = {}

    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        return FakePopen(["scan_id: abc123", '{"type":"result"}'])
    status, sid = launch.orion_arm(
        repo_dir=str(tmp_path / "repo"), ollama_url="u", model_tag="gemma3:12b",
        json_out=str(tmp_path / "out/findings.json"), usage_log=str(tmp_path / "u.jsonl"),
        shim_dir="/shim", base_env={"PATH": "/bin"}, on_line=lambda l: None,
        popen=fake_popen)
    assert status == "ok" and sid == "abc123"
    assert "--output-format" not in captured["cmd"]      # the flag Orion does NOT have
    assert "--json" in captured["cmd"]
    assert (tmp_path / "out").is_dir()                    # parent dir was created


def test_orion_arm_reuses_graph_with_scan_id(tmp_path):
    captured = {}

    def fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        return FakePopen(["scan_id: abc123"])
    launch.orion_arm(repo_dir="r", ollama_url="u", model_tag="m",
                     json_out=str(tmp_path / "f.json"), usage_log="u", shim_dir="/s",
                     base_env={}, on_line=lambda l: None, scan_id="abc123", popen=fake_popen)
    assert "--scan-id" in captured["cmd"] and "abc123" in captured["cmd"]
    assert "r" not in captured["cmd"]  # no repo positional when reusing
