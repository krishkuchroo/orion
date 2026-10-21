import io
from eval.arms import launch


class FakePopen:
    def __init__(self, lines, cmd=None, **kw):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.returncode = 0
        self.pid = 4321
        self._lines = lines

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def test_stream_calls_on_line_and_returns_ok():
    import subprocess
    seen, cap = [], {}

    def fake_popen(cmd, **kw):
        cap.update(kw)
        return FakePopen(["a", "b", "c"])
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=seen.append,
                                      popen=fake_popen)
    assert status == "ok"
    assert seen == ["a", "b", "c"]
    assert cap["stdin"] == subprocess.DEVNULL  # never inherit stdin: codex exec reads it to EOF


def test_crashed_when_returncode_nonzero():
    class Bad(FakePopen):
        def __init__(self, *a, **k):
            super().__init__(["oops"])
            self.returncode = 1
    status = launch.stream_subprocess(["x"], env={}, cwd=".", on_line=lambda l: None,
                                      popen=lambda cmd, **kw: Bad())
    assert status == "crashed"


def test_orion_subprocess_arm_is_gone():
    assert not hasattr(launch, "orion_arm")
