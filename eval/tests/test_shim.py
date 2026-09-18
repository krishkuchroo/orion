import os
import stat
import subprocess
from eval import shim_setup


def test_shim_dir_is_executable():
    d = shim_setup.shim_dir()
    wrapper = os.path.join(d, "claude")
    assert os.path.isfile(wrapper)
    assert os.stat(wrapper).st_mode & stat.S_IXUSR


def test_shim_tees_stdout_to_usage_log(tmp_path):
    # a fake "real claude" that prints a stream-json-ish result line
    fake = tmp_path / "realclaude"
    fake.write_text('#!/bin/bash\necho \'{"type":"result","usage":{"input_tokens":7}}\'\n')
    fake.chmod(0o755)
    log = tmp_path / "usage.jsonl"
    env = dict(os.environ, EVAL_USAGE_LOG=str(log), EVAL_REAL_CLAUDE=str(fake))
    wrapper = os.path.join(shim_setup.shim_dir(), "claude")
    out = subprocess.run([wrapper, "-p", "hi"], capture_output=True, text=True, env=env)
    assert '"input_tokens":7' in out.stdout          # passed through to caller
    assert '"input_tokens":7' in log.read_text()      # AND captured to the log
    assert out.returncode == 0
