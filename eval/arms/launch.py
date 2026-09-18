import os
import re
import subprocess
import threading
import queue as _q

from .env import orion_env

HUNG_SECONDS = 3600
_SCAN_ID_RE = re.compile(r"^scan_id:\s*(\S+)")


def stream_subprocess(cmd, *, env, cwd, on_line, hung_seconds=HUNG_SECONDS,
                      popen=subprocess.Popen) -> str:
    proc = popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                 env=env, cwd=cwd)
    lines = _q.Queue()

    def _reader():
        for line in proc.stdout:
            lines.put(line.rstrip("\n"))
        lines.put(None)  # sentinel: stream ended

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    hung = False
    while True:
        try:
            line = lines.get(timeout=hung_seconds)
        except _q.Empty:
            hung = True
            try:
                proc.kill()
            except Exception:
                pass
            break
        if line is None:
            break
        on_line(line)
    proc.wait()
    if hung:
        return "hung"
    return "ok" if proc.returncode == 0 else "crashed"


def orion_arm(*, repo_dir, ollama_url, model_tag, json_out, usage_log, shim_dir, base_env,
              on_line, scan_id=None, popen=subprocess.Popen):
    env = orion_env(base_env, ollama_url=ollama_url, model_tag=model_tag,
                    usage_log=usage_log, shim_dir=shim_dir)
    os.makedirs(os.path.dirname(json_out), exist_ok=True)  # Orion's write_text won't mkdir
    if scan_id:
        cmd = ["orion", "scan", "--scan-id", scan_id, "--json", json_out, "--quiet"]
    else:
        cmd = ["orion", "scan", repo_dir, "--json", json_out, "--quiet"]
    seen = {"sid": scan_id}

    def _on_line(line):
        m = _SCAN_ID_RE.match(line)
        if m:
            seen["sid"] = m.group(1)
        on_line(line)
    status = stream_subprocess(cmd, env=env, cwd=".", on_line=_on_line, popen=popen)
    return status, seen["sid"]
