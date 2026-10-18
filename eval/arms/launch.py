import subprocess
import threading
import queue as _q

HUNG_SECONDS = 3600


def stream_subprocess(cmd, *, env, cwd, on_line, hung_seconds=HUNG_SECONDS, on_start=None,
                      popen=subprocess.Popen) -> str:
    proc = popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                 env=env, cwd=cwd)
    if on_start is not None:
        on_start(proc)  # pid handoff: lets a PhaseSampler attach to the live process tree
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
