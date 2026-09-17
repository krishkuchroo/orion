"""Process driver: build the target exe with coverage, then drive it via argv/stdin. Stdlib only.

For a compiled target built from the scanned source. `start()` runs the coverage build once
(`go build -cover ...` via the tracer's build_flags), then each `send()` execs the instrumented
binary with a mutated argv/stdin under the tracer's coverage env (GOCOVERDIR). Seeds come from the
graph's :EntryPoint methods (a main() taking argv already registers as an EntryPoint), falling back
to a single empty-argv run.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .base import Input, Response, RunningTarget

_ENTRY_CYPHER = (
    "MATCH (e:EntryPoint {scan_id:$scan_id}) RETURN e.method_full_name AS m ORDER BY m"
)


class ProcessDriver:
    """Build + drive a Go (or other compiled-from-source) exe."""

    def __init__(self, build_cmd: list[str], out_bin: str, tracer,
                 build_flags: list[str] | None = None) -> None:
        self._build_cmd = build_cmd        # e.g. ["go","build","-o","<out_bin>","./..."]
        self._out_bin = out_bin
        self._tracer = tracer              # supplies launch_env(work) keyed to the actual work dir
        self._extra_flags = build_flags or []

    def start(self, repo: str, work: Path, build_flags: list[str]) -> RunningTarget:
        self._env = self._tracer.launch_env(work)
        out = str(Path(work) / self._out_bin)
        cmd = self._inject_flags(self._build_cmd, build_flags + self._extra_flags, out)
        env = {**os.environ, **self._env}
        subprocess.run(cmd, cwd=repo, env=env, capture_output=True, text=True,
                       timeout=600, check=True)
        return RunningTarget(kind="process", repo=repo, work=work, exe_path=out)

    @staticmethod
    def _inject_flags(build_cmd: list[str], flags: list[str], out: str) -> list[str]:
        """Insert coverage flags and the -o output right after the `build` verb. Pure."""
        cmd = list(build_cmd)
        try:
            i = cmd.index("build") + 1
        except ValueError:
            i = 1
        cmd[i:i] = [*flags, "-o", out]
        return cmd

    def seeds(self, db, scan_id: str) -> list[Input]:
        res = db.run_cypher(scan_id, _ENTRY_CYPHER, limit=200)
        rows = res.get("rows", [])
        seeds = [Input(kind="process", label=f"argv:{r.get('m')}", argv=()) for r in rows]
        return seeds or [Input(kind="process", label="argv:empty", argv=())]

    def send(self, target: RunningTarget, inp: Input) -> Response:
        env = {**os.environ, **self._env, "GOCOVERDIR": str(target.work / "covdata")}
        (target.work / "covdata").mkdir(parents=True, exist_ok=True)
        try:
            out = subprocess.run([target.exe_path, *inp.argv], input=inp.stdin,
                                 capture_output=True, env=env, timeout=30, check=False)
            return Response(ok=True, status=out.returncode)
        except (OSError, subprocess.SubprocessError) as e:
            return Response(ok=False, detail=str(e))

    def stop(self, target: RunningTarget) -> None:
        pass
