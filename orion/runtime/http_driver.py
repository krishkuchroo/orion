"""HTTP driver: boot a web app, log in, seed requests from the graph, drive them. Stdlib only.

Seeds come from the graph being enriched: for an Express app the route table is already there as
`app.get/post(...)` CpgCall nodes (verified: `MATCH (c:CpgCall {scan_id}) WHERE c.name IN
['get','post',...] AND c.code STARTS WITH 'app.'`). Auth is a first-class step -- NodeGoat gates
nearly every route behind login middleware, so an unauthenticated fuzzer would only ever see
redirects to /login. `login()` establishes a session cookie before the loop starts.

Uses urllib/http.client -- NO new dependency.
"""
from __future__ import annotations

import http.cookiejar
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .base import Input, Response, RunningTarget

_ROUTE_CYPHER = (
    "MATCH (c:CpgCall {scan_id:$scan_id}) "
    "WHERE c.name IN ['get','post','put','delete'] AND c.code STARTS WITH 'app.' "
    "RETURN c.name AS verb, c.code AS code ORDER BY c.file_path, c.line"
)
_ROUTE_PATH_RE = re.compile(r"""app\.\w+\(\s*['"]([^'"]+)['"]""")


def routes_from_rows(rows: list[dict]) -> list[Input]:
    """Pure: graph rows -> seed Inputs. `code` is the raw `app.get("/path", handler)` source; we lift
    the verb and the path literal. Rows whose code has no string path (router mounts) are skipped."""
    seeds: list[Input] = []
    for r in rows:
        verb = (r.get("verb") or "get").upper()
        m = _ROUTE_PATH_RE.search(r.get("code") or "")
        if not m:
            continue
        path = m.group(1)
        if not path.startswith("/"):
            continue
        seeds.append(Input(kind="http", label=f"{verb} {path}", verb=verb, path=path))
    # Dedup (verb, path), stable order.
    seen: set = set()
    out: list[Input] = []
    for s in seeds:
        k = (s.verb, s.path)
        if k not in seen:
            seen.add(k)
            out.append(s)
    return out


class HttpDriver:
    """Drive a booted web app. `boot_cmd`/`base_url`/`login` are supplied by the target descriptor."""

    def __init__(self, boot_cmd: list[str], base_url: str, tracer,
                 login: dict | None = None, boot_wait: float = 25.0) -> None:
        self._boot_cmd = boot_cmd
        self._base_url = base_url.rstrip("/")
        self._tracer = tracer        # supplies launch_env(work) keyed to the ACTUAL work dir
        self._login = login          # {"path","fields":{...}} or None
        self._boot_wait = boot_wait
        self._opener = None

    def start(self, repo: str, work: Path, build_flags: list[str]) -> RunningTarget:
        import os
        # Key the coverage env to the SAME work dir the tracer will collect from -- otherwise the app
        # writes coverage somewhere the collector never looks (the bug this replaced).
        env = {**os.environ, **self._tracer.launch_env(work)}
        # New session so the whole tree (e.g. `npm start` and its `node` child) shares a process
        # group we can signal at once -- otherwise SIGTERM hits npm and the node child never flushes.
        proc = subprocess.Popen(self._boot_cmd, cwd=repo, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        self._wait_ready()
        if self._login:
            self._do_login()
        return RunningTarget(kind="http", repo=repo, work=work,
                             base_url=self._base_url, handle=proc)

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self._boot_wait
        while time.monotonic() < deadline:
            try:
                self._opener.open(self._base_url + "/", timeout=3)
                return
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)

    def _do_login(self) -> None:
        data = urllib.parse.urlencode(self._login.get("fields", {})).encode()
        url = self._base_url + self._login.get("path", "/login")
        try:
            self._opener.open(urllib.request.Request(url, data=data), timeout=10)
        except (urllib.error.URLError, OSError):
            pass  # best-effort; the loop still runs (and observes the auth-wall paths)

    def seeds(self, db, scan_id: str) -> list[Input]:
        res = db.run_cypher(scan_id, _ROUTE_CYPHER, limit=500)
        return routes_from_rows(res.get("rows", []))

    def send(self, target: RunningTarget, inp: Input) -> Response:
        url = target.base_url + inp.path
        req = urllib.request.Request(url, method=inp.verb,
                                     data=inp.body or None, headers=inp.headers or {})
        try:
            resp = self._opener.open(req, timeout=10)
            return Response(ok=True, status=getattr(resp, "status", 0))
        except urllib.error.HTTPError as e:
            return Response(ok=True, status=e.code)          # a 500 is signal, not a driver failure
        except (urllib.error.URLError, OSError, ValueError) as e:
            # ValueError: a mutated input produced a URL urllib refuses (control chars). One bad
            # input must degrade to a skipped request, never abort the whole run.
            return Response(ok=False, detail=str(e))

    def stop(self, target: RunningTarget) -> None:
        import os
        import signal
        proc = target.handle
        if proc is None:
            return
        # Signal the whole group so the node child (which holds the coverage) gets SIGTERM and the
        # preload's handler flushes on exit(0). Fall back to the single process if the group is gone.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
        try:
            proc.wait(timeout=15)   # give node time to write coverage + cpu profile
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
