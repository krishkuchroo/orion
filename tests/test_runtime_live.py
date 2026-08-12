"""@slow, skip-guarded end-to-end runtime tests. These EXECUTE the target, so they are opt-in.

They need infra that CI does not have, so each skips cleanly when its prerequisite is absent.

    # NodeGoat HTTP enrichment (needs Docker for mongo + the fixture with a built scan graph):
    ./.venv/bin/python -m pytest tests/test_runtime_live.py::test_nodegoat_http_enrich -m slow
    # Go exe enrichment (needs the `go` toolchain):
    ./.venv/bin/python -m pytest tests/test_runtime_live.py::test_go_exe_enrich -m slow
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from orion.graphdb import GraphDB

FIXTURE = Path("fixtures/NodeGoat")


def _db_or_skip() -> GraphDB:
    try:
        db = GraphDB()
        if not db.ping():
            pytest.skip("Neo4j not reachable")
        return db
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")


_MONGO_CONTAINER = "orion-nodegoat-mongo"


def _ensure_nodegoat_mongo() -> None:
    """Publish a seeded mongo on host 27017 for the host-run app. Idempotent: reuses a running
    container. NodeGoat's own compose only `expose`s mongo (no host port) and needs seeding, so the
    host-run model provisions its own. Best-effort; a failure just leaves the app unbootable → skip."""
    running = subprocess.run(["docker", "ps", "--filter", f"name={_MONGO_CONTAINER}",
                              "--format", "{{.Names}}"], capture_output=True, text=True)
    if _MONGO_CONTAINER not in running.stdout:
        subprocess.run(["docker", "rm", "-f", _MONGO_CONTAINER], capture_output=True)
        subprocess.run(["docker", "run", "-d", "-p", "27017:27017", "--name", _MONGO_CONTAINER,
                        "mongo:4.4"], capture_output=True)
        time.sleep(5)
    subprocess.run(["node", "artifacts/db-reset.js"], cwd=str(FIXTURE),
                   env={**__import__("os").environ, "MONGODB_URI": "mongodb://localhost:27017/nodegoat"},
                   capture_output=True)


@pytest.mark.slow
def test_nodegoat_http_enrich():
    """Boot NodeGoat, log in with the seeded creds, drive it, and assert the enrichment landed:
    at least one executed CpgCall AND (novel edge OR previously-unreachable code proven executed).

    Prereqs (each skips cleanly): the fixture, `npm install` already run (node_modules present),
    docker + node on PATH."""
    if not FIXTURE.exists():
        pytest.skip("NodeGoat fixture not present")
    if not (FIXTURE / "node_modules" / "express").exists():
        pytest.skip("NodeGoat deps not installed (run `npm install --omit=dev` in fixtures/NodeGoat)")
    if shutil.which("docker") is None or shutil.which("node") is None:
        pytest.skip("docker + node required (NodeGoat needs mongo)")

    from orion import graph_build
    from orion.runtime import enrich as enrich_fn

    db = _db_or_skip()
    # A descriptor makes the boot + login explicit (NodeGoat gates routes behind isLoggedIn).
    desc_dir = FIXTURE / ".orion"
    desc_dir.mkdir(exist_ok=True)
    (desc_dir / "runtime.json").write_text(
        '{"kind":"http","boot":["node","server.js"],"base_url":"http://localhost:4000",'
        '"login":{"path":"/login","fields":{"userName":"user1","password":"User1_123"}}}')
    _ensure_nodegoat_mongo()

    scan_id = graph_build.build(str(FIXTURE), stream=True)
    events = []
    metric = enrich_fn(scan_id, str(FIXTURE), None, on_event=events.append, budget=60)
    assert metric is not None, f"runtime stage skipped: {[e['detail'] for e in events]}"
    assert metric["calls_marked"] >= 1, f"no coverage correlated; events={[e['detail'] for e in events]}"
    # The value claim: at least one observed edge the static graph lacked, or (weaker) executed
    # coverage of previously-unreachable nodes.
    assert metric["novel_edges"] >= 1 or metric["unreachable_executed"] >= 1
    db.close()


@pytest.mark.slow
def test_go_exe_enrich(tmp_path):
    """Build a tiny Go program with `-cover`, drive it, and assert executed props correlate."""
    if shutil.which("go") is None:
        pytest.skip("go toolchain not available")

    from orion.runtime.go_tracer import GoCoverTracer
    from orion.runtime.process_driver import ProcessDriver
    from orion.runtime.base import Input

    (tmp_path / "go.mod").write_text("module example.com/tiny\n\ngo 1.21\n")
    (tmp_path / "main.go").write_text(
        "package main\n\nimport \"os\"\n\n"
        "func handle(a string) int { if a == \"boom\" { return 1 }; return 0 }\n\n"
        "func main() { arg := \"\"; if len(os.Args) > 1 { arg = os.Args[1] }; os.Exit(handle(arg)) }\n")

    tracer = GoCoverTracer(module_prefix="example.com/tiny")
    work = tmp_path / "work"
    work.mkdir()
    driver = ProcessDriver(build_cmd=["go", "build", "./..."], out_bin="tiny.bin", tracer=tracer)
    target = driver.start(str(tmp_path), work, tracer.build_flags())
    driver.send(target, Input(kind="process", argv=("boom",)))
    driver.stop(target)
    trace = tracer.collect(work, str(tmp_path))
    covered_files = {h.file_path for h in trace.coverage}
    assert "main.go" in covered_files, f"expected main.go coverage, got {covered_files}"
