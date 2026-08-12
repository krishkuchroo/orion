"""Token-free tests for the engine loop and the HTTP route seeding.

Fake driver/tracer -- no boot, no network. Spec §9 tests 8-9. Run:
    ./.venv/bin/python -m pytest tests/test_runtime_engine.py
"""
from __future__ import annotations

from pathlib import Path

from orion.runtime import engine
from orion.runtime.base import Hit, Input, Response, RuntimeTrace, RunningTarget
from orion.runtime.http_driver import routes_from_rows


class _FakeDriver:
    """Records every input sent; returns nothing observable (coverage comes from the tracer)."""
    def __init__(self):
        self.sent = []

    def send(self, target, inp):
        self.sent.append(inp)
        return Response(ok=True)

    def stop(self, target):
        pass


class _FakeTracer:
    """Returns coverage keyed on the input label so distinct inputs 'reach' distinct lines."""
    def __init__(self):
        self.n = 0

    def collect(self, work, repo):
        self.n += 1
        # First few inputs reach new lines; then the target 'plateaus' (no new coverage).
        if self.n <= 3:
            return RuntimeTrace(coverage=(Hit("a.js", self.n, 1),))
        return RuntimeTrace(coverage=(Hit("a.js", 1, 1),))  # already-seen line

    def reset(self, work):
        pass


def _target():
    return RunningTarget(kind="http", repo=".", work=Path("."))


# ── 8. engine determinism ──────────────────────────────────────────────
def test_engine_deterministic():
    seeds = [Input(kind="http", label="s0", path="/"), Input(kind="http", label="s1", path="/x")]

    def run_once():
        d, t = _FakeDriver(), _FakeTracer()
        engine.run(d, t, _target(), seeds, budget=25, seed=42)
        return [(i.verb, i.path, i.label) for i in d.sent]

    a = run_once()
    b = run_once()
    assert a == b                      # same seed -> identical input sequence
    assert len(a) == 25                # budget respected exactly


def test_engine_accumulates_coverage():
    d, t = _FakeDriver(), _FakeTracer()
    trace = engine.run(d, t, _target(), [Input(kind="http", label="s", path="/")],
                       budget=10, seed=1)
    # The first 3 drives reach distinct lines 1,2,3 -> accumulated coverage has all three.
    lines = {h.line for h in trace.coverage}
    assert {1, 2, 3}.issubset(lines)


# ── 9. HTTP seeds from the graph's route rows ──────────────────────────
def test_http_seeds_from_graph():
    rows = [
        {"verb": "get", "code": 'app.get("/login", sessionHandler.displayLoginPage)'},
        {"verb": "post", "code": 'app.post("/login", sessionHandler.handleLoginRequest)'},
        {"verb": "get", "code": 'app.get("/login", sessionHandler.displayLoginPage)'},  # dup
        {"verb": "use", "code": 'app.use(express.static(...))'},                          # no path literal
    ]
    seeds = routes_from_rows(rows)
    got = [(s.verb, s.path) for s in seeds]
    assert got == [("GET", "/login"), ("POST", "/login")]   # deduped, mount skipped
