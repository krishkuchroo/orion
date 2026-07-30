"""Item 0: build-phase instrumentation.

Token-free, infra-free tests for `graph_build._timed` -- the helper that times each build sub-phase
(parse / consume / normalize / persist) and emits a 'build'/'timing' progress event so a run's
progress.jsonl carries the split. The full build wiring is exercised by the Neo4j-backed
test_graph_build / test_stream_build suites and by a real scan; here we only prove the helper's
contract (pass-through result, non-negative duration, correct event, None-safe)."""
from __future__ import annotations

from orion import graph_build


def test_timed_passes_result_through_and_emits_event():
    events: list[dict] = []
    result, seconds = graph_build._timed(events.append, "persist", lambda: {"scan_id": "x", "nodes": 3})
    # the wrapped call's return value is passed straight through
    assert result == {"scan_id": "x", "nodes": 3}
    assert seconds >= 0.0
    # exactly one build/timing event, labeled, with the phase name in its detail
    assert len(events) == 1
    ev = events[0]
    assert ev["phase"] == "build" and ev["event"] == "timing"
    assert ev["detail"].startswith("persist: ") and ev["detail"].endswith("s")


def test_timed_is_none_safe():
    """on_event=None (the library-call path, e.g. tests calling build() without a logger) must not
    crash and must still return the result + duration."""
    result, seconds = graph_build._timed(None, "normalize", lambda: 42)
    assert result == 42
    assert seconds >= 0.0
