"""Token-free tests for the runtime correlation core (orion/runtime/correlate.py).

Pure: no Neo4j, no boot, no network, no `go`. Covers spec §9 tests 1-5. Run:
    ./.venv/bin/python -m pytest tests/test_runtime_correlate.py
"""
from __future__ import annotations

from orion.runtime.base import Hit, ObservedCall, RuntimeTrace
from orion.runtime.correlate import (
    MethodResolver,
    build_line_starts,
    correlate,
    count_novel_edges,
    offset_to_line,
)


# ── 1. byte offset → line ──────────────────────────────────────────────
def test_byte_to_line():
    src = "line1\nline2\nline3\n"  # line starts at bytes 0, 6, 12, (18)
    starts = build_line_starts(src)
    assert starts == [0, 6, 12, 18]
    assert offset_to_line(starts, 0) == 1          # first byte
    assert offset_to_line(starts, 5) == 1          # the '\n' of line 1
    assert offset_to_line(starts, 6) == 2          # first byte of line 2
    assert offset_to_line(starts, 13) == 3         # inside line 3
    assert offset_to_line(starts, 999) == 4        # past the end -> last line
    assert offset_to_line(starts, -1) == 1         # degenerate -> clamp


def test_byte_to_line_multibyte():
    # A multi-byte char must not shift the offset→line mapping (V8 offsets are byte offsets).
    src = "é = 1\nx = 2\n"   # 'é' is 2 bytes; line 2 starts after "é = 1\n" = 7 bytes
    starts = build_line_starts(src)
    assert starts[1] == 7
    assert offset_to_line(starts, 7) == 2


# ── 2. containing-method resolution (no end line) ──────────────────────
def test_containing_method():
    methods = [
        ("f.js::a", "f.js", 10),
        ("f.js::b", "f.js", 30),
        ("g.js::c", "g.js", 5),
    ]
    r = MethodResolver(methods)
    assert r.resolve("f.js", 9) is None            # above the first method
    assert r.resolve("f.js", 10) == "f.js::a"      # exactly at the decl
    assert r.resolve("f.js", 25) == "f.js::a"      # between a and b -> a
    assert r.resolve("f.js", 30) == "f.js::b"
    assert r.resolve("f.js", 999) == "f.js::b"     # after the last -> last
    assert r.resolve("g.js", 8) == "g.js::c"
    assert r.resolve("unknown.js", 5) is None      # unknown file


def test_containing_method_skips_bad_rows():
    methods = [
        ("ok", "f.js", 10),
        ("no_file", "", 5),
        ("no_line", "f.js", None),   # non-int line
    ]
    r = MethodResolver(methods)
    assert r.resolve("f.js", 12) == "ok"
    # the no_file / no_line rows never anchor containment
    assert r.resolve("", 5) is None


# ── 3. coverage → props ────────────────────────────────────────────────
def test_coverage_to_props():
    call_index = {
        ("f.js", 10): ["uidA", "uidB"],   # two calls share line 10
        ("f.js", 12): ["uidC"],
    }
    resolver = MethodResolver([("f.js::a", "f.js", 8)])
    trace = RuntimeTrace(coverage=(
        Hit("f.js", 10, 3),
        Hit("f.js", 10, 1),   # same line hit again -> hit_count sums
        Hit("f.js", 12, 5),
        Hit("f.js", 999, 2),  # correlates to no call
    ))
    plan = correlate(trace, call_index, resolver)
    assert plan.call_hits == {"uidA": 4, "uidB": 4, "uidC": 5}
    assert plan.method_hits["f.js::a"] == 3 + 1 + 5 + 2   # all lines fall in method a
    assert plan.dropped["coverage_no_call"] == 1          # line 999


def test_line_zero_correlates_to_nothing():
    # A CpgCall whose Joern line defaulted to 0 is not in the index keyed by real lines.
    call_index = {("f.js", 5): ["uid5"]}
    resolver = MethodResolver([])
    trace = RuntimeTrace(coverage=(Hit("f.js", 0, 9),))
    plan = correlate(trace, call_index, resolver)
    assert plan.call_hits == {}
    assert plan.dropped["coverage_no_call"] == 1


# ── 4. observed calls → edges ──────────────────────────────────────────
def test_observed_call_edges():
    resolver = MethodResolver([
        ("f.js::a", "f.js", 10),
        ("f.js::b", "f.js", 30),
    ])
    trace = RuntimeTrace(calls=(
        ObservedCall("f.js", 15, "f.js", 32),   # a -> b
        ObservedCall("f.js", 16, "f.js", 33),   # a -> b again (hits sum)
        ObservedCall("f.js", 15, "nope.js", 1), # callee resolves to nothing -> dropped
        ObservedCall("f.js", 15, "f.js", 16),   # a -> a (self edge) -> dropped
    ))
    plan = correlate(trace, {}, resolver)
    assert plan.edges == {("f.js::a", "f.js::b"): 2}
    assert plan.dropped["edge_unresolved"] == 2


# ── 5. novel edge count (the value metric J) ───────────────────────────
def test_novel_edge_count():
    static = {("a", "b"), ("b", "c")}
    observed = [("a", "b"), ("a", "d"), ("a", "d"), ("e", "f")]
    # (a,b) is static; (a,d) and (e,f) are novel; (a,d) dedups to one.
    assert count_novel_edges(observed, static) == 2
