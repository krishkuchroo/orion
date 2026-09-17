"""Token-free tests for the tracer parsers (V8 coverage, V8 cpu-profile, Go covdata).

Pure parse over literal blobs -- no Node, no `go`, no filesystem. Spec §9 tests 6-7. Run:
    ./.venv/bin/python -m pytest tests/test_runtime_tracers.py
"""
from __future__ import annotations

from orion.runtime.go_tracer import parse_covdata_textfmt
from orion.runtime.v8_tracer import parse_cpu_profile, parse_v8_coverage


# ── 6. V8 coverage JSON → RuntimeTrace ─────────────────────────────────
def _reader(sources):
    return lambda rel: sources.get(rel)


def test_v8_parse_basic():
    src = "a();\nb();\nc();\n"  # lines at bytes 0,5,10
    blob = {"result": [{
        "url": "file:///repo/app/x.js",
        "functions": [{"ranges": [
            {"startOffset": 0, "endOffset": 4, "count": 2},   # line 1
            {"startOffset": 5, "endOffset": 9, "count": 0},   # line 2, NOT executed -> skipped
            {"startOffset": 10, "endOffset": 13, "count": 1}, # line 3
        ]}],
    }]}
    trace, malformed = parse_v8_coverage([blob], "/repo", _reader({"app/x.js": src}))
    hits = {(h.file_path, h.line): h.hit_count for h in trace.coverage}
    assert hits == {("app/x.js", 1): 2, ("app/x.js", 3): 1}
    assert malformed == 0


def test_v8_parse_skips_node_modules_and_internals():
    blob = {"result": [
        {"url": "node:internal/bootstrap", "functions": [{"ranges": [{"startOffset": 0, "endOffset": 1, "count": 1}]}]},
        {"url": "file:///repo/node_modules/x/i.js", "functions": [{"ranges": [{"startOffset": 0, "endOffset": 1, "count": 1}]}]},
    ]}
    trace, _ = parse_v8_coverage([blob], "/repo", _reader({}))
    assert trace.coverage == ()


def test_v8_parse_malformed_counted_not_crash():
    blobs = [
        {"result": "not a list"},                       # malformed blob
        {"result": [{"url": "file:///repo/a.js",
                     "functions": [{"ranges": [{"startOffset": "bad", "count": 1}]}]}]},  # bad range
        {"nokey": 1},                                    # malformed blob
    ]
    trace, malformed = parse_v8_coverage(blobs, "/repo", _reader({"a.js": "x\n"}))
    assert trace.coverage == ()
    assert malformed == 3


# ── V8 cpu-profile → observed calls ────────────────────────────────────
def test_cpu_profile_calls():
    prof = {"nodes": [
        {"id": 1, "callFrame": {"url": "file:///repo/a.js", "lineNumber": 9}, "children": [2]},
        {"id": 2, "callFrame": {"url": "file:///repo/b.js", "lineNumber": 4}, "children": []},
        {"id": 3, "callFrame": {"url": "node:internal", "lineNumber": 0}, "children": [1]},  # parent outside repo
    ]}
    trace, dropped = parse_cpu_profile(prof, "/repo")
    # node 1 -> 2 is in-repo (lines +1 to 1-based): a.js:10 -> b.js:5
    calls = [(c.caller_file, c.caller_line, c.callee_file, c.callee_line) for c in trace.calls]
    assert ("a.js", 10, "b.js", 5) in calls
    assert dropped == 1  # the node:internal -> 1 link


# ── 7. Go covdata textfmt → RuntimeTrace ───────────────────────────────
def test_go_covdata_parse():
    text = (
        "mode: set\n"
        "example.com/app/handler.go:12.2,14.16 2 3\n"   # lines 12-14, count 3
        "example.com/app/handler.go:20.2,20.10 1 0\n"   # count 0 -> skipped
        "garbage line\n"
    )
    trace = parse_covdata_textfmt(text, module_prefix="example.com/app")
    hits = {(h.file_path, h.line): h.hit_count for h in trace.coverage}
    assert hits == {("handler.go", 12): 3, ("handler.go", 13): 3, ("handler.go", 14): 3}
