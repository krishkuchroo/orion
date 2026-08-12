"""Correlate a normalized RuntimeTrace back onto existing graph nodes. PURE — no I/O, no Neo4j.

This is the load-bearing module and the most-tested one. It answers two questions with only plain
data as input (a graph query, or a fake, supplies that data):

  1. Which CpgCall / CpgMethod nodes executed?  -> by (file_path, line).
  2. Which caller→callee pairs were observed?    -> resolve both endpoints to their containing method.

The hard part is that CpgMethod carries a declaration `line` but NO end line (see embed.py's 40-line
window workaround). We resolve containment structurally instead of guessing a window: within a file,
a covered line L belongs to the method with the GREATEST declaration line <= L (the closest preceding
`def`/`function`). That is exact enough for a boolean `executed` and a summed `hit_count`, and needs
no end line.
"""
from __future__ import annotations

import bisect
from collections.abc import Iterable

from .base import ObservedCall, RuntimeTrace, WritePlan


# ─────────────────────────── byte offset → line (JS/V8) ───────────────────────────

def build_line_starts(source: str) -> list[int]:
    """Byte offsets at which each line begins (`starts[i]` = offset of line i+1, 1-based lines).

    V8 coverage keys ranges by UTF-8 byte offset, so offsets are computed over the ENCODED bytes,
    not code points -- a multi-byte char must not shift the mapping. `starts[0]` is always 0."""
    starts = [0]
    data = source.encode("utf-8")
    for i, b in enumerate(data):
        if b == 0x0A:  # '\n'
            starts.append(i + 1)
    return starts


def offset_to_line(line_starts: list[int], offset: int) -> int:
    """1-based line containing byte `offset`. `line_starts` from build_line_starts (ascending).

    The line is the greatest start <= offset. bisect_right gives the count of starts <= offset,
    which is exactly the 1-based line number. Clamped to >=1 for a negative/degenerate offset."""
    if offset < 0:
        return 1
    return max(1, bisect.bisect_right(line_starts, offset))


# ─────────────────────────── containing-method resolution ───────────────────────────

class MethodResolver:
    """Resolve a (file_path, line) to the full_name of the CpgMethod that contains it.

    Built from the internal methods' declaration lines. A covered line L in file F resolves to the
    method in F with the greatest declaration line <= L. Methods with no file_path or a non-int line
    are simply absent from the index (they cannot anchor containment)."""

    def __init__(self, methods: Iterable[tuple[str, str, int]]) -> None:
        # methods: (full_name, file_path, line)
        by_file: dict[str, list[tuple[int, str]]] = {}
        for full_name, file_path, line in methods:
            if not file_path or not isinstance(line, int):
                continue
            by_file.setdefault(file_path, []).append((line, full_name))
        # Sort each file's methods by declaration line so bisect can find the closest preceding one.
        # Ties (two methods declared on the same line, rare) resolve to the last-inserted after sort;
        # deterministic given a stable input order.
        self._by_file = {f: sorted(v, key=lambda t: t[0]) for f, v in by_file.items()}
        self._lines = {f: [line for line, _ in v] for f, v in self._by_file.items()}

    def resolve(self, file_path: str, line: int) -> str | None:
        """The containing method's full_name, or None (line above the first method / unknown file)."""
        rows = self._by_file.get(file_path)
        if not rows:
            return None
        idx = bisect.bisect_right(self._lines[file_path], line) - 1
        if idx < 0:
            return None
        return rows[idx][1]


# ─────────────────────────── the correlation ───────────────────────────

def correlate(
    trace: RuntimeTrace,
    call_index: dict[tuple[str, int], list[str]],
    resolver: MethodResolver,
) -> WritePlan:
    """Turn a RuntimeTrace into a WritePlan. Pure.

    `call_index` maps (file_path, line) -> list of CpgCall uids on that line (several calls can share
    a line, e.g. `f(g(x))`; all are marked executed -- v1 is line-granular, not column-granular).
    `resolver` maps (file, line) -> containing CpgMethod full_name.

    Every trace item that correlates to nothing is COUNTED in `plan.dropped` (never silently lost)."""
    call_hits: dict[str, int] = {}
    method_hits: dict[str, int] = {}
    edges: dict[tuple[str, str], int] = {}
    dropped = {"coverage_no_call": 0, "coverage_no_method": 0, "edge_unresolved": 0}

    for h in trace.coverage:
        uids = call_index.get((h.file_path, h.line))
        if uids:
            for uid in uids:
                call_hits[uid] = call_hits.get(uid, 0) + h.hit_count
        else:
            dropped["coverage_no_call"] += 1
        m = resolver.resolve(h.file_path, h.line)
        if m is not None:
            method_hits[m] = method_hits.get(m, 0) + h.hit_count
        else:
            dropped["coverage_no_method"] += 1

    for c in trace.calls:
        caller = resolver.resolve(c.caller_file, c.caller_line)
        callee = resolver.resolve(c.callee_file, c.callee_line)
        if caller is None or callee is None or caller == callee:
            # Drop unresolved frames and self-edges (a method calling within itself is not a new
            # caller→callee linkage and would only add noise).
            dropped["edge_unresolved"] += 1
            continue
        edges[(caller, callee)] = edges.get((caller, callee), 0) + 1

    return WritePlan(call_hits=call_hits, method_hits=method_hits, edges=edges, dropped=dropped)


def count_novel_edges(
    edges: Iterable[tuple[str, str]],
    static_pairs: set[tuple[str, str]],
) -> int:
    """How many observed (caller, callee) pairs have NO corresponding static call path.

    `static_pairs` is the set of method→method pairs the static graph already links via
    CONTAINS_CALL+RESOLVES_TO. A novel edge is one the static CPG lacked -- the value metric (J).
    Deduplicated: each distinct pair counts once."""
    return sum(1 for pair in set(edges) if pair not in static_pairs)
