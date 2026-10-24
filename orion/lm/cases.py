"""CodeCase builder: a flow-slice dict (or a bare function) plus budgeted code snippets.

A CodeCase is the `slice.flow_slice` dict plus `snippets`: list of
`{"role": "target"|"source"|"caller"|"callee", "file", "function", "start", "end", "code"}`, target first.
A function case (no graph flow) also gets a one-node sink line from `orion/lm/sinks.annotate`.
`orion/lm/format.py` is the only thing that turns a case into a message. Local only, no network.
"""
from __future__ import annotations

from dataclasses import dataclass

from orion.lm.codeindex import MODULE, RepoIndex, Span
from orion.lm.sinks import annotate


@dataclass(frozen=True)
class CaseBudget:
    max_target_lines: int = 120
    max_context_lines: int = 40
    max_callers: int = 2
    max_callees: int = 2


def _window(start: int, end: int, limit: int, anchor: int) -> tuple[int, int]:
    """The whole span if it fits `limit` lines, else `limit` lines containing `anchor`, centred where possible."""
    if end - start + 1 <= limit:
        return start, end
    anchor = min(max(anchor, start), end)
    s = min(max(anchor - limit // 2, start), end - limit + 1)
    return s, s + limit - 1


def _snippet(index: RepoIndex, role: str, span: Span, limit: int, anchor: int) -> dict | None:
    s, e = _window(span.start, span.end, limit, anchor)
    try:
        code = index.source(span.file, s, e)
    except OSError:
        return None
    return {"role": role, "file": span.file, "function": span.name, "start": s, "end": e, "code": code}


def _first_line_naming(index: RepoIndex, span: Span, name: str) -> int:
    try:
        lines = index.source(span.file, span.start, span.end).split("\n")
    except OSError:
        return span.start
    for i, ln in enumerate(lines):
        if name in ln:
            return span.start + i
    return span.start


def _context(index: RepoIndex, target: Span, seen: set, budget: CaseBudget) -> list[dict]:
    out: list[dict] = []
    for role, spans in (("caller", index.callers(target, budget.max_callers)),
                        ("callee", index.callees(target, budget.max_callees))):
        for sp in spans:
            key = (sp.file, sp.start, sp.end)
            if key in seen:
                continue
            anchor = _first_line_naming(index, sp, target.name) if role == "caller" else sp.start
            snip = _snippet(index, role, sp, budget.max_context_lines, anchor)
            if snip is not None:
                seen.add(key)
                out.append(snip)
    return out


def _line(node: dict) -> int | None:
    v = node.get("line")
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def case_from_flow(flow: dict, index: RepoIndex, *, budget: CaseBudget = CaseBudget()) -> dict:
    case = dict(flow)
    case["snippets"] = []
    nodes = flow.get("nodes") or []
    if not nodes:
        return case
    sink, first = nodes[-1], nodes[0]
    line = _line(sink)
    if line is None or not sink.get("file"):
        return case
    target = index.enclosing(sink["file"], line)
    if target is None:
        return case
    tsnip = _snippet(index, "target", target, budget.max_target_lines, line)
    if tsnip is None:
        return case
    snippets, seen = [tsnip], {(target.file, target.start, target.end)}
    fline = _line(first)
    if fline is not None and first.get("file"):
        src = index.enclosing(first["file"], fline)
        if src is not None and src != target:
            ssnip = _snippet(index, "source", src, budget.max_context_lines, fline)
            if ssnip is not None:
                snippets.append(ssnip)
                seen.add((src.file, src.start, src.end))
    snippets += _context(index, target, seen, budget)
    case["snippets"] = snippets
    return case


def case_from_function(index: RepoIndex, file: str, span: Span, *, anchor: int, case_id: str = "F0",
                       budget: CaseBudget = CaseBudget()) -> dict:
    """A code-only case for `span` (no graph flow): target snippet + callers/callees, then
    `sinks.annotate` gives it the sink line Orion's sink rules find in the target, so training rows and
    runtime code-only cases look the same."""
    case = {"flow_id": case_id, "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None,
            "nodes": [], "snippets": []}
    tsnip = _snippet(index, "target", span, budget.max_target_lines, anchor)
    if tsnip is None:
        return case
    seen = {(span.file, span.start, span.end)}
    case["snippets"] = [tsnip] + _context(index, span, seen, budget)
    return annotate(case)
