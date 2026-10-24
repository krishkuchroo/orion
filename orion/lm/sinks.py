"""Sink line for a code-only case, from Orion's own sink rules.

A graph flow (`slice.flow_slice`) always ends at a sink call. A code-only case (`cases.case_from_function`:
Stage 1 training rows and runtime cases with no flow) has no graph nodes, so `annotate` gives it ONE sink
node the same way the graph build would classify a call: `pathfind._classify_sink` (case-insensitive
substring over the code, highest `_SINK_SEVERITY` wins) run on each line of the target snippet, with the
profile `profiles.with_lm_sinks(profiles.GENERIC)` unless one is given. The best line wins; ties go to
the first line. Only the target snippet's code is read: never a label, lead or fix line, so vulnerable,
patched and negative rows go through one rule. There is no graph path, so `source_uid`/`sink_uid` stay
None. Pure and idempotent.
"""
from __future__ import annotations

from orion.graph import pathfind, profiles


def default_profile() -> profiles.Profile:
    return profiles.with_lm_sinks(profiles.GENERIC)


def _target(case: dict) -> dict | None:
    for sn in case.get("snippets") or []:
        if sn.get("role") == "target":
            return sn
    return None


def annotate(case: dict, profile=None) -> dict:
    """`case` plus a sink node when its target snippet has a line Orion's sink rules match (see the module
    doc); a new dict either way. A case with graph nodes or a sink_category already set comes back as is."""
    out = dict(case)
    if case.get("nodes") or case.get("sink_category") is not None:
        return out
    target = _target(case)
    start = target.get("start") if target else None
    if target is None or not isinstance(start, int) or isinstance(start, bool):
        return out
    prof = default_profile() if profile is None else profile
    best: tuple[int, int, str, str] | None = None            # (severity, offset, category, code)
    for offset, line in enumerate(str(target.get("code") or "").split("\n")):
        category = pathfind._classify_sink({"name": "", "code": line}, prof)
        if category is None:
            continue
        sev = pathfind._severity(category)
        if best is None or sev > best[0]:
            best = (sev, offset, category, line.strip())
    if best is None:
        return out
    _, offset, category, code = best
    out["sink_category"] = category
    out["nodes"] = [{"role": "sink", "file": target.get("file"), "line": start + offset,
                     "function": target.get("function"), "code": code}]
    return out
