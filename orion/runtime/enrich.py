"""Orchestrate the runtime stage: select → start → drive → collect → correlate → writeback → metric.

Best-effort by contract: any failure (unsupported target, unbootable app, missing toolchain, driver
error) emits a `runtime/error` event and returns without touching the graph -- exactly as the
semantic index degrades when the model is absent (cli.py). The static graph is never at risk here:
writeback only adds props/edges, never clears NODE_KEY labels.

This module owns the two graph READS correlation needs (the CpgCall (file,line)→uid index and the
CpgMethod (full_name,file,line) list); everything downstream is pure.
"""
from __future__ import annotations

import datetime as _dt
import tempfile
from pathlib import Path

from ..graphdb import GraphDB
from . import correlate, engine, targets, writeback
from .base import RuntimeTrace


def _event(event: str, detail: str = "") -> dict:
    return {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "phase": "runtime", "shape": None, "lead": None, "turn": None,
        "event": event, "detail": detail,
    }


def _call_index(db: GraphDB, scan_id: str) -> dict[tuple[str, int], list[str]]:
    """(file_path, line) -> [CpgCall uid]. Calls with line 0 / unknown file cannot correlate; they
    are still returned but will simply never be hit by a real (file,line) coverage key."""
    res = db.run_cypher(
        scan_id,
        "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.line > 0 "
        "RETURN c.file_path AS f, c.line AS l, c.uid AS uid", limit=1_000_000)
    idx: dict[tuple[str, int], list[str]] = {}
    for r in res.get("rows", []):
        idx.setdefault((r["f"], r["l"]), []).append(r["uid"])
    return idx


def _methods(db: GraphDB, scan_id: str) -> list[tuple[str, str, int]]:
    """(full_name, file_path, line) for internal methods with both file and line -- the containment
    resolver's input."""
    res = db.run_cypher(
        scan_id,
        "MATCH (m:CpgMethod {scan_id:$scan_id}) "
        "WHERE m.is_external = false AND m.file_path IS NOT NULL AND m.line IS NOT NULL "
        "RETURN m.full_name AS fn, m.file_path AS f, m.line AS l", limit=1_000_000)
    return [(r["fn"], r["f"], r["l"]) for r in res.get("rows", [])]


def enrich(scan_id: str, repo: str, profile=None, on_event=None, *, budget: int = 200) -> dict | None:
    """Run the runtime stage for `scan_id`. Returns a metric dict, or None if the stage was skipped.
    Never raises: a failure is an event + None."""
    def emit(ev, detail=""):
        if on_event is not None:
            on_event(_event(ev, detail))

    try:
        sel = targets.select(repo, profile)
        if sel is None:
            emit("warn", "no runtime target detected for this repo; skipping (graph unchanged)")
            return None
        driver, tracer = sel
        emit("start", f"runtime stage: driving target (budget {budget} inputs)")

        work = Path(tempfile.mkdtemp(prefix="orion_runtime_"))
        db = GraphDB()
        try:
            seeds = driver.seeds(db, scan_id)
            emit("tool", f"{len(seeds)} seed inputs from the graph")
            target = driver.start(repo, work, tracer.build_flags())
            try:
                engine.run(driver, tracer, target, seeds, budget=budget)
            finally:
                driver.stop(target)
            # Collect ONCE, AFTER stop. A long-running server flushes V8 coverage only on exit, so a
            # mid-run collect sees nothing; a compiled exe's GOCOVERDIR has accumulated every run's
            # data by now. This post-stop collect is authoritative for both shapes.
            trace = tracer.collect(work, repo)

            emit("tool", f"observed {len(trace.coverage)} covered lines, "
                         f"{len(trace.calls)} call frames")
            plan = _correlate(db, scan_id, trace)
        finally:
            db.close()

        metric = writeback.apply_plan(scan_id, plan)
        emit("done",
             f"{metric['calls_marked']} calls + {metric['methods_marked']} methods marked executed; "
             f"{metric['observed_edges']} OBSERVED_CALL edges "
             f"({metric['novel_edges']} with no static path); "
             f"{metric['unreachable_executed']} executed nodes were marked reachable_from_entry=false")
        return metric
    except Exception as exc:  # noqa: BLE001 -- best-effort stage; never abort the scan
        emit("error", f"runtime stage failed, continuing without it: {exc}")
        return None


def _correlate(db: GraphDB, scan_id: str, trace: RuntimeTrace):
    call_index = _call_index(db, scan_id)
    resolver = correlate.MethodResolver(_methods(db, scan_id))
    return correlate.correlate(trace, call_index, resolver)
