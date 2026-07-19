"""Live progress log for a scan run.

Every `ProgressEvent` the pipeline emits is appended as one JSON line to
`<run_dir>/progress.jsonl`, so a run is watchable in real time (`orion scan --watch`) and
inspectable after the fact -- and stoppable: `tail` polls the file rather than blocking on a
socket/pipe, so a caller can end it cleanly (Ctrl-C, or by flipping the `stop` signal) without
tearing down the pipeline itself.

Only needs `contracts` + stdlib, so this module (and its tests) stay usable without Neo4j, the
`claude` CLI, or the embedding model being anywhere nearby.
"""
from __future__ import annotations

import json
import os
import threading
import time

from .contracts import OnEvent, ProgressEvent

_LOG_NAME = "progress.jsonl"
_POLL_SECONDS = 0.25


def _log_path(run_dir: str) -> str:
    return os.path.join(run_dir, _LOG_NAME)


def _format_event(evt: dict) -> str:
    """One human-readable summary line for a ProgressEvent. Shared by the live logger's stdout
    print and by `tail`, so a run looks the same whether you watched it live or replayed the log.
    """
    phase = evt.get("phase", "?")
    event = evt.get("event", "?")
    bits = [f"[{phase}/{event}]"]
    if evt.get("shape"):
        bits.append(f"shape={evt['shape']}")
    if evt.get("lead") is not None:
        bits.append(f"lead={evt['lead']}")
    if evt.get("turn") is not None:
        bits.append(f"turn={evt['turn']}")
    detail = evt.get("detail")
    if detail:
        bits.append(f"- {detail}")
    return " ".join(bits)


def run_logger(run_dir: str, quiet: bool = False) -> OnEvent:
    """Return an `on_event(ProgressEvent)` callable that appends each event to
    `<run_dir>/progress.jsonl` and (unless `quiet`) prints a one-line summary to stdout.

    Safe to call from a worker thread: a lock guards both the file append and the print so
    concurrent callers (e.g. parallel discovery shapes) never interleave a partial line.
    """
    os.makedirs(run_dir, exist_ok=True)
    path = _log_path(run_dir)
    lock = threading.Lock()

    def on_event(evt: ProgressEvent) -> None:
        line = json.dumps(evt, default=str)
        with lock:
            try:
                with open(path, "a") as f:
                    f.write(line + "\n")
                if not quiet:
                    print(_format_event(evt))
            except OSError:
                # Best-effort observability, never fatal: a disk-full/broken-pipe/permissions
                # failure here must not crash the pipeline it's supposed to be observing (a live
                # scan hit ENOSPC on this exact write and it took the whole run down with it).
                pass

    return on_event


def read_events(run_dir: str) -> list[dict]:
    """Pure helper: parse every JSON line currently in `<run_dir>/progress.jsonl`, in order.
    Returns `[]` if the log doesn't exist yet (a run that hasn't started writing). Factored out
    of `tail` so both it and tests can read the log without duplicating the parsing.
    """
    path = _log_path(run_dir)
    if not os.path.exists(path):
        return []
    events: list[dict] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


def _is_stopped(stop) -> bool:
    """`stop` is either a `threading.Event` or a zero-arg predicate returning truthy when done."""
    if isinstance(stop, threading.Event):
        return stop.is_set()
    return bool(stop())


def tail(run_dir: str, stop) -> None:
    """Live `--watch` view: print new events from `<run_dir>/progress.jsonl` as they arrive,
    until `stop` says to end. `stop` may be a `threading.Event` (checked via `is_set()`) or a
    zero-arg callable predicate. Polls on a short interval rather than blocking, so a Ctrl-C
    (raised as `KeyboardInterrupt` in the polling loop) or the caller flipping `stop` both exit
    within one poll tick -- clean, no dangling readers.
    """
    seen = 0
    try:
        while not _is_stopped(stop):
            events = read_events(run_dir)
            for evt in events[seen:]:
                print(_format_event(evt))
            seen = len(events)
            time.sleep(_POLL_SECONDS)
    except KeyboardInterrupt:
        pass
    finally:
        # Final drain: pick up anything written in the gap between the last poll and stop being
        # observed, so the tail never silently drops the run's last few events.
        events = read_events(run_dir)
        for evt in events[seen:]:
            print(_format_event(evt))
