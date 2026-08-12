"""Frozen data contracts and seam interfaces for the runtime stage.

Like `orion/contracts.py` is the spine of discovery/verify, this is the spine of the runtime stage:
the tracer, the correlator, and the writeback all speak in these types. Everything here is pure
data or a `Protocol`; no I/O, no Neo4j, no subprocess. The two impure seams (`Driver`, `Tracer`) are
declared as Protocols so a fake satisfies them in a token-free test.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


# ─────────────────────────── normalized trace ───────────────────────────

@dataclass(frozen=True)
class Hit:
    """One executed source location. `file_path` is repo-relative (matches CpgCall.file_path)."""
    file_path: str
    line: int
    hit_count: int


@dataclass(frozen=True)
class ObservedCall:
    """One caller→callee pair seen in a profiler's call tree. Endpoints are source locations that
    the correlator resolves to containing CpgMethods; a location that resolves to no method is
    dropped, never fabricated into an edge."""
    caller_file: str
    caller_line: int
    callee_file: str
    callee_line: int


@dataclass(frozen=True)
class RuntimeTrace:
    """What a Tracer produces: the two independent signals (coverage, call tree), never conflated.
    `calls` is empty when the language/tracer has no call-tree source (props-only enrichment)."""
    coverage: tuple[Hit, ...] = ()
    calls: tuple[ObservedCall, ...] = ()

    def merge(self, other: "RuntimeTrace") -> "RuntimeTrace":
        """Union two traces (the engine accumulates one per input). Coverage hit_counts on the same
        (file, line) are summed; observed calls are unioned. Pure; returns a new trace."""
        acc: dict[tuple[str, int], int] = {}
        for h in (*self.coverage, *other.coverage):
            acc[(h.file_path, h.line)] = acc.get((h.file_path, h.line), 0) + h.hit_count
        coverage = tuple(Hit(f, l, c) for (f, l), c in acc.items())
        calls = tuple(dict.fromkeys((*self.calls, *other.calls)))  # dedup, order-stable
        return RuntimeTrace(coverage=coverage, calls=calls)


# ─────────────────────────── the write plan ───────────────────────────

@dataclass(frozen=True)
class WritePlan:
    """The pure output of correlation: what writeback should apply. No DB handle, no Cypher here.

    - `call_hits`   : CpgCall.uid -> summed hit_count (nodes to mark executed).
    - `method_hits` : CpgMethod.full_name -> summed hit_count.
    - `edges`       : (caller_full_name, callee_full_name) -> summed hits (OBSERVED_CALL edges).
    - `dropped`     : counts of trace items that correlated to nothing (surfaced, never silent).
    """
    call_hits: dict[str, int] = field(default_factory=dict)
    method_hits: dict[str, int] = field(default_factory=dict)
    edges: dict[tuple[str, str], int] = field(default_factory=dict)
    dropped: dict[str, int] = field(default_factory=dict)


# ─────────────────────────── driver seam ───────────────────────────

@dataclass
class Input:
    """One thing to feed the target. For HTTP: verb+path+body+headers. For a process: argv+stdin.
    A plain mutable bag so the engine's mutator can derive variants cheaply."""
    kind: str                      # "http" | "process"
    label: str = ""                # human-readable, for progress events
    # http
    verb: str = "GET"
    path: str = "/"
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    # process
    argv: tuple[str, ...] = ()
    stdin: bytes = b""


@dataclass
class Response:
    """The observable result of one Input (status/output). The engine does not judge it; coverage
    delta is the only feedback signal. Kept for future crash detection (stage 2)."""
    ok: bool = True
    status: int = 0
    detail: str = ""


@dataclass
class RunningTarget:
    """Opaque handle a Driver hands back from start() and consumes in send()/stop(). Concrete drivers
    stuff fields in; the engine only reads `repo` and `work` (for tracer.collect) and passes the rest
    through to the driver."""
    kind: str
    repo: str                       # source root, for the tracer to read files by relpath
    work: Path                      # dump dir the tracer writes/reads (coverage/profile)
    base_url: str = ""
    exe_path: str = ""
    handle: object | None = None    # e.g. a Popen, held by the driver


class Driver(Protocol):
    """How to boot and drive one target shape. Impure by nature; the ONLY execution seam."""

    def start(self, repo: str, work: Path, build_flags: list[str]) -> RunningTarget: ...
    def seeds(self, db, scan_id: str) -> list[Input]: ...
    def send(self, target: RunningTarget, inp: Input) -> Response: ...
    def stop(self, target: RunningTarget) -> None: ...


class Tracer(Protocol):
    """How to instrument a target and parse its coverage/profile dumps into a RuntimeTrace."""

    def launch_env(self, work: Path) -> dict[str, str]: ...
    def build_flags(self) -> list[str]: ...
    def collect(self, work: Path, repo: str) -> RuntimeTrace: ...
    def reset(self, work: Path) -> None: ...
