"""V8/Node tracer: zero-instrumentation JS coverage + sampled call tree.

Node honors `NODE_V8_COVERAGE=<dir>` (per-function byte-range coverage JSON dumped on exit) and
`--cpu-prof` (a sampled call tree with file+line call frames). The JS "instrumentation" is therefore
just an env var and a flag on the target's own `npm start` -- no rebuild.

`parse_v8_coverage` and `parse_cpu_profile` are PURE over the dumped JSON + a source reader, so they
are unit-tested on literal blobs. Only `collect` touches the filesystem.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from .base import Hit, ObservedCall, RuntimeTrace
from .correlate import build_line_starts, offset_to_line

COVERAGE_SUBDIR = "v8-coverage"
CPUPROF_SUBDIR = "cpu-prof"


def _script_to_relpath(url: str, repo: str) -> str | None:
    """Map a V8 script url (a file: URL or absolute path) to a repo-relative path, or None if it is
    outside the repo (node internals, node_modules). Correlation only wants first-party files."""
    if not url:
        return None
    path = urlparse(url).path if url.startswith("file:") else url
    if not path or url.startswith("node:") or "node_modules" in path:
        return None
    try:
        rel = os.path.relpath(os.path.realpath(path), os.path.realpath(repo))
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    return rel


def parse_v8_coverage(blobs: list[dict], repo: str, read_source) -> tuple[RuntimeTrace, int]:
    """V8 coverage JSON blobs -> (RuntimeTrace with coverage hits, malformed_count).

    Each blob has `result: [{url, functions: [{ranges: [{startOffset, endOffset, count}]}]}]`.
    `read_source(relpath) -> str | None` supplies file text so byte offsets become lines. A blob or
    entry that is malformed is COUNTED and skipped, never crashes the parse."""
    per_line: dict[tuple[str, int], int] = {}
    line_starts_cache: dict[str, list[int] | None] = {}
    malformed = 0

    def line_starts_for(rel: str) -> list[int] | None:
        if rel not in line_starts_cache:
            src = read_source(rel)
            line_starts_cache[rel] = build_line_starts(src) if src is not None else None
        return line_starts_cache[rel]

    for blob in blobs:
        results = blob.get("result") if isinstance(blob, dict) else None
        if not isinstance(results, list):
            malformed += 1
            continue
        for entry in results:
            if not isinstance(entry, dict):
                malformed += 1
                continue
            rel = _script_to_relpath(entry.get("url", ""), repo)
            if rel is None:
                continue
            starts = line_starts_for(rel)
            if starts is None:
                continue
            for fn in entry.get("functions", []) or []:
                for rng in (fn.get("ranges", []) if isinstance(fn, dict) else []) or []:
                    try:
                        count = int(rng["count"])
                        start = int(rng["startOffset"])
                    except (KeyError, TypeError, ValueError):
                        malformed += 1
                        continue
                    if count <= 0:
                        continue  # a range with count 0 means NOT executed -- skip it
                    line = offset_to_line(starts, start)
                    key = (rel, line)
                    per_line[key] = per_line.get(key, 0) + count

    coverage = tuple(Hit(f, l, c) for (f, l), c in per_line.items())
    return RuntimeTrace(coverage=coverage), malformed


def parse_cpu_profile(profile: dict, repo: str) -> tuple[RuntimeTrace, int]:
    """A V8 `--cpu-prof` JSON profile -> (RuntimeTrace with observed calls, dropped_count).

    The profile has `nodes: [{id, callFrame:{url,lineNumber}, children:[id...]}]`. Each parent→child
    link whose both frames map into the repo becomes an ObservedCall. `lineNumber` is 0-based in a
    cpu profile, so we +1 to match graph 1-based lines. Frames outside the repo are skipped."""
    nodes = profile.get("nodes") if isinstance(profile, dict) else None
    if not isinstance(nodes, list):
        return RuntimeTrace(), 1
    by_id: dict[int, dict] = {}
    for n in nodes:
        if isinstance(n, dict) and "id" in n:
            by_id[n["id"]] = n

    def frame(n: dict) -> tuple[str, int] | None:
        cf = n.get("callFrame") if isinstance(n, dict) else None
        if not isinstance(cf, dict):
            return None
        rel = _script_to_relpath(cf.get("url", ""), repo)
        if rel is None:
            return None
        ln = cf.get("lineNumber")
        if not isinstance(ln, int):
            return None
        return (rel, ln + 1)

    calls: list[ObservedCall] = []
    dropped = 0
    for n in nodes:
        pf = frame(n)
        for child_id in (n.get("children", []) if isinstance(n, dict) else []) or []:
            child = by_id.get(child_id)
            cf = frame(child) if child is not None else None
            if pf is None or cf is None:
                dropped += 1
                continue
            calls.append(ObservedCall(pf[0], pf[1], cf[0], cf[1]))
    return RuntimeTrace(calls=tuple(calls)), dropped


class V8Tracer:
    """Tracer instance for Node targets."""

    def build_flags(self) -> list[str]:
        return []  # no rebuild for JS

    def launch_env(self, work: Path) -> dict[str, str]:
        cov = work / COVERAGE_SUBDIR
        cov.mkdir(parents=True, exist_ok=True)
        # --cpu-prof is a node CLI flag; pass it via NODE_OPTIONS so it rides the target's own start.
        prof = work / CPUPROF_SUBDIR
        prof.mkdir(parents=True, exist_ok=True)
        # NODE_V8_COVERAGE and --cpu-prof flush ONLY on a clean process exit. A long-running server
        # killed with SIGTERM never exits cleanly, so nothing is written. This preload traps the
        # termination signals and calls process.exit(0), which fires the exit hooks that flush both
        # coverage and the cpu profile. Required via NODE_OPTIONS so it also rides `npm start`'s child.
        preload = work / "orion_exit_flush.cjs"
        preload.write_text(
            "process.on('SIGTERM', () => process.exit(0));\n"
            "process.on('SIGINT', () => process.exit(0));\n")
        return {
            "NODE_V8_COVERAGE": str(cov),
            "NODE_OPTIONS": f"--cpu-prof --cpu-prof-dir={prof} --require {preload}",
        }

    def reset(self, work: Path) -> None:
        pass  # coverage accumulates across the run; we collect once at the end

    def collect(self, work: Path, repo: str) -> RuntimeTrace:
        cov_dir = work / COVERAGE_SUBDIR
        prof_dir = work / CPUPROF_SUBDIR
        blobs: list[dict] = []
        if cov_dir.is_dir():
            for f in cov_dir.glob("*.json"):
                try:
                    blobs.append(json.loads(f.read_text()))
                except (OSError, ValueError):
                    continue
        read_source = _fs_reader(repo)
        trace, _ = parse_v8_coverage(blobs, repo, read_source)
        if prof_dir.is_dir():
            for f in prof_dir.glob("*.cpuprofile"):
                try:
                    prof = json.loads(f.read_text())
                except (OSError, ValueError):
                    continue
                sub, _ = parse_cpu_profile(prof, repo)
                trace = trace.merge(sub)
        return trace


def _fs_reader(repo: str):
    def read(rel: str) -> str | None:
        try:
            return (Path(repo) / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    return read
