"""Build a code graph for a repo and persist it into Orion's own Neo4j, returning the scan_id.

Standalone (no sentryV2 dependency): repo -> Joern CPG (~/joern) -> canonical schema -> Orion's
Neo4j on 7688. Single-scan lifecycle — each build clears its own scan partition and reloads, so
scans never accumulate or contaminate each other.

    scan_id = sha1(abspath(repo) + "|" + commit_sha_or_'nocommit')

is deterministic: the same repo at the same commit always resolves to the same scan_id (re-builds
MERGE idempotently).
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from datetime import datetime, timezone

from .contracts import OnEvent, ProgressEvent
from .graph import deps, joern_adapter, persist, profiles


def _event(phase: str, event: str, *, detail: str = "") -> ProgressEvent:
    """One build-phase ProgressEvent dict (see contracts.ProgressEvent for the key contract)."""
    return {"ts": datetime.now(timezone.utc).isoformat(), "phase": phase, "shape": None,
            "lead": None, "turn": None, "event": event, "detail": detail}


def _ambiguity_warning(repo_path: str, language: str | None,
                       frontend: str) -> ProgressEvent | None:
    """A 'build'/'warn' event when `repo` carries more than one language marker and the user did
    NOT pin --language; else None. Pure -- only file-existence checks, no Joern/Neo4j -- so the
    warn path is testable without any infrastructure. A polyglot repo is never scanned silently:
    the caller emits this so the picked frontend, and the --language escape hatch, are both visible.
    """
    if language is not None:
        return None
    markers = joern_adapter.detect_language_markers(repo_path)
    if len(markers) <= 1:
        return None
    found = ", ".join(name for name, _ in markers)
    return _event("build", "warn",
                  detail=(f"repo has multiple language markers ({found}); scanning as {frontend} "
                          f"-- override with `orion scan --language <frontend>` if wrong"))


def _commit_sha(repo: str) -> str:
    """The checked-out commit of `repo`, or 'nocommit' if it is not a git repo / git is absent.
    Degrades to the sentinel rather than crashing — a plain directory is a valid scan target."""
    try:
        out = subprocess.run(
            ["git", "-C", repo, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "nocommit"


def scan_id_for(repo_path: str) -> str:
    """Deterministic scan identity for a repo (abspath + commit)."""
    abspath = os.path.abspath(repo_path)
    return hashlib.sha1(f"{abspath}|{_commit_sha(abspath)}".encode("utf-8")).hexdigest()


def build(repo_path: str, language: str | None = None,
          on_event: OnEvent | None = None, *,
          stream: bool = False, queue_size: int = 64,
          scan_id: str | None = None, mem_stats_path: str | None = None) -> str:
    """Build `repo_path` into Orion's graph and return its scan_id. Clears then loads that scan.

    `language` pins the Joern frontend (jssrc/pythonsrc/gosrc/javasrc), overriding auto-detection;
    when omitted the frontend is guessed from the repo's markers and -- if `on_event` is given and
    the repo is polyglot -- a 'warn' event names the pick and the --language override.

    `stream=True` takes the streaming per-function build (parse/reuse cpg.bin, NO whole-graph export;
    the per-function producer -> bounded consumer assembles the SAME envelope) instead of the legacy
    joern-export blob; `queue_size` bounds how many function segments the consumer decodes at once.
    `scan_id` overrides the deterministic identity so two builds of the SAME repo (e.g. a legacy vs a
    stream parity check) persist into DISTINCT partitions instead of clobbering each other.

    `mem_stats_path` is a stream-only diagnostic hook (Task 10): when set, the stream branch's
    `build_envelope` writes a measured peak-RSS breakdown JSON there. It is IGNORED on the legacy
    path (which has no bounded consumer to measure); passing it never changes the returned scan_id."""
    scan_id = scan_id or scan_id_for(repo_path)
    frontend, display_language = joern_adapter.resolve_language(repo_path, language)
    if on_event is not None:
        warn = _ambiguity_warning(repo_path, language, frontend)
        if warn is not None:
            on_event(warn)
    profile = profiles.select_profile(repo_path, display_language)
    if stream:
        import tempfile
        from pathlib import Path
        from .graph import stream_build
        cpg_bin = joern_adapter.ensure_cpg(repo_path, frontend)   # parse or reuse cpg.bin, NO export
        work = Path(tempfile.mkdtemp(prefix="orion_stream_"))
        envelope = stream_build.build_envelope(str(cpg_bin), work, profile, queue_size=queue_size,
                                               mem_stats_path=mem_stats_path)
    else:
        envelope = joern_adapter.export_repo(repo_path, frontend, profile)
    dependencies = deps.parse_dependencies(repo_path)
    batch = joern_adapter.normalize(envelope, scan_id, language=display_language,
                                    dependencies=dependencies)
    persist.persist(batch)
    return scan_id
