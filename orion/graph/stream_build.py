"""Streaming per-function build: producer (Joern) -> segments.jsonl -> bounded consumer.

Phase 2 replaces the whole-graph joern-export (one 85x pretty-JSON blob that OOMs on large repos)
with a per-function producer that streams one segment per cpg.method. `run_producer` shells the
flatgraph script `joern_scripts/emit_segments.sc`; each line of `segments.jsonl` is a self-contained
function slice (vertices incl. the METHOD, wholly-inside edges, callsites, and the cross-method
REACHING_DEF closure seam) whose union reproduces `taint_summary.partition` + `_closure_edges`
exactly. See docs/superpowers/specs/2026-07-23-streaming-graph-build-design.md."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path

from .joern_adapter import _joern_bin, _jvm_flags, _ensure_greadlink

_SCRIPT = Path(__file__).parent / "joern_scripts" / "emit_segments.sc"


def run_producer(cpg_bin: str, out_jsonl: str) -> int:
    """Run the flatgraph producer over `cpg_bin`, writing one segment per line to `out_jsonl`;
    return the per-function segment count (total lines minus the one seg=-1 preamble line).

    The script loads the CPG with `CpgLoader.load` (the stored graph, no overlay re-application),
    so its node/edge set matches the joern-export GraphSON the Python partition keys on. Any non-zero
    exit or a missing output file is surfaced as a RuntimeError with captured stdout+stderr -- never a
    silent empty/partial run."""
    env = _ensure_greadlink(dict(os.environ))
    joern = _joern_bin("joern")
    r = subprocess.run(
        [str(joern), *_jvm_flags(), "--script", str(_SCRIPT),
         "--param", f"cpgPath={cpg_bin}", "--param", f"outPath={out_jsonl}"],
        capture_output=True, text=True, env=env)
    if r.returncode != 0 or not Path(out_jsonl).exists():
        raise RuntimeError(f"segment producer failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
    with open(out_jsonl) as fh:
        total = sum(1 for _ in fh)
    return total - 1   # minus the one preamble line
