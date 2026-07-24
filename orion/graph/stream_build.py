"""Streaming per-function build: producer (Joern) -> segments.jsonl -> bounded consumer.

Phase 2 replaces the whole-graph joern-export (one 85x pretty-JSON blob that OOMs on large repos)
with a per-function producer that streams one segment per cpg.method. `run_producer` shells the
flatgraph script `joern_scripts/emit_segments.sc`; each line of `segments.jsonl` is a self-contained
function slice (vertices incl. the METHOD, wholly-inside edges, callsites, and the cross-method
REACHING_DEF closure seam) whose union reproduces `taint_summary.partition` + `_closure_edges`
exactly. See docs/superpowers/specs/2026-07-23-streaming-graph-build-design.md."""
from __future__ import annotations
import json
import os
import subprocess
from collections import Counter
from itertools import islice
from pathlib import Path

from .joern_adapter import _joern_bin, _jvm_flags, _ensure_greadlink, project_graphson
from . import taint_summary as T  # noqa: F401  (pass 2 / Task 7 threads summaries through this)

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


# ─────────────────────── consumer pass 1: bounded-window structural projection ───────────────────────
def _read_preamble(path: str) -> dict:
    """Line 0 is always the seg=-1 preamble (the FILE nodes)."""
    with open(path) as fh:
        return json.loads(fh.readline())


def _iter_segments(path: str, start: int = 1):
    """Yield (line_index, record) for per-function records, skipping the line-0 preamble. `start`
    is the resume cursor (>= 1)."""
    with open(path) as fh:
        for i, line in enumerate(fh):
            if i == 0 or i < start:
                continue
            yield i, json.loads(line)


def _seg_to_graphson(seg: dict) -> dict:
    """One per-function segment -> the {vertices, edges} shape project_graphson/partition consume.
    The METHOD vertex is ALREADY inside seg['vertices'] (spec §5), so do NOT re-prepend it."""
    return {"vertices": seg["vertices"], "edges": seg["edges"]}


def _structural(seg: dict, profile) -> tuple[list, list]:
    """Structural nodes + edges for ONE per-function segment.

    CONTAINS_CALL comes from the slice's own intra CONTAINS edges. CALL (-> RESOLVES_TO) is
    reconstructed from `seg['call_edges']` -- EVERY CALL -> METHOD out-edge (operator calls and every
    callee of a multi-callee site), matching what legacy `project_graphson` persists (a RESOLVES_TO
    for EVERY CALL -> METHOD edge). It is NOT built from the taint `callsites` field, which carries
    only real calls with a single callee (a strict subset, short 1638 edges on NodeGoat).
    SOURCE_FILE (-> DEFINED_IN) is synthesized from source_file.file_id. FLOWS_TO is excluded
    (Task 7 adds it)."""
    proj = project_graphson(_seg_to_graphson(seg), profile=profile)
    nodes = list(proj["nodes"])
    edges = [e for e in proj["edges"] if e["label"] == "CONTAINS"]     # intra CONTAINS_CALL
    for call_id, callee_id in seg["call_edges"]:
        edges.append({"label": "CALL", "out": call_id, "in": callee_id,
                      "out_label": "CALL", "in_label": "METHOD"})
    fid = seg["source_file"]["file_id"]
    if fid is not None:
        edges.append({"label": "SOURCE_FILE", "out": seg["method_id"], "in": fid,
                      "out_label": "METHOD", "in_label": "FILE"})
    return nodes, edges


def collect_structural(cpg_bin: str, work, profile, *, queue_size: int = 64):
    """Test-only pass-1 driver: run the producer, then project structural nodes/edges from the
    stream with a bounded window (<= queue_size segments decoded at once). Returns the structural
    node set `{(label, id)}` and the structural edge multiset `Counter((label, out, in))` over
    CONTAINS_CALL + RESOLVES_TO + DEFINED_IN (FLOWS_TO excluded, Task 7). Must equal legacy
    `project_graphson`'s node set and non-FLOWS_TO edge multiset EXACTLY."""
    work = Path(work); work.mkdir(parents=True, exist_ok=True)
    out = work / "segments.jsonl"
    run_producer(cpg_bin, str(out))
    node_set: set = set()
    edge_ctr: Counter = Counter()
    for f in _read_preamble(str(out))["files"]:
        node_set.add(("FILE", f["id"]))                    # FILE nodes come only from the preamble
    it = _iter_segments(str(out))
    while True:
        batch = list(islice(it, queue_size))               # bounded window: <= queue_size at once
        if not batch:
            break
        for _, seg in batch:
            nodes, edges = _structural(seg, profile)
            node_set.update((n["label"], n["id"]) for n in nodes)
            edge_ctr.update((e["label"], e["out"], e["in"]) for e in edges)
    return node_set, edge_ctr
