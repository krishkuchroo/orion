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
from collections import Counter, defaultdict
from itertools import islice
from pathlib import Path

from .joern_adapter import _joern_bin, _jvm_flags, _ensure_greadlink, project_graphson
from . import joern_adapter as J    # Task 7 reuses the split entry-point test (_entry_method_ids_from)
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


# ─────────────────────── consumer pass 2: summary-stitch taint (FLOWS_TO) + full envelope ───────────────────────
def _method_fullname(seg: dict):
    """The FULL_NAME of a segment's own METHOD vertex (== joern_adapter._prop for a single-cardinality
    property: the producer serializes propertiesMap as a plain scalar, no GraphSON type-tag)."""
    mv = next(v for v in seg["vertices"] if v["id"] == seg["method_id"])
    return mv["properties"].get("FULL_NAME")


def _seg_cross_rd(seg: dict) -> dict:
    """One segment's cross-method REACHING_DEF source->targets map (the closure seam `build_summary`
    consults as `cross_rd`), rebuilt from the producer's flat `[[out,in],...]` pairs."""
    d = defaultdict(list)
    for (o, i) in seg["cross_rd"]:
        d[o].append(i)
    return dict(d)


def build_envelope(cpg_bin: str, work, profile, *, queue_size: int = 64,
                   resume: bool = False, simulate_crash_after: int = None) -> dict:
    """Assemble the SAME `{"nodes","edges","entry_methods"}` envelope `project_graphson` returns for
    the whole graph, but from the per-function stream. Two passes over `segments.jsonl`:

      PASS 1 projects structural nodes/edges (Task 6) AND accumulates the cross-method tables the
        stitch needs — `callee_edges` (call id -> callee METHOD id, straight off each callsite's single
        taint callee), `callgraph`, `method_fullname` — plus the entry-point facts (`method_vertices`,
        `called`, `has_param`, `callback_fulls`). Entry ids are then reconstructed via the SAME tested
        `_entry_method_ids_from` the whole graph uses (delta C.3), and `entry_taint` restores the
        GENERIC entry-point-param taint sources.
      PASS 2 builds one `Summary` per segment WITH that segment's closure seam (`cross_rd`/
        `closure_targets`) and the reconstructed `entry_taint`, sets `callee_edges` on each so
        `_callee_map` resolves cross-function hops, then `stitch` produces FLOWS_TO.

    Never `build_summary(mid, ..., None)`: that drops the closure seam and yields 190, not 217."""
    work = Path(work); work.mkdir(parents=True, exist_ok=True)
    out = work / "segments.jsonl"
    if not (resume and out.exists()):
        run_producer(cpg_bin, str(out))
    src_names = profile.request_source_names if profile else T._REQUEST_PARAM_NAMES

    # ---- PASS 1: project structural (Task 6) + accumulate cross-method tables + entry facts ----
    nodes, edges = [], []                       # the normalized batch, held ONCE (Option 2 / §8)
    callee_edges: dict = {}                      # call_id -> callee METHOD id (== _attach_callees cmap)
    callgraph = defaultdict(set)                 # caller mid -> {callee mid}
    method_fullname: dict = {}                   # method_id -> FULL_NAME
    method_vertices: dict = {}                   # method_id -> its METHOD vertex (for the entry test)
    called: set = set(); has_param: set = set(); callback_fulls: set = set()
    for f in _read_preamble(str(out))["files"]:
        nodes.append({"label": "FILE", "id": f["id"], "props": {"NAME": f["properties"].get("NAME")}})
    start = 1                                    # Task 9 replaces this with _read_cursor(work) on resume
    for i, seg in _iter_segments(str(out), start):
        snodes, sedges = _structural(seg, profile)
        nodes.extend(snodes); edges.extend(sedges)
        mid = seg["method_id"]
        method_fullname[mid] = _method_fullname(seg)
        method_vertices[mid] = next(v for v in seg["vertices"] if v["id"] == mid)
        # Cross-function callee map + call graph + the `called` set (entry detection), ALL from
        # `call_edges` -- EVERY CALL -> METHOD out-edge, last-write-wins. This is byte-identical to
        # the oracle's callee relation (collapse_flows' `callee[o] = i` and taint_summary._attach_callees'
        # cmap, both last-wins over ALL CALL edges). It is NOT the taint `callsites` subset, which
        # keeps only real calls with their FIRST callee: that drops the <operator>.* callee edges AND
        # mis-resolves a multi-callee real call to its first callee, so `stitch_target` hops to the
        # wrong param and OVER-produces `inferred` FLOWS_TO on a GENERIC repo (PyGoat: 1078 vs 1075).
        # `call_edges` last-wins reproduces the oracle cmap exactly (0 differing keys on both repos).
        for _call_id, callee_id in seg["call_edges"]:
            if callee_id is not None:
                callee_edges[_call_id] = callee_id     # last-wins == collapse_flows' callee[o] = i
                callgraph[mid].add(callee_id)
                called.add(callee_id)
        for v in seg["vertices"]:
            if v["label"] == "METHOD_REF":
                mfn = v["properties"].get("METHOD_FULL_NAME")
                if isinstance(mfn, str) and mfn:
                    callback_fulls.add(mfn)
        if any(e["label"] == "AST" and e["outVLabel"] == "METHOD"
               and e["inVLabel"] == "METHOD_PARAMETER_IN" for e in seg["edges"]):
            has_param.add(mid)
        # Task 9 hooks: persist pass-1 tables/summaries + cursor per batch, honor simulate_crash_after.

    # entry-point reconstruction (C.3), reusing the refactored tested logic
    entry_ids = J._entry_method_ids_from(method_vertices, called, has_param, callback_fulls)
    entry_methods = sorted({method_fullname[e] for e in entry_ids
                            if method_fullname.get(e) is not None})
    entry_taint = (frozenset(entry_ids)
                   if (profile is not None and profile.entrypoint_params_are_sources) else None)

    # ---- PASS 2: build_summary per segment WITH the closure seam + entry_taint ----
    summaries: dict = {}
    for i, seg in _iter_segments(str(out), 1):
        mid = seg["method_id"]
        summaries[mid] = T.build_summary(mid, _seg_to_graphson(seg), src_names, entry_taint,
                                         cross_rd=_seg_cross_rd(seg),
                                         closure_targets=seg["closure_targets"])
        summaries[mid].callee_edges = callee_edges     # _callee_map reads this off any summary
    flows = T.stitch(summaries, dict(callgraph),
                     request_source_names=src_names, entrypoint_method_ids=entry_taint)
    edges.extend(flows)
    return {"nodes": nodes, "edges": edges, "entry_methods": entry_methods}
