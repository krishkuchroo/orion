# Streaming Per-Function Graph Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Orion's whole-graph `joern-export` (an 85x pretty-JSON blob that OOMs on large repos) with a streaming per-function pipeline that never builds or parses that blob, producing an identical graph including taint edges. The delivered memory model is honest (see spec §8): peak is `O(window + compact accumulators + normalized batch)`, roughly one graph size and about 85x below the blob, NOT constant in repo size. The producer is genuinely bounded; the consumer runs a bounded window but keeps O(repo) accumulators plus one normalized batch (Option 2, batch-at-end persist).

**Architecture:** Factor the global `collapse_flows` taint pass into bounded **per-function summaries** plus a **global stitch** (Phase 1, validated against the whole-graph oracle behind the existing path). Then add a Joern per-function producer that streams numbered segments to a durable JSONL "queue," and a bounded-window two-pass Python consumer that projects structural nodes/edges, accumulates the normalized batch plus the cross-method tables and summaries, runs the stitch, and persists the batch ONCE at the end (Phase 2, Option 2). Gate on NodeGoat + PyGoat parity before flipping the default (Phase 3).

**Tech Stack:** Python 3.11 (`./.venv/bin/python`), pytest, Joern CLI (`~/joern/joern-cli`, Scala `.sc` scripts), Neo4j (docker-compose, bolt 7688).

## Global Constraints

- Parity gate (pass/fail, copied from spec §2): streaming build reproduces NodeGoat's graph exactly, **217 FLOWS_TO edges**, identical persisted node/edge set, **14/15** recall unchanged. Second gate: **PyGoat parity**. Nothing replaces the legacy path until both pass.
- The whole-graph `collapse_flows` (`orion/graph/joern_adapter.py:96`) is the **exact oracle** and must remain unmodified as the reference throughout Phase 1.
- Reuse existing helpers, do NOT duplicate: `_unwrap`, `_prop`, `_deepint`, `_is_real_call`, `_clean`, `_REQUEST_PARAM_NAMES`, `_SOURCE_ANNOTATIONS`, `_MAPPED_NODE_LABELS`, `_MAPPED_EDGES` (all in `joern_adapter.py`).
- Taint config is profile-driven: `request_source_names` and (GENERIC profile only) `entrypoint_method_ids`, thread both exactly as `project_graphson` does (`joern_adapter.py:326-330`).
- Run tests with `./.venv/bin/python -m pytest`. Token-free suite must stay green (currently 69 passing). Live/Joern-dependent tests are marked `@pytest.mark.slow`.
- Interpreter: always `./.venv/bin/python` (venv activation does not persist across shells).
- `fixtures/` is gitignored; NodeGoat prebuilt CPG is `fixtures/NodeGoat/cpg.bin`.

---

## File Structure

- Create `orion/graph/taint_summary.py`, the summary-stitch analysis: `partition`, `build_summary`, `stitch`, and `flows_via_summaries` (the whole-graph entry that must equal `collapse_flows`). Phase 1.
- Create `orion/graph/joern_scripts/emit_segments.sc`, Joern Scala producer: iterate `cpg.method`, emit one JSON segment per function. Phase 2.
- Create `orion/graph/stream_build.py`, streaming consumer: run the producer, read `segments.jsonl` with a bounded window + resume cursor, project + persist structurally per segment, accumulate summaries, run the stitch, persist FLOWS_TO. Phase 2.
- Modify `orion/graph_build.py`, add the `stream=` build path alongside the legacy path.
- Modify `orion/cli.py`, add `--stream/--no-stream` and `--queue-size` flags.
- Create tests: `tests/test_taint_summary.py`, `tests/test_stream_build.py`.
- Create `tests/conftest.py` helper (if absent) exposing a cached NodeGoat graphson fixture.

---

## Phase 1, Summary-stitch taint, validated by the oracle (no streaming yet)

### Task 1: NodeGoat graphson fixture + `partition`

**Files:**
- Create: `orion/graph/taint_summary.py`
- Create: `tests/test_taint_summary.py`
- Test: `tests/test_taint_summary.py::test_partition_covers_graph`

**Interfaces:**
- Consumes: raw Joern GraphSON dict `g` (the `{"vertices":[...], "edges":[...]}` form, possibly wrapped in `{"@type","@value"}`), and `joern_adapter._unwrap`.
- Produces:
  - `owner_map(g) -> dict[int,int|None]`, vertex id → enclosing METHOD id via AST ancestry.
  - `partition(g) -> tuple[dict[int,dict], dict[int,set[int]]]`, `(methods, callgraph)` where `methods[mid] = {"vertices":[...], "edges":[...]}` holds only vertices owned by `mid` and edges wholly inside `mid`; `callgraph[caller_mid] = {callee_mid,...}` from CALL edges (call node → callee METHOD).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_taint_summary.py
import json, subprocess, tempfile, shutil
from pathlib import Path
import pytest
from orion.graph import taint_summary as T
from orion.graph import joern_adapter as J

JOERN_EXPORT = Path.home() / "joern/joern-cli/joern-export"

def _export(cpg_bin: str) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="orion_ts_"))
    try:
        subprocess.run([str(JOERN_EXPORT), "--repr=all", "--format=graphson",
                        "--out", str(tmp / "e"), cpg_bin], check=True,
                       capture_output=True, text=True)
        return json.loads((tmp / "e" / "export.json").read_text())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

@pytest.fixture(scope="session")
def nodegoat_graphson():
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    return _export(cpg)

@pytest.mark.slow
def test_partition_covers_graph(nodegoat_graphson):
    g = nodegoat_graphson
    inner = g["@value"] if "@type" in g else g
    methods, callgraph = T.partition(g)
    # Every METHOD id appears as a partition key.
    method_ids = {J._unwrap(v["id"]) for v in inner["vertices"] if v["label"] == "METHOD"}
    assert set(methods) == method_ids
    # NodeGoat has 281 functions (measured).
    assert len(methods) == 281
    # Cross-method edges (dropped from every slice) match the measured 12531.
    inside = sum(len(m["edges"]) for m in methods.values())
    assert len(inner["edges"]) - inside == 12531
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_partition_covers_graph -v`
Expected: FAIL with `AttributeError: module 'orion.graph.taint_summary' has no attribute 'partition'`

- [ ] **Step 3: Write minimal implementation**

```python
# orion/graph/taint_summary.py
"""Summary-stitch interprocedural taint: factor collapse_flows into bounded per-function
summaries + a global stitch that reproduces it exactly. See
docs/superpowers/specs/2026-07-23-streaming-graph-build-design.md."""
from __future__ import annotations
from collections import defaultdict
from .joern_adapter import (_unwrap, _prop, _deepint, _is_real_call,
                            _REQUEST_PARAM_NAMES, _SOURCE_ANNOTATIONS)


def _inner(g: dict) -> dict:
    return g["@value"] if "@type" in g else g


def owner_map(g: dict) -> dict:
    """Vertex id -> enclosing METHOD id by climbing AST parent edges (same climb as B3's
    _call_file_map). A METHOD owns itself; a vertex under no METHOD maps to None."""
    inner = _inner(g)
    verts = {_unwrap(v["id"]): v for v in inner.get("vertices", [])}
    ast_parent: dict = {}
    for e in inner.get("edges", []):
        if e["label"] == "AST":
            ast_parent[_unwrap(e["inV"])] = _unwrap(e["outV"])
    out: dict = {}
    for vid, v in verts.items():
        cur, guard = vid, 0
        while cur is not None and guard < 512:
            guard += 1
            node = verts.get(cur)
            if node is None:
                cur = None
                break
            if node["label"] == "METHOD":
                break
            cur = ast_parent.get(cur)
        out[vid] = cur
    return out


def partition(g: dict) -> tuple[dict, dict]:
    inner = _inner(g)
    verts = {_unwrap(v["id"]): v for v in inner.get("vertices", [])}
    own = owner_map(g)
    methods: dict = {vid: {"vertices": [], "edges": []}
                     for vid, v in verts.items() if v["label"] == "METHOD"}
    for vid, m in own.items():
        if m in methods:
            methods[m]["vertices"].append(verts[vid])
    callgraph: dict = defaultdict(set)
    for e in inner.get("edges", []):
        o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
        mo, mi = own.get(o), own.get(i)
        if mo is not None and mo == mi and mo in methods:
            methods[mo]["edges"].append(e)
        if e["label"] == "CALL" and verts.get(i, {}).get("label") == "METHOD" and mo in methods:
            callgraph[mo].add(i)
    return methods, dict(callgraph)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_partition_covers_graph -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orion/graph/taint_summary.py tests/test_taint_summary.py
git commit -m "feat(taint): partition graphson into per-function subgraphs + call graph"
```

---

### Task 2: `build_summary`, the per-function transfer function

**Files:**
- Modify: `orion/graph/taint_summary.py`
- Test: `tests/test_taint_summary.py::test_summary_direct_reach`

**Interfaces:**
- Consumes: `partition` output; `_is_real_call`, `_prop`, `_deepint`, `_unwrap`.
- Produces: `build_summary(method_id, sub, request_source_names, entrypoint_method_ids) -> Summary` where `Summary` is a dataclass with:
  - `method_id: int`
  - `direct: dict[int, set[tuple[int,int]]]`, entry vertex id → set of `(real_call_id, arg_index)` reached by the intra-function rd walk seeded from the entry's reaching-defs (stopping at real-call args; NOT crossing calls).
  - `params: dict[int,int]`, param index → METHOD_PARAMETER_IN id.
  - `real_calls: set[int]`, real CALL ids in this function (each is also a `direct` entry).
  - `internal_sources: set[int]`, entry ids that are attacker-controlled sources here (request-object fieldAccess whose base ∈ `request_source_names`, annotated source params, and, when `entrypoint_method_ids` includes this method, its params).
  - `callsite: dict[int, dict[int,int]]`, real_call id → {arg_index → callee arg-slot marker}; the callee METHOD is resolved globally in `stitch` via the call graph, so this stores only the arg indices present.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_taint_summary.py
@pytest.mark.slow
def test_summary_direct_reach(nodegoat_graphson):
    methods, _ = T.partition(nodegoat_graphson)
    # Every function's summary builds without error and every direct target is a real call
    # that lives in that same function (intra-function invariant).
    for mid, sub in methods.items():
        s = T.build_summary(mid, sub, frozenset({"req", "request"}), None)
        for entry, targets in s.direct.items():
            for (rc, idx) in targets:
                assert rc in s.real_calls
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_summary_direct_reach -v`
Expected: FAIL with `AttributeError: ... has no attribute 'build_summary'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to orion/graph/taint_summary.py
from dataclasses import dataclass, field

@dataclass
class Summary:
    method_id: int
    direct: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    real_calls: set = field(default_factory=set)
    internal_sources: set = field(default_factory=set)
    callsite: dict = field(default_factory=dict)


def _intra(sub: dict):
    """Build the intra-function relations collapse_flows uses, scoped to one method's subgraph."""
    verts = {_unwrap(v["id"]): v for v in sub["vertices"]}
    rd = defaultdict(list)          # REACHING_DEF: node -> nodes its def reaches
    arg_parent: dict = {}           # arg node -> its parent call
    arg_index: dict = {}            # arg node -> its ARGUMENT_INDEX
    arg_children = defaultdict(dict)
    mparams: dict = {}              # param index -> param id (this method)
    param_ann = defaultdict(set)    # param id -> annotation names
    for e in sub["edges"]:
        lbl = e["label"]; o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
        if lbl == "REACHING_DEF":
            rd[o].append(i)
        elif lbl == "ARGUMENT":
            arg_parent[i] = o
            if i in verts:
                idx = _deepint(_prop(verts[i], "ARGUMENT_INDEX"))
                arg_index[i] = idx
                arg_children[o][idx] = i
        elif lbl == "AST":
            ol = verts.get(o, {}).get("label"); il = verts.get(i, {}).get("label")
            if ol == "METHOD" and il == "METHOD_PARAMETER_IN":
                mparams[_deepint(_prop(verts[i], "INDEX"))] = i
            elif ol == "METHOD_PARAMETER_IN" and il == "ANNOTATION":
                for key in (_prop(verts[i], "FULL_NAME"), _prop(verts[i], "NAME")):
                    if isinstance(key, str) and key:
                        param_ann[o].add(key)
    return verts, rd, arg_parent, arg_index, arg_children, mparams, param_ann


def _enclosing_real_arg(n, verts, arg_parent, arg_index):
    cur = n
    while cur in arg_parent:
        pa = arg_parent[cur]
        pv = verts.get(pa)
        if pv is not None and _is_real_call(pv["label"], _prop(pv, "METHOD_FULL_NAME")):
            return pa, arg_index.get(cur)
        cur = pa
    return None, None


def _reach(entry, rd, verts, arg_parent, arg_index):
    """Intra-function: (real_call, idx) sites reached from `entry`, stopping at each real-call arg
    (mirrors the collapse_flows inner walk WITHOUT the stitch)."""
    out = set()
    seen = {entry}
    stack = list(rd.get(entry, []))
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        rc, idx = _enclosing_real_arg(n, verts, arg_parent, arg_index)
        if rc is not None:
            out.add((rc, idx))
            continue
        stack.extend(rd.get(n, []))
    return out


def _base_root_name(fa, verts, arg_children):
    cur, guard = fa, 0
    while guard < 32:
        guard += 1
        v = verts.get(cur)
        if v is None:
            return None
        if v["label"] == "IDENTIFIER":
            return _prop(v, "NAME")
        if v["label"] == "CALL" and _prop(v, "METHOD_FULL_NAME") == "<operator>.fieldAccess":
            cur = arg_children.get(cur, {}).get(1)
            if cur is None:
                return None
            continue
        return None
    return None


def build_summary(method_id, sub, request_source_names, entrypoint_method_ids) -> Summary:
    verts, rd, arg_parent, arg_index, arg_children, mparams, param_ann = _intra(sub)
    real_calls = {vid for vid, v in verts.items()
                  if _is_real_call(v["label"], _prop(v, "METHOD_FULL_NAME"))}
    s = Summary(method_id=method_id, params=dict(mparams), real_calls=set(real_calls))
    # Entries: every real call (a potential source `s`), every param (stitch target), sources.
    entries = set(real_calls) | set(mparams.values())
    # internal sources
    for p, names in param_ann.items():
        if names & _SOURCE_ANNOTATIONS:
            s.internal_sources.add(p)
    if entrypoint_method_ids and method_id in entrypoint_method_ids:
        s.internal_sources.update(mparams.values())
    for vid, v in verts.items():
        if (v["label"] == "CALL" and _prop(v, "METHOD_FULL_NAME") == "<operator>.fieldAccess"
                and _base_root_name(vid, verts, arg_children) in request_source_names):
            s.internal_sources.add(vid)
    entries |= s.internal_sources
    for e in entries:
        s.direct[e] = _reach(e, rd, verts, arg_parent, arg_index)
    # callsite arg indices per real call (callee METHOD resolved globally in stitch)
    for rc in real_calls:
        s.callsite[rc] = dict(arg_children.get(rc, {}))
    return s
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_summary_direct_reach -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orion/graph/taint_summary.py tests/test_taint_summary.py
git commit -m "feat(taint): per-function summary (direct-reach transfer function)"
```

---

### Task 3: `stitch` + `flows_via_summaries`, THE oracle parity gate

**Files:**
- Modify: `orion/graph/taint_summary.py`
- Test: `tests/test_taint_summary.py::test_oracle_parity_nodegoat`

**Interfaces:**
- Consumes: `{method_id: Summary}`, `callgraph` (caller_mid → {callee_mid}), and a map `param_slot: dict[(callee_mid, idx) -> param_id]` derivable from each summary's `params`.
- Produces: `stitch(summaries, callgraph, ...) -> list[dict]` and `flows_via_summaries(g, request_source_names=_REQUEST_PARAM_NAMES, entrypoint_method_ids=None) -> list[dict]`, each dict shaped exactly like `collapse_flows` output: `{"label":"FLOWS_TO","out":int,"in":int,"arg_index":int,"provenance":"proven"|"inferred"}`.

- [ ] **Step 1: Write the failing test (the parity gate)**

```python
# add to tests/test_taint_summary.py
from orion.graph import profiles

def _flowset(flows):
    return {(f["out"], f["in"], f["arg_index"], f["provenance"]) for f in flows}

@pytest.mark.slow
def test_oracle_parity_nodegoat(nodegoat_graphson):
    g = nodegoat_graphson
    prof = profiles.select_profile("fixtures/NodeGoat")
    entry_ids = J._entry_method_ids(g["@value"] if "@type" in g else g)
    entry_taint = frozenset(entry_ids) if prof.entrypoint_params_are_sources else None
    oracle = J.collapse_flows(g["@value"] if "@type" in g else g,
                              request_source_names=prof.request_source_names,
                              entrypoint_method_ids=entry_taint)
    got = T.flows_via_summaries(g, request_source_names=prof.request_source_names,
                                entrypoint_method_ids=entry_taint)
    assert len(oracle) == 217, "baseline changed; re-derive expectation"
    assert _flowset(got) == _flowset(oracle)   # EXACT: edges + provenance
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_oracle_parity_nodegoat -v`
Expected: FAIL with `AttributeError: ... has no attribute 'flows_via_summaries'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to orion/graph/taint_summary.py
def stitch(summaries: dict, callgraph: dict, *,
           request_source_names=_REQUEST_PARAM_NAMES, entrypoint_method_ids=None) -> list:
    method_of = {}                     # entry/call/param id -> owning method id
    param_slot = {}                    # (method_id, idx) -> param id
    for mid, s in summaries.items():
        for e in s.direct:
            method_of[e] = mid
        for idx, pid in s.params.items():
            param_slot[(mid, idx)] = pid
            method_of[pid] = mid
    # callee METHOD for (call_id) via callgraph: a real call in method A resolves to some callee in
    # callgraph[A]; collapse_flows used the CALL edge call->METHOD. Rebuild that exact mapping.
    # (Provided by partition: see Task 3 Step 3a below.)
    callee = _callee_map(summaries, callgraph)

    def stitch_target(rc, idx):
        m = callee.get(rc)
        return param_slot.get((m, idx)) if m is not None else None

    best: dict = {}
    # best family: seed from every real call `s`.
    for mid, s in summaries.items():
        for src in s.real_calls:
            frontier = [(src, mid, False)]
            seen = {(src, False)}
            while frontier:
                entry, emid, crossed = frontier.pop()
                for (rc, idx) in summaries[emid].direct.get(entry, ()):
                    if rc != src:
                        key = (src, rc, idx)
                        best[key] = best.get(key, True) and crossed
                    tgt = stitch_target(rc, idx)
                    if tgt is not None and (tgt, True) not in seen:
                        seen.add((tgt, True))
                        frontier.append((tgt, method_of[tgt], True))
    param_flows: set = set()
    for mid, s in summaries.items():
        for src in s.internal_sources:
            frontier = [(src, mid, False)]
            seen = {(src, False)}
            while frontier:
                entry, emid, crossed = frontier.pop()
                for (rc, idx) in summaries[emid].direct.get(entry, ()):
                    param_flows.add((rc, idx))
                    tgt = stitch_target(rc, idx)
                    if tgt is not None and (tgt, True) not in seen:
                        seen.add((tgt, True))
                        frontier.append((tgt, method_of[tgt], True))
    flows = [{"label": "FLOWS_TO", "out": a, "in": b, "arg_index": i,
              "provenance": "inferred" if crossed else "proven"}
             for (a, b, i), crossed in best.items()]
    flows += [{"label": "FLOWS_TO", "out": rc, "in": rc, "arg_index": idx,
               "provenance": "inferred"} for (rc, idx) in param_flows]
    return flows


def flows_via_summaries(g, *, request_source_names=_REQUEST_PARAM_NAMES,
                        entrypoint_method_ids=None) -> list:
    methods, callgraph = partition(g)
    summaries = {mid: build_summary(mid, sub, request_source_names, entrypoint_method_ids)
                 for mid, sub in methods.items()}
    # attach the raw callee edges partition saw, for _callee_map
    summaries = _attach_callees(summaries, g)
    return stitch(summaries, callgraph, request_source_names=request_source_names,
                  entrypoint_method_ids=entrypoint_method_ids)
```

Step 3a, `_callee_map` and `_attach_callees` must reproduce collapse_flows' `callee[o]=i` (CALL edge from real call `o` to callee METHOD `i`). Add to `partition` a third return, or compute here from `g`:

```python
# add to orion/graph/taint_summary.py
def _attach_callees(summaries, g):
    inner = _inner(g)
    verts = {_unwrap(v["id"]): v for v in inner.get("vertices", [])}
    cmap = {}
    for e in inner.get("edges", []):
        if e["label"] == "CALL":
            o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
            if verts.get(o, {}).get("label") == "CALL" and verts.get(i, {}).get("label") == "METHOD":
                cmap[o] = i
    for s in summaries.values():
        s.callee_edges = cmap  # shared read-only view
    return summaries

def _callee_map(summaries, callgraph):
    for s in summaries.values():
        return getattr(s, "callee_edges", {})
    return {}
```

> **Acceptance is the oracle test.** This code mirrors `collapse_flows` step-for-step; if `test_oracle_parity_nodegoat` shows any diff, fix the discrepancy (most likely: the `seen`/dedup key granularity, or a `direct` entry that should/shouldn't stop at a real call) until the flow sets are identical. Do NOT modify `collapse_flows`.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_oracle_parity_nodegoat -v`
Expected: PASS, `_flowset(got) == _flowset(oracle)`, both size 217.

- [ ] **Step 5: Commit**

```bash
git add orion/graph/taint_summary.py tests/test_taint_summary.py
git commit -m "feat(taint): global stitch reproduces collapse_flows exactly on NodeGoat (217)"
```

---

### Task 4: PyGoat oracle parity

**Files:**
- Modify: `tests/test_taint_summary.py`
- Test: `tests/test_taint_summary.py::test_oracle_parity_pygoat`

**Interfaces:**
- Consumes: `flows_via_summaries`, `collapse_flows`, `profiles.select_profile`. PyGoat uses the GENERIC profile (entry-point params are sources), so this exercises the `entrypoint_method_ids` path Task 3 must also satisfy.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_taint_summary.py
@pytest.mark.slow
def test_oracle_parity_pygoat():
    cpg = "fixtures/PyGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("PyGoat cpg.bin not present")
    g = _export(cpg)
    inner = g["@value"] if "@type" in g else g
    prof = profiles.select_profile("fixtures/PyGoat")
    entry_ids = J._entry_method_ids(inner)
    entry_taint = frozenset(entry_ids) if prof.entrypoint_params_are_sources else None
    oracle = J.collapse_flows(inner, request_source_names=prof.request_source_names,
                              entrypoint_method_ids=entry_taint)
    got = T.flows_via_summaries(g, request_source_names=prof.request_source_names,
                                entrypoint_method_ids=entry_taint)
    assert _flowset(got) == _flowset(oracle)
```

- [ ] **Step 2: Run test to verify it fails or skips**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_oracle_parity_pygoat -v`
Expected: PASS if PyGoat CPG present; else SKIP. If it FAILS, the GENERIC entry-point-source path in `build_summary` needs fixing (`internal_sources` must include entry-point params exactly as `collapse_flows` does).

- [ ] **Step 3: Fix any GENERIC-profile discrepancy**

If failing, verify `entrypoint_method_ids and method_id in entrypoint_method_ids` gate in `build_summary` adds `mparams.values()` to `internal_sources`, matching `collapse_flows:204-206`.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_taint_summary.py::test_oracle_parity_pygoat -v`
Expected: PASS or SKIP.

- [ ] **Step 5: Commit**

```bash
git add tests/test_taint_summary.py orion/graph/taint_summary.py
git commit -m "test(taint): PyGoat (GENERIC profile) oracle parity"
```

---

## Phase 2, Streaming pipeline

### Task 5: Joern producer script (flatgraph) + segment/partition equivalence + closure parity

**Files:**
- Create: `orion/graph/joern_scripts/emit_segments.sc`
- Create: `orion/graph/stream_build.py` (with `run_producer` only for now)
- Test: `tests/test_stream_build.py::test_producer_matches_python_partition`
- Test: `tests/test_stream_build.py::test_producer_closure_parity_pygoat`

**Interfaces:**
- Produces:
  - `emit_segments.sc`: a Joern **flatgraph** script (Joern 4.0.569 / flatgraph-core 0.1.32 / codepropertygraph 1.7.70) that, given `cpg.bin` loaded, writes `segments.jsonl` in the frozen spec §5 schema: one preamble line (`seg=-1`, the `cpg.file` FILE nodes) then one line per `cpg.method` (including external stubs, so RESOLVES_TO parity covers external callees). Each per-function line carries `method_id`, `vertices` (INCLUDING the METHOD vertex, full property dump), `edges` (wholly-inside AST/REACHING_DEF/ARGUMENT/CONTAINS, WITH `outVLabel`/`inVLabel`), `source_file.file_id`, `callsites` (TAINT shape: real calls only, single `callee_id` direct from the CALL out-neighbor), `call_edges` (RESOLVES_TO source: EVERY CALL->METHOD out-edge, unfiltered, one `[call_id, callee_id]` pair per edge, from the same CALL out-neighbor accessor), `cross_rd`, `closure_targets`. Consumer normalizes producer JSON into the same `{label,id,properties}` shape `_unwrap`/`_prop` expect (plain scalars, no GraphSON type-tagging needed).
  - `stream_build.run_producer(cpg_bin: str, out_jsonl: str) -> int`: runs `joern --script emit_segments.sc`, returns the per-function segment count (total lines minus the one preamble). Uses `joern_adapter._jvm_flags()` and `_ensure_greadlink`.

**flatgraph accessor warning (why Step 1 is a required live probe).** The old sketch used `propertiesMap.toString`, `outE.l`, and `e.inNode`/`e.outNode`. In flatgraph (this Joern) NONE of those exist. Neighbor traversal uses typed generated accessors (`_astOut`, `_reachingDefOut`, `_argumentOut`, `_containsOut`, `_fileViaSourceFileOut`, ...) and typed property accessors. The exact spellings are pinned by a live probe, not guessed. The design contract is the §5 schema plus the probe directive; do NOT invent final accessor names.

- [ ] **Step 1: Probe the flatgraph API on the real CPG (REQUIRED, do this first)**

Run a throwaway `joern --script` (or `joern` REPL) probe against `fixtures/NodeGoat/cpg.bin` to nail, and record in a comment block at the top of `emit_segments.sc`:
  - the typed neighbor accessors that enumerate a method's AST subtree and its wholly-inside AST / REACHING_DEF / ARGUMENT / CONTAINS edges (candidates: `_astOut`, `_reachingDefOut`, `_argumentOut`, `_containsOut`);
  - the CALL-to-callee accessor that yields the resolved callee METHOD node id for `callsites[].callee_id`;
  - the SOURCE_FILE accessor that yields a method's FILE (candidate `_fileViaSourceFileOut`);
  - the typed property accessors (e.g. `.name`, `.fullName`, `.argumentIndex`, `.isExternal`) and how to dump a node's FULL property set;
  - that `node.id` returns the SAME integer id space as the GraphSON `g:Int64` ids the Python partition keys on (so producer ids and `_export` ids compare directly in the equivalence test);
  - the exact `cpg.bin` load invocation for `--script` (confirm the `run_producer` argument form).

Run (example probe):
```bash
~/joern/joern-cli/joern --script /dev/stdin <<'EOF'
importCpg("fixtures/NodeGoat/cpg.bin")
val m = cpg.method.nameExact("<some real method>").head
// print m.id, one node's full property set, and confirm the typed *Out accessor spellings
EOF
```
Do NOT proceed to Step 4 with guessed accessor names.

- [ ] **Step 2: Write the failing tests (partition equivalence + closure parity)**

```python
# tests/test_stream_build.py
import json
from collections import Counter, defaultdict
from pathlib import Path
import pytest
from orion.graph import stream_build as S
from orion.graph import taint_summary as T
from tests.test_taint_summary import _export  # reuse exporter

def _read_segments(path: Path):
    recs = [json.loads(l) for l in path.read_text().splitlines()]
    preamble = [r for r in recs if r["seg"] == -1]
    perfunc = [r for r in recs if r["seg"] >= 0]
    return preamble, perfunc

def _consulted_cross_rd(g):
    """The part of _closure_edges' cross_rd the stitch actually consults: source keys owned by some
    method. Method-less-source keys are inert (never walked) and are NOT carried by the producer."""
    own = T.owner_map(g)
    raw, _ = T._closure_edges(g)
    return {src: set(dsts) for src, dsts in raw.items() if own.get(src) is not None}

def _prod_closure(perfunc):
    prod_cross, prod_targets = defaultdict(set), defaultdict(set)
    for seg in perfunc:
        for (o, i) in seg["cross_rd"]:
            prod_cross[o].add(i)
        for t in seg["closure_targets"]:
            prod_targets[seg["method_id"]].add(t)
    return {k: set(v) for k, v in prod_cross.items()}, dict(prod_targets)

@pytest.mark.slow
def test_producer_matches_python_partition(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    out = tmp_path / "segments.jsonl"
    n = S.run_producer(cpg, str(out))
    preamble, perfunc = _read_segments(out)
    assert len(preamble) == 1
    assert n == len(perfunc) == 281
    # Per-method vertex-id sets. The Python partition INCLUDES the METHOD vertex; so does the producer.
    g = _export(cpg)
    methods, _ = T.partition(g)
    py = {mid: {T._unwrap(v["id"]) for v in sub["vertices"]} for mid, sub in methods.items()}
    prod = {seg["method_id"]: {v["id"] for v in seg["vertices"]} for seg in perfunc}
    assert prod == py
    # Closure-edge parity gate (delta D.3.C): union over segments == the consulted closure seam.
    _, targets_by_method = T._closure_edges(g)
    prod_cross, prod_targets = _prod_closure(perfunc)
    assert prod_cross == _consulted_cross_rd(g)
    assert prod_targets == {m: set(v) for m, v in targets_by_method.items()}

@pytest.mark.slow
def test_producer_closure_parity_pygoat(tmp_path):
    cpg = "fixtures/PyGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("PyGoat cpg.bin not present")
    out = tmp_path / "segments.jsonl"
    S.run_producer(cpg, str(out))
    _, perfunc = _read_segments(out)
    g = _export(cpg)
    _, targets_by_method = T._closure_edges(g)
    prod_cross, prod_targets = _prod_closure(perfunc)
    assert prod_cross == _consulted_cross_rd(g)
    assert prod_targets == {m: set(v) for m, v in targets_by_method.items()}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py -k producer -v`
Expected: FAIL, `emit_segments.sc` / `run_producer` missing.

- [ ] **Step 4: Write the flatgraph producer script (§5 / A.2 schema) and the runner**

```scala
// orion/graph/joern_scripts/emit_segments.sc
// flatgraph producer (Joern 4.0.569 / flatgraph-core 0.1.32 / codepropertygraph 1.7.70).
// Accessor spellings confirmed by the Step-1 probe -- record them here:
//   AST subtree:        <m.ast / m._astOut>        full property dump: <node.propertiesMap / typed>
//   wholly-inside edges: AST/REACHING_DEF/ARGUMENT/CONTAINS  (typed *Out accessors)
//   CALL -> callee id:   <call.callee id / _callOut>
//   SOURCE_FILE -> FILE: <m._fileViaSourceFileOut>
// Emits the frozen spec §5 schema: one preamble line (seg=-1, FILE nodes) then one line per
// cpg.method (INCLUDING external stubs, so RESOLVES_TO parity covers external callees).
import java.io.PrintWriter

@main def main(outPath: String) = {
  val pw = new PrintWriter(outPath)
  try {
    // ---- global ownership + closure precompute (producer holds the whole cpg once) ----
    // owner: nodeId -> owning METHOD id (nearest enclosing METHOD via AST ancestry, == owner_map).
    // idsByMethod: methodId -> Set[ownedNodeId];  owned = union of all idsByMethod.
    // Iterate every REACHING_DEF edge o->i with owner(o) != owner(i) ONCE and bucket (A.3):
    //   SOURCE side  (into owner(o)'s segment): cross_rd(o) += i   iff owner(o) defined AND i in owned
    //                                            (the `i in owned` filter DROPS method-less targets)
    //   TARGET side  (into owner(i)'s segment): closure_targets(owner(i)) += i   iff owner(i) defined
    //                                            (NO filter on owner(o): KEEP method-less sources)

    // ---- preamble: FILE nodes from cpg.file (full property dump incl. NAME) ----
    pw.println(s"""{"seg":-1,"files":[<file json ...>]}""")

    var seg = 0
    cpg.method.l.foreach { m =>                 // cpg.method includes external stubs
      val nodes = m.ast.l                        // owned AST subtree, INCLUDING m itself (== partition)
      val ids   = nodes.map(_.id).toSet
      // vertices: FULL property dump per node (MUST include IDENTIFIER.NAME + ANNOTATION.FULL_NAME/NAME
      // + ARGUMENT_INDEX + INDEX; missing IDENTIFIER.NAME silently drops NodeGoat below 217)
      val vjson = nodes.map(n => s"""{"id":${n.id},"label":"${n.label}","properties":${propJson(n)}}""").mkString(",")
      // edges: every edge with BOTH endpoints in ids (AST/REACHING_DEF/ARGUMENT/CONTAINS), WITH labels
      val ejson = intraEdges(nodes, ids).map(e =>
        s"""{"label":"${e.label}","outV":${e.outId},"inV":${e.inId},"outVLabel":"${e.outLabel}","inVLabel":"${e.inLabel}"}""").mkString(",")
      val fileId = sourceFileId(m)               // this method's SOURCE_FILE FILE id (Long or null)
      // callsites: one per REAL call; callee_id DIRECT from the CALL out-neighbor (may be external).
      // This is the TAINT call graph and stays real-call / single-callee (byte-identical). RESOLVES_TO
      // is NOT reconstructed from it (a strict subset); it is reconstructed from call_edges below.
      val csjson = realCalls(m).map(c =>
        s"""{"call_id":${c.id},"callee_id":${calleeId(c)},"callee_full_name":"${c.methodFullName}","args":${argMap(c)}}""").mkString(",")
      // call_edges: EVERY CALL->METHOD out-edge owned by this method (RESOLVES_TO source), UNFILTERED
      // (operator calls + all callees of a multi-callee site), one [call_id, callee_id] pair per edge,
      // from the same CALL out-neighbor accessor as callsites. Recovers the 1638 edges (1576 operator +
      // 62 multi-callee) callsites omits, reaching exact structural RESOLVES_TO parity (2047 on NodeGoat).
      val cejson = callEdges(m.id).map { case (cid, calleeId) => s"[$cid,$calleeId]" }.mkString(",")
      val crossJson  = crossRd(m.id).map { case (o, i) => s"[$o,$i]" }.mkString(",")
      val targetJson = closureTargets(m.id).mkString(",")
      pw.println(
        s"""{"seg":$seg,"method_id":${m.id},"vertices":[$vjson],"edges":[$ejson],""" +
        s""""source_file":{"file_id":${fileId}},"callsites":[$csjson],"call_edges":[$cejson],""" +
        s""""cross_rd":[$crossJson],"closure_targets":[$targetJson]}""")
      seg += 1
    }
    seg
  } finally pw.close()
}
```

> The helper shapes (`propJson`, `intraEdges`, `sourceFileId`, `realCalls`, `calleeId`, `argMap`, `crossRd`, `closureTargets`) are filled in with the Step-1-confirmed flatgraph accessors. The equivalence + closure-parity tests are the definition of done: iterate the accessors until `prod == py` AND both closure unions match. Do NOT re-prepend the method into `vertices` in the consumer (it is already inside `vertices`); see Task 6's `_seg_to_graphson`.

```python
# orion/graph/stream_build.py
"""Streaming per-function build: producer (Joern) -> segments.jsonl -> bounded consumer."""
from __future__ import annotations
import json, os, subprocess
from pathlib import Path
from .joern_adapter import _joern_bin, _jvm_flags, _ensure_greadlink

_SCRIPT = Path(__file__).parent / "joern_scripts" / "emit_segments.sc"

def run_producer(cpg_bin: str, out_jsonl: str) -> int:
    """Run the flatgraph producer; return the per-function segment count (total lines minus the one
    seg=-1 preamble line). Step-1 confirms the exact cpg-load invocation."""
    env = _ensure_greadlink(dict(os.environ))
    joern = _joern_bin("joern")
    r = subprocess.run([str(joern), *_jvm_flags(), "--script", str(_SCRIPT),
                        "--param", f"outPath={out_jsonl}", "--import", cpg_bin],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0 or not Path(out_jsonl).exists():
        raise RuntimeError(f"segment producer failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
    return sum(1 for _ in open(out_jsonl)) - 1   # minus the one preamble line
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py -k producer -v`
Expected: PASS, per-method id sets match the Python partition, and both closure unions match the consulted seam, on NodeGoat (and PyGoat when present).

- [ ] **Step 6: Commit**

```bash
git add orion/graph/joern_scripts/emit_segments.sc orion/graph/stream_build.py tests/test_stream_build.py
git commit -m "feat(stream): flatgraph per-function producer emits §5 segments incl. closure seam"
```

---

### Task 6: Bounded-window consumer (pass 1), structural node AND edge parity

**Files:**
- Modify: `orion/graph/stream_build.py`
- Test: `tests/test_stream_build.py::test_stream_structural_parity`

**Interfaces:**
- Consumes: `run_producer`, `joern_adapter.project_graphson` (structural node/edge projection).
- Produces: the consumer's **pass 1** (delta C.1): read the preamble (project FILE nodes once), then iterate per-function records with a bounded window (`queue_size` decoded at once), projecting structural nodes/edges per segment and reconstructing the three cross-family structural edges (CONTAINS_CALL from the slice; CALL/RESOLVES_TO from `call_edges`, EVERY CALL->METHOD out-edge, NOT the taint `callsites[].callee_id` subset; SOURCE_FILE/DEFINED_IN from the FILE preamble + `source_file.file_id`). No per-method subgraph is held across passes; pass 2 (summaries) is added in Task 7. A test-only `collect_structural(cpg_bin, work, profile, *, queue_size=64) -> tuple[set, Counter]` returns the structural node set `{(label,id)}` and the structural edge multiset `Counter((label,out,in))`.

- [ ] **Step 1: Write the failing test (structural NODE + EDGE parity)**

```python
# add to tests/test_stream_build.py
@pytest.mark.slow
def test_stream_structural_parity(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    from orion.graph import joern_adapter as J, profiles
    prof = profiles.select_profile("fixtures/NodeGoat")
    g = _export(cpg)
    legacy = J.project_graphson(g, profile=prof)
    legacy_nodes = {(n["label"], n["id"]) for n in legacy["nodes"]}
    # Structural edge multiset (excludes FLOWS_TO): CONTAINS_CALL + RESOLVES_TO + DEFINED_IN, by ids.
    legacy_struct = Counter((e["label"], e["out"], e["in"])
                            for e in legacy["edges"] if e["label"] != "FLOWS_TO")
    nodes, edges = S.collect_structural(str(cpg), tmp_path, prof)
    assert nodes == legacy_nodes
    assert edges == legacy_struct
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_structural_parity -v`
Expected: FAIL, `collect_structural`/consumer missing.

- [ ] **Step 3: Write the consumer pass-1 projection (bounded window)**

```python
# add to orion/graph/stream_build.py
from collections import Counter
from itertools import islice
from .joern_adapter import project_graphson
from . import taint_summary as T

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
    The METHOD vertex is ALREADY inside seg['vertices'] (spec §5 / A.2.1), so do NOT re-prepend it."""
    return {"vertices": seg["vertices"], "edges": seg["edges"]}

def _structural(seg: dict, profile) -> tuple[list, list]:
    """Structural nodes + edges for ONE per-function segment. CONTAINS_CALL comes from the slice's own
    intra CONTAINS edges; CALL (-> RESOLVES_TO) is reconstructed from seg['call_edges'] (EVERY
    CALL->METHOD out-edge, operator calls + all multi-callee edges), matching what legacy
    project_graphson persists; NOT from the taint callsites (a strict subset, short 1638 edges on
    NodeGoat). SOURCE_FILE (-> DEFINED_IN) is synthesized from source_file.file_id. FLOWS_TO is
    excluded (Task 7 adds it)."""
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
```

> This is pass 1's projection: nodes come per-segment (plus FILE from the preamble) and every structural edge is reconstructed in-window from the segment. There is no "re-derived at persist by `normalize` via `method_full_name`" step; `normalize` synthesizes nothing from names; the consumer supplies CALL/SOURCE_FILE edges by id. Full node-property parity and the DB round-trip are Task 8 (delta D.3.A/B/D).

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_structural_parity -v`
Expected: PASS, node ids AND the CONTAINS_CALL/RESOLVES_TO/DEFINED_IN edge multiset match legacy.

- [ ] **Step 5: Commit**

```bash
git add orion/graph/stream_build.py tests/test_stream_build.py
git commit -m "feat(stream): bounded-window consumer pass 1, structural node+edge parity"
```

---

### Task 7: Wire the stitch into the consumer (two-pass), FLOWS_TO == 217

**Files:**
- Modify: `orion/graph/stream_build.py`
- Modify: `orion/graph/joern_adapter.py` (refactor `_entry_method_ids` to accept accumulated inputs)
- Test: `tests/test_stream_build.py::test_stream_flows_parity`

**Interfaces:**
- Produces: `stream_build.build_envelope(cpg_bin, work, profile, *, queue_size=64, resume=False, simulate_crash_after=None) -> dict`: returns the SAME `{"nodes","edges","entry_methods"}` envelope `project_graphson` returns for the whole graph, assembled from the stream. Pass 1 projects structural nodes/edges (Task 6) and accumulates the cross-method tables (`callee_edges`, `callgraph`, `method_fullname`) plus the entry-point facts; pass 2 builds one `Summary` per segment with that segment's closure seam and the reconstructed `entry_taint`; the stitch produces FLOWS_TO.
- Refactor: split `joern_adapter._entry_method_ids(g)` into `_entry_method_ids_from(method_vertices, called, has_param, callback_fulls) -> set` (the pure entry test) with `_entry_method_ids(g)` as a thin wrapper that builds the four inputs from the whole graph. The stream builds the same four inputs from its accumulators, so entry detection is the identical tested logic (delta C.3), never a re-implementation.

**Do NOT call `build_summary(mid, ..., None)`.** That omits the closure seam and yields 190, not 217. Thread each segment's `cross_rd`/`closure_targets` and the reconstructed `entry_taint`, exactly the 5th/6th args `flows_via_summaries` uses (`taint_summary.py:347-349`).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_stream_build.py
@pytest.mark.slow
def test_stream_flows_parity(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    from orion.graph import joern_adapter as J, profiles
    prof = profiles.select_profile("fixtures/NodeGoat")
    env = S.build_envelope(str(cpg), tmp_path, prof)
    flows = [e for e in env["edges"] if e["label"] == "FLOWS_TO"]
    assert len(flows) == 217
    # C.3 fix: entry_methods are full_names (not sorted summary ids) and match legacy exactly.
    legacy = J.project_graphson(_export(cpg), profile=prof)
    assert env["entry_methods"] == legacy["entry_methods"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_flows_parity -v`
Expected: FAIL, `build_envelope` missing.

- [ ] **Step 3: Implement the two-pass `build_envelope` + the entry refactor**

```python
# add to orion/graph/stream_build.py
from collections import defaultdict
from . import joern_adapter as J

def _method_fullname(seg: dict):
    mv = next(v for v in seg["vertices"] if v["id"] == seg["method_id"])
    return mv["properties"].get("FULL_NAME")

def _seg_cross_rd(seg: dict) -> dict:
    d = defaultdict(list)
    for (o, i) in seg["cross_rd"]:
        d[o].append(i)
    return dict(d)

def build_envelope(cpg_bin: str, work, profile, *, queue_size: int = 64,
                   resume: bool = False, simulate_crash_after: int = None) -> dict:
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
        for cs in seg["callsites"]:
            if cs["callee_id"] is not None:
                callee_edges[cs["call_id"]] = cs["callee_id"]
                callgraph[mid].add(cs["callee_id"])
                called.add(cs["callee_id"])
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
```

```python
# orion/graph/joern_adapter.py: split the entry test out so the stream reuses it verbatim
def _entry_method_ids_from(method_vertices: dict, called: set, has_param: set,
                           callback_fulls: set) -> set:
    """The pure structural entry-point test over accumulated inputs (see _entry_method_ids). Used by
    both the whole-graph wrapper below and the streaming consumer, so there is ONE entry logic."""
    entries: set = set()
    for vid, v in method_vertices.items():
        if bool(_prop(v, "IS_EXTERNAL")):
            continue
        if _clean(_prop(v, "FILENAME")) is None or vid not in has_param:
            continue
        name = _prop(v, "NAME") or ""
        if name.startswith("<") or name == ":program":
            continue
        is_callback = _prop(v, "FULL_NAME") in callback_fulls
        if vid in called and not is_callback:
            continue
        entries.add(vid)
    return entries

def _entry_method_ids(g: dict) -> set:
    verts = {_unwrap(v["id"]): v for v in g.get("vertices", [])}
    method_vertices = {vid: v for vid, v in verts.items() if v["label"] == "METHOD"}
    callback_fulls = {mfn for v in verts.values() if v["label"] == "METHOD_REF"
                      and isinstance((mfn := _prop(v, "METHOD_FULL_NAME")), str) and mfn}
    called, has_param = set(), set()
    for e in g.get("edges", []):
        o, i = _unwrap(e["outV"]), _unwrap(e["inV"]); lbl = e["label"]
        if lbl == "CALL" and verts.get(i, {}).get("label") == "METHOD":
            called.add(i)
        elif (lbl == "AST" and verts.get(o, {}).get("label") == "METHOD"
              and verts.get(i, {}).get("label") == "METHOD_PARAMETER_IN"):
            has_param.add(o)
    return _entry_method_ids_from(method_vertices, called, has_param, callback_fulls)
```

> `entry_methods = sorted(summaries)` is GONE (persist claim4): ints never match `normalize`'s full_name lookup, so it emitted zero EntryPoints. The stream now emits the entry methods' full_names, and `entry_taint` (GENERIC only) restores PyGoat's entry-point-param sources. Callees resolve via `callee_edges` from `callsites[].callee_id`, never a `callee_full_name -> id` re-resolution, so there is no `_attach_callees_stream` and no order-dependence.

**Memory note (Option 2).** `nodes`/`edges` accumulate the full normalized batch and are held ONCE, then Task 8 normalizes+persists it in a single call. This is the largest O(repo) resident term (spec §8); it is the accepted first-cutover model (clears the 85x blob), NOT a claim of bounded-in-repo memory. Returning the whole envelope is convenient for the Task 8 parity test; true incremental persist (Option 1) is a future follow-on.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_flows_parity -v`
Expected: PASS, exactly 217 FLOWS_TO and `entry_methods` equal to legacy.

- [ ] **Step 5: Commit**

```bash
git add orion/graph/stream_build.py orion/graph/joern_adapter.py tests/test_stream_build.py
git commit -m "feat(stream): two-pass envelope with closure seam + entry reconstruction, FLOWS_TO==217"
```

---

### Task 8: CLI + graph_build path, envelope + persist parity (delta D.3)

**Files:**
- Modify: `orion/graph_build.py` (`build()`, add `stream=`/`queue_size=`/`scan_id=`)
- Modify: `orion/cli.py` (add `--stream/--no-stream`, `--queue-size`)
- Modify: `orion/graph/joern_adapter.py` (add `ensure_cpg`)
- Modify: `orion/graph/persist.py` (add `flows_count`)
- Test: `tests/test_stream_build.py::test_stream_envelope_parity_nodegoat` (A + D)
- Test: `tests/test_stream_build.py::test_stream_two_partition_persist_parity` (B + D)
- Test: `tests/test_stream_build.py::test_stream_envelope_parity_pygoat` (E)

**Interfaces:**
- Produces: `graph_build.build(repo_path, language=None, on_event=None, *, stream=False, queue_size=64, scan_id=None) -> str`: the `scan_id` override lets two builds persist into DISTINCT partitions for parity test B; CLI flags `--stream/--no-stream` (default False for now) and `--queue-size` (default 64) threaded into `build`.
- Adds: `joern_adapter.ensure_cpg(repo_path, language=None) -> Path` (parse or reuse `cpg.bin`, NO export) and `persist.flows_count(scan_id) -> int`.

**The old FLOWS_TO-count test was a tautology (delta D.2):** legacy and stream builds of `fixtures/NodeGoat` resolve to the SAME deterministic `scan_id`, so the stream build cleared+overwrote the legacy partition and the test compared a count to itself. The `scan_id` override + the envelope-level and two-partition tests below replace it.

- [ ] **Step 1: Write the failing tests (D.3 A/B/D/E)**

```python
# add to tests/test_stream_build.py
def _nodeset(env):
    return {(n["label"], n["id"], frozenset(n["props"].items())) for n in env["nodes"]}

def _edgemulti(env):
    return Counter((e["label"], e["out"], e["in"], e.get("arg_index"), e.get("provenance"))
                   for e in env["edges"])

@pytest.mark.slow
def test_stream_envelope_parity_nodegoat(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    from orion.graph import joern_adapter as J, profiles
    prof = profiles.select_profile("fixtures/NodeGoat")
    legacy = J.project_graphson(_export(cpg), profile=prof)
    stream = S.build_envelope(str(cpg), tmp_path, prof)
    # (A) full node set (labels+ids+props) and edge multiset (structural + FLOWS_TO w/ provenance)
    assert _nodeset(stream) == _nodeset(legacy)
    assert _edgemulti(stream) == _edgemulti(legacy)
    assert stream["entry_methods"] == legacy["entry_methods"]
    # (D) structural-edge counts explicitly (subsumed by A, asserted for a sharper failure message)
    def _struct(env):
        return Counter(e["label"] for e in env["edges"] if e["label"] != "FLOWS_TO")
    assert _struct(stream) == _struct(legacy)

@pytest.mark.slow
def test_stream_two_partition_persist_parity():
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    from orion import graph_build
    from orion.graph import persist
    from neo4j import GraphDatabase
    from orion import config
    legacy_id = graph_build.build("fixtures/NodeGoat", None, None, stream=False, scan_id="parity-legacy")
    stream_id = graph_build.build("fixtures/NodeGoat", None, None, stream=True, scan_id="parity-stream")

    def _counts(sid):
        drv = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
        try:
            with drv.session(database=config.NEO4J_DATABASE) as s:
                nodes = {r["l"]: r["n"] for r in s.run(
                    "MATCH (x {scan_id:$sid}) UNWIND labels(x) AS l RETURN l, count(*) AS n", sid=sid)}
                edges = {r["t"]: r["n"] for r in s.run(
                    "MATCH ({scan_id:$sid})-[r]->() RETURN type(r) AS t, count(r) AS n", sid=sid)}
            return nodes, edges
        finally:
            drv.close()

    assert persist.flows_count(stream_id) == persist.flows_count(legacy_id) == 217
    assert _counts(stream_id) == _counts(legacy_id)   # per-label node + per-type edge parity (incl. D)

@pytest.mark.slow
def test_stream_envelope_parity_pygoat(tmp_path):
    cpg = "fixtures/PyGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("PyGoat cpg.bin not present")
    from orion.graph import joern_adapter as J, profiles
    prof = profiles.select_profile("fixtures/PyGoat")   # GENERIC: exercises entry_taint
    legacy = J.project_graphson(_export(cpg), profile=prof)
    stream = S.build_envelope(str(cpg), tmp_path, prof)
    assert _nodeset(stream) == _nodeset(legacy)
    assert _edgemulti(stream) == _edgemulti(legacy)
    assert stream["entry_methods"] == legacy["entry_methods"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py -k "envelope_parity or two_partition" -v`
Expected: FAIL, `build(..., stream=..., scan_id=...)`, `ensure_cpg`, and/or `flows_count` missing.

- [ ] **Step 3: Add the stream path to graph_build, the CLI flags, `ensure_cpg`, and `flows_count`**

```python
# orion/graph_build.py: inside build(), branch on stream; scan_id override for parity test B
def build(repo_path, language=None, on_event=None, *,
          stream=False, queue_size=64, scan_id=None):
    scan_id = scan_id or scan_id_for(repo_path)
    frontend, display_language = joern_adapter.resolve_language(repo_path, language)
    if on_event is not None:
        warn = _ambiguity_warning(repo_path, language, frontend)
        if warn is not None:
            on_event(warn)
    profile = profiles.select_profile(repo_path, display_language)
    if stream:
        import tempfile
        from pathlib import Path as _P
        from .graph import stream_build
        cpg_bin = joern_adapter.ensure_cpg(repo_path, frontend)     # parse or reuse cpg.bin, NO export
        work = _P(tempfile.mkdtemp(prefix="orion_stream_"))
        envelope = stream_build.build_envelope(str(cpg_bin), work, profile, queue_size=queue_size)
    else:
        envelope = joern_adapter.export_repo(repo_path, frontend, profile)
    dependencies = deps.parse_dependencies(repo_path)              # NOT deps.parse (does not exist)
    batch = joern_adapter.normalize(envelope, scan_id, language=display_language,
                                    dependencies=dependencies)
    persist.persist(batch)
    return scan_id
```

```python
# orion/cli.py: add to the scan subparser
scan.add_argument("--stream", dest="stream", action="store_true",
                  help="use the streaming per-function build (avoids the 85x export blob)")
scan.add_argument("--no-stream", dest="stream", action="store_false")
scan.set_defaults(stream=False)
scan.add_argument("--queue-size", dest="queue_size", type=int, default=64,
                  help="functions held in flight by the streaming build (default 64)")
# and where build() is called in _run_scan:
graph_build.build(args.repo, args.language, on_event, stream=args.stream, queue_size=args.queue_size)
```

```python
# orion/graph/joern_adapter.py: parse-only helper (the parse half of export_repo, no _run_export)
def ensure_cpg(repo_path, language=None) -> Path:
    """Parse `repo` to a cpg.bin and return its path WITHOUT exporting (the streaming producer reads
    cpg.bin directly). Reuses a prebuilt `<repo>/cpg.bin` when present; else joern-parse into a temp."""
    repo = Path(repo_path).resolve()
    cpg_bin = repo / "cpg.bin"
    if cpg_bin.exists():
        return cpg_bin
    env = _ensure_greadlink(dict(os.environ))
    env.setdefault("JAVA_HOME", os.environ.get("JAVA_HOME", ""))
    parse = _joern_bin("joern-parse")
    if not parse.exists():
        raise RuntimeError(f"joern-parse not found under {config.JOERN_HOME} (set JOERN_HOME)")
    out_cpg = Path(tempfile.mkdtemp(prefix="orion_cpg_")) / "cpg.bin"
    r = subprocess.run([str(parse), *_jvm_flags(), str(repo),
                        "--language", language or _guess_language(repo), "--output", str(out_cpg)],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0 or not out_cpg.exists():
        raise RuntimeError(f"joern-parse failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
    return out_cpg
```

```python
# orion/graph/persist.py: read helper (FLOWS_TO carries scan_id via schema.emit_edge)
def flows_count(scan_id: str) -> int:
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            return s.run("MATCH ()-[r:FLOWS_TO {scan_id:$sid}]->() RETURN count(r) AS n",
                         sid=scan_id).single()["n"]
    finally:
        driver.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py -k "envelope_parity or two_partition" -v`
Expected: PASS, envelope node/edge/entry parity (NodeGoat + PyGoat) and two-partition DB parity with FLOWS_TO exactly 217.

- [ ] **Step 5: Commit**

```bash
git add orion/graph_build.py orion/cli.py orion/graph/persist.py orion/graph/joern_adapter.py tests/test_stream_build.py
git commit -m "feat(stream): --stream/--queue-size CLI path + envelope/two-partition persist parity"
```

---

### Task 9: Resume from cursor + order-independence

**Files:**
- Modify: `orion/graph/stream_build.py`
- Test: `tests/test_stream_build.py::test_resume_equals_uninterrupted`
- Test: `tests/test_stream_build.py::test_stream_order_independence`

**Interfaces:**
- Consumes: `_iter_segments(path, start)`, a `work/cursor` file, and persisted pass-1 tables (`work/tables.json`).
- Produces: `build_envelope(..., resume=True)` skips `run_producer` (the durable numbered `segments.jsonl` is never re-produced), reads `work/cursor` as the pass-1 `start`, and reloads the persisted pass-1 tables (`callee_edges`, `callgraph`, `method_fullname`, `method_vertices`, `called`, `has_param`, `callback_fulls`) before continuing. The consumer writes the cursor + tables after each pass-1 batch. A test-only `simulate_crash_after` stops pass 1 early with `SimulatedCrash`.

**Cursor aligns with the Option-2 batch-at-end boundary.** Persist happens ONCE at the very end (Task 8), so a crash before it loses only the DB write, never the segments. Resume replays pass 1 from the cursor (reusing the persisted tables), then re-runs pass 2 + stitch (both deterministic and cheap). Because the consumer is order-independent (below), the resumed result is identical to an uninterrupted one.

- [ ] **Step 1: Write the failing tests**

```python
# add to tests/test_stream_build.py
import random

@pytest.mark.slow
def test_resume_equals_uninterrupted(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    from orion.graph import profiles
    prof = profiles.select_profile("fixtures/NodeGoat")
    full = S.build_envelope(str(cpg), tmp_path / "a", prof)
    w = tmp_path / "b"
    with pytest.raises(S.SimulatedCrash):
        S.build_envelope(str(cpg), w, prof, simulate_crash_after=100)
    resumed = S.build_envelope(str(cpg), w, prof, resume=True)   # reuses segments.jsonl + cursor + tables
    fa = sorted((e["out"], e["in"], e["arg_index"]) for e in full["edges"] if e["label"] == "FLOWS_TO")
    fb = sorted((e["out"], e["in"], e["arg_index"]) for e in resumed["edges"] if e["label"] == "FLOWS_TO")
    assert fa == fb

@pytest.mark.slow
def test_stream_order_independence(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    from orion.graph import profiles
    prof = profiles.select_profile("fixtures/NodeGoat")
    a, b = tmp_path / "a", tmp_path / "b"; b.mkdir(parents=True)
    base = S.build_envelope(str(cpg), a, prof)                   # produces a/segments.jsonl once
    lines = (a / "segments.jsonl").read_text().splitlines()
    preamble = [l for l in lines if json.loads(l)["seg"] == -1]
    perfunc = [l for l in lines if json.loads(l)["seg"] >= 0]
    random.Random(1).shuffle(perfunc)                            # random per-function ordering
    (b / "segments.jsonl").write_text("\n".join(preamble + perfunc) + "\n")
    shuffled = S.build_envelope(str(cpg), b, prof, resume=True)  # reuse shuffled file, no producer
    def fs(env):
        return {(e["out"], e["in"], e["arg_index"]) for e in env["edges"] if e["label"] == "FLOWS_TO"}
    assert fs(base) == fs(shuffled)                              # keyed by method_id, not seg order
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py -k "resume or order_independence" -v`
Expected: FAIL, cursor/resume + `SimulatedCrash` not implemented; `resume=True` still re-runs the producer.

- [ ] **Step 3: Implement cursor + tables persistence + resume + `SimulatedCrash`**

```python
# in orion/graph/stream_build.py
class SimulatedCrash(RuntimeError):
    pass

def _read_cursor(work) -> int:
    p = Path(work) / "cursor"
    return int(p.read_text()) if p.exists() else 1     # line-1 is the first per-function record

# In build_envelope pass 1:
#   - resume=True: skip run_producer when segments.jsonl exists; start = _read_cursor(work);
#     reload work/tables.json into (callee_edges, callgraph, method_fullname, method_vertices,
#     called, has_param, callback_fulls) BEFORE the loop.
#   - after each bounded-window batch: write work/tables.json (the accumulators) and
#     (work/"cursor").write_text(str(last_line_index + 1)).
#   - if simulate_crash_after is not None and processed_count >= simulate_crash_after:
#         raise SimulatedCrash  (AFTER the cursor+tables for completed batches are written)
# Pass 2 always re-reads the whole segments.jsonl from line 1 (deterministic, order-independent).
```

> Order-independence is by construction: `best` is an AND-reduction, `param_flows`/closure targets are sets, `callgraph` is set-union, callee resolution uses `callee_id` (never an order-dependent `callee_full_name -> id`), and persist is a single clear-then-CREATE. So any per-function ordering yields the identical FLOWS_TO set (spec §9). The one remaining name-resolution, METHOD_REF full_name for entry detection, is entry-only; key on `(full_name, filename)` if a repo ever collides first-party full_names.

- [ ] **Step 4: Run tests to verify they pass**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py -k "resume or order_independence" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orion/graph/stream_build.py tests/test_stream_build.py
git commit -m "feat(stream): resumable consumer (cursor + tables) + order-independence property test"
```

---

## Phase 3, Gate, scale, flip default

### Task 10: sharpemu scale smoke (peak-RSS bound + honest breakdown)

**Files:**
- Modify: `orion/graph/stream_build.py` (optional `mem_stats_path` diagnostic hook)
- Modify: `orion/graph_build.py` (forward `mem_stats_path` in the stream branch)
- Test: `tests/test_stream_build.py::test_sharpemu_fits_memory`

**Interfaces:**
- Consumes: `graph_build.build(..., stream=True, mem_stats_path=...)`; `resource.getrusage` for peak RSS.
- Produces: `build_envelope` writes a JSON breakdown to `mem_stats_path` when given: `window_peak_mb` (max decoded-window + per-segment projection bytes), `accumulators_mb` (summaries + callgraph + callee_edges + tables), `batch_mb` (the held normalized node/edge batch), `driver_mb` (Neo4j driver estimate). This MEASURES the O(repo) terms instead of assuming them (delta consumer F5).

**Honest model (spec §8 / delta C.2).** Memory is NOT constant in repo size. The `< 6000 MB` budget already concedes that. The breakdown makes the terms visible: `window` is bounded by `queue_size`; `accumulators` and `batch` grow O(repo) but each is ~1x graph size, ~85x below the pretty-JSON blob. If the budget is exceeded, the batch is the largest term (Option 1 incremental persist is the follow-on that bounds it).

- [ ] **Step 1: Write the failing/skipping test**

```python
# add to tests/test_stream_build.py
import resource
@pytest.mark.slow
def test_sharpemu_fits_memory(tmp_path):
    repo = "fixtures/sharpemu"
    if not Path(repo).exists():
        pytest.skip("sharpemu not cloned")
    from orion import graph_build
    stats_path = tmp_path / "mem.json"
    graph_build.build(repo, "csharpsrc", None, stream=True, queue_size=64,
                      mem_stats_path=str(stats_path))
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)  # bytes on macOS
    assert peak_mb < 6000, f"stream build peaked at {peak_mb:.0f} MB"
    br = json.loads(stats_path.read_text())
    for k in ("window_peak_mb", "accumulators_mb", "batch_mb", "driver_mb"):
        assert k in br, f"missing peak-RSS breakdown term: {k}"
    print("peak-RSS breakdown (MB):", br, "total getrusage:", round(peak_mb))
```

- [ ] **Step 2: Run it**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_sharpemu_fits_memory -v -s`
Expected: PASS (builds under ~6 GB, breakdown recorded) or SKIP. If it exceeds budget, the breakdown identifies which O(repo) term dominates (expected: `batch_mb`), which motivates the Option-1 incremental-persist follow-on rather than a hidden regression.

- [ ] **Step 3: Commit**

```bash
git add orion/graph/stream_build.py orion/graph_build.py tests/test_stream_build.py
git commit -m "test(stream): sharpemu within budget + measured peak-RSS breakdown"
```

---

### Task 11: Flip `--stream` to default; keep `--no-stream` escape hatch

**Files:**
- Modify: `orion/cli.py` (`set_defaults(stream=True)`)
- Modify: `CLAUDE.md` (document the streaming build, `--queue-size`, `--no-stream`, the honest memory model)
- Test: NodeGoat AND PyGoat streaming parity + full token-free suite + NodeGoat recall eval

- [ ] **Step 1: Gate on BOTH NodeGoat and PyGoat streaming parity**

Run the streaming parity gates green before flipping (not NodeGoat alone; Task 4 is a Phase-1 oracle test, not an end-to-end stream test):
```bash
./.venv/bin/python -m pytest tests/test_stream_build.py \
  -k "producer or structural_parity or flows_parity or envelope_parity or two_partition or resume or order_independence" -v
```
Expected: PASS on NodeGoat, and PASS (or SKIP only if the fixture is absent) on PyGoat. Both `test_stream_envelope_parity_pygoat` and `test_producer_closure_parity_pygoat` must pass when `fixtures/PyGoat/cpg.bin` is present.

- [ ] **Step 2: Run the NodeGoat recall eval on the stream path**

Run the existing eval against a `--stream` build of NodeGoat.
Expected: **14/15** recall, 0 true false positives, unchanged.

- [ ] **Step 3: Flip the default**

```python
# orion/cli.py
scan.set_defaults(stream=True)   # was False
```

- [ ] **Step 4: Run the full token-free suite**

Run: `./.venv/bin/python -m pytest -m "not slow" -q`
Expected: all pass (>= 69).

- [ ] **Step 5: Update CLAUDE.md (honest memory model + three-family closure)**

Document, precisely:
- streaming build is the default; `--no-stream` reverts to the whole-graph export; `--queue-size` default 64.
- streaming AVOIDS building/parsing the 85x pretty-JSON blob. Memory is `O(window + compact accumulators + normalized batch)`, roughly one graph size and ~85x below the blob. It is NOT "flat in repo size": the producer is bounded, the consumer is bounded-window but O(repo) in accumulators + the batch-at-end (Option 2) normalized batch. True incremental persist (Option 1) is a future follow-on.
- the summary-stitch taint reproduces `collapse_flows` exactly (oracle-tested at 217), including the THIRD cross-edge family: cross-method REACHING_DEF closure edges, carried per-segment (`cross_rd` source side dropping method-less targets; `closure_targets` target side keeping method-less sources) and threaded into `build_summary`'s `cross_rd`/`closure_targets` args. `build_summary`/`_reach_full`/`stitch` are byte-for-byte the Phase-1 code.

- [ ] **Step 6: Commit**

```bash
git add orion/cli.py CLAUDE.md
git commit -m "feat(stream): make streaming build the default (whole-graph via --no-stream)"
```

---

## Self-Review

**Spec coverage:**
- §4 pipeline (producer/queue/two-pass consumer/stitch) to Tasks 5,6,7,8. ✓
- §5 segment schema (preamble + per-function, METHOD-in-vertices, endpoint labels, CONTAINS, callsites callee_id, cross_rd/closure_targets) + reconstruction rules (RESOLVES_TO/DEFINED_IN by id, closure third family) to Tasks 5,6,7. ✓
- §6 summary-stitch algorithm incl. the closure_out third family to Tasks 1,2,3 (Phase 1 code) and its per-segment sourcing to Tasks 5,7 (+4 GENERIC path). ✓
- §7 rollout order (refactor behind legacy, --stream, gate, flip) to Phase 1 (behind legacy), Task 8 (flag), Task 11 (flip). ✓
- §8 honest memory model + resume to Tasks 9,10. ✓
- §9 testing (oracle, structural node+edge, closure parity, envelope, recall, scale, resume, order-independence) to Tasks 3,4,5,6,7,8,9,10,11. ✓
- §2 parity gate (NodeGoat 217 + PyGoat + 14/15) to Tasks 3,4,5,8,11. ✓
- §10 stage two to explicitly out of scope; queue built to enable it (Task 5 durable numbered stream). ✓

**Placeholder scan:** The Task 5 flatgraph `.sc` helpers (`propJson`, `intraEdges`, `sourceFileId`, `realCalls`, `calleeId`, `argMap`, `crossRd`, `closureTargets`) are the one place the engineer iterates against hard tests rather than copying final code: their accessor spellings are pinned by the REQUIRED Step-1 live probe, and their output is acceptance-gated by `test_producer_matches_python_partition` (partition equivalence), the closure-parity gates (`prod_cross`/`prod_targets` unions), and downstream `test_stream_flows_parity == 217`. The §5 schema plus the probe directive is the contract; the passing tests are the definition of done.

**Type consistency:** `Summary` fields (`direct`, `params`, `real_calls`, `internal_sources`, `callsite`, `closure_out`, `callee_edges`) are used consistently. `build_summary(method_id, sub, request_source_names, entrypoint_method_ids, cross_rd=None, closure_targets=())`, `stitch(summaries, callgraph, *, request_source_names, entrypoint_method_ids)`, `flows_via_summaries`, `partition`, `owner_map`, `_closure_edges`, `run_producer`, `build_envelope`, `collect_structural`, `_entry_method_ids_from`, `flows_count`, `ensure_cpg`, and `graph_build.build(..., stream, queue_size, scan_id)` signatures match between definition and call sites. FLOWS_TO dict shape identical to `collapse_flows`. The stale `build_summary(mid, ..., None)` call and the removed `_attach_callees_stream`/`entry_methods = sorted(summaries)` no longer appear. ✓
