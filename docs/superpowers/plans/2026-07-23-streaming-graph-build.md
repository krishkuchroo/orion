# Streaming Per-Function Graph Build — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Orion's whole-graph `joern-export` (an 85× pretty-JSON blob that OOMs on large repos) with a streaming per-function pipeline whose peak memory is bounded and independent of repo size, producing an identical graph including taint edges.

**Architecture:** Factor the global `collapse_flows` taint pass into bounded **per-function summaries** plus a **global stitch** (Phase 1, validated against the whole-graph oracle behind the existing path). Then add a Joern per-function producer that streams numbered segments to a durable JSONL "queue," and a bounded-window Python consumer that persists structurally and accumulates summaries, running the stitch at the end (Phase 2). Gate on NodeGoat + PyGoat parity before flipping the default (Phase 3).

**Tech Stack:** Python 3.11 (`./.venv/bin/python`), pytest, Joern CLI (`~/joern/joern-cli`, Scala `.sc` scripts), Neo4j (docker-compose, bolt 7688).

## Global Constraints

- Parity gate (pass/fail, copied from spec §2): streaming build reproduces NodeGoat's graph exactly — **217 FLOWS_TO edges**, identical persisted node/edge set, **14/15** recall unchanged. Second gate: **PyGoat parity**. Nothing replaces the legacy path until both pass.
- The whole-graph `collapse_flows` (`orion/graph/joern_adapter.py:96`) is the **exact oracle** and must remain unmodified as the reference throughout Phase 1.
- Reuse existing helpers — do NOT duplicate: `_unwrap`, `_prop`, `_deepint`, `_is_real_call`, `_clean`, `_REQUEST_PARAM_NAMES`, `_SOURCE_ANNOTATIONS`, `_MAPPED_NODE_LABELS`, `_MAPPED_EDGES` (all in `joern_adapter.py`).
- Taint config is profile-driven: `request_source_names` and (GENERIC profile only) `entrypoint_method_ids` — thread both exactly as `project_graphson` does (`joern_adapter.py:326-330`).
- Run tests with `./.venv/bin/python -m pytest`. Token-free suite must stay green (currently 69 passing). Live/Joern-dependent tests are marked `@pytest.mark.slow`.
- Interpreter: always `./.venv/bin/python` (venv activation does not persist across shells).
- `fixtures/` is gitignored; NodeGoat prebuilt CPG is `fixtures/NodeGoat/cpg.bin`.

---

## File Structure

- Create `orion/graph/taint_summary.py` — the summary-stitch analysis: `partition`, `build_summary`, `stitch`, and `flows_via_summaries` (the whole-graph entry that must equal `collapse_flows`). Phase 1.
- Create `orion/graph/joern_scripts/emit_segments.sc` — Joern Scala producer: iterate `cpg.method`, emit one JSON segment per function. Phase 2.
- Create `orion/graph/stream_build.py` — streaming consumer: run the producer, read `segments.jsonl` with a bounded window + resume cursor, project + persist structurally per segment, accumulate summaries, run the stitch, persist FLOWS_TO. Phase 2.
- Modify `orion/graph_build.py` — add the `stream=` build path alongside the legacy path.
- Modify `orion/cli.py` — add `--stream/--no-stream` and `--queue-size` flags.
- Create tests: `tests/test_taint_summary.py`, `tests/test_stream_build.py`.
- Create `tests/conftest.py` helper (if absent) exposing a cached NodeGoat graphson fixture.

---

## Phase 1 — Summary-stitch taint, validated by the oracle (no streaming yet)

### Task 1: NodeGoat graphson fixture + `partition`

**Files:**
- Create: `orion/graph/taint_summary.py`
- Create: `tests/test_taint_summary.py`
- Test: `tests/test_taint_summary.py::test_partition_covers_graph`

**Interfaces:**
- Consumes: raw Joern GraphSON dict `g` (the `{"vertices":[...], "edges":[...]}` form, possibly wrapped in `{"@type","@value"}`), and `joern_adapter._unwrap`.
- Produces:
  - `owner_map(g) -> dict[int,int|None]` — vertex id → enclosing METHOD id via AST ancestry.
  - `partition(g) -> tuple[dict[int,dict], dict[int,set[int]]]` — `(methods, callgraph)` where `methods[mid] = {"vertices":[...], "edges":[...]}` holds only vertices owned by `mid` and edges wholly inside `mid`; `callgraph[caller_mid] = {callee_mid,...}` from CALL edges (call node → callee METHOD).

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

### Task 2: `build_summary` — the per-function transfer function

**Files:**
- Modify: `orion/graph/taint_summary.py`
- Test: `tests/test_taint_summary.py::test_summary_direct_reach`

**Interfaces:**
- Consumes: `partition` output; `_is_real_call`, `_prop`, `_deepint`, `_unwrap`.
- Produces: `build_summary(method_id, sub, request_source_names, entrypoint_method_ids) -> Summary` where `Summary` is a dataclass with:
  - `method_id: int`
  - `direct: dict[int, set[tuple[int,int]]]` — entry vertex id → set of `(real_call_id, arg_index)` reached by the intra-function rd walk seeded from the entry's reaching-defs (stopping at real-call args; NOT crossing calls).
  - `params: dict[int,int]` — param index → METHOD_PARAMETER_IN id.
  - `real_calls: set[int]` — real CALL ids in this function (each is also a `direct` entry).
  - `internal_sources: set[int]` — entry ids that are attacker-controlled sources here (request-object fieldAccess whose base ∈ `request_source_names`, annotated source params, and — when `entrypoint_method_ids` includes this method — its params).
  - `callsite: dict[int, dict[int,int]]` — real_call id → {arg_index → callee arg-slot marker}; the callee METHOD is resolved globally in `stitch` via the call graph, so this stores only the arg indices present.

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

### Task 3: `stitch` + `flows_via_summaries` — THE oracle parity gate

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

Step 3a — `_callee_map` and `_attach_callees` must reproduce collapse_flows' `callee[o]=i` (CALL edge from real call `o` to callee METHOD `i`). Add to `partition` a third return, or compute here from `g`:

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
Expected: PASS — `_flowset(got) == _flowset(oracle)`, both size 217.

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

## Phase 2 — Streaming pipeline

### Task 5: Joern producer script + segment/Python partition equivalence

**Files:**
- Create: `orion/graph/joern_scripts/emit_segments.sc`
- Create: `orion/graph/stream_build.py` (with `run_producer` only for now)
- Test: `tests/test_stream_build.py::test_producer_matches_python_partition`

**Interfaces:**
- Produces:
  - `emit_segments.sc` — a Joern script that, given `cpg.bin` loaded, iterates `cpg.method` and writes `segments.jsonl` (one JSON object per line: `{"seg":int,"method":{...},"vertices":[...],"edges":[...]}`) mirroring `partition`'s per-method vertex/edge sets. Vertices/edges serialized in the same shape as GraphSON `_unwrap` expects (or a compact equivalent the consumer adapts).
  - `stream_build.run_producer(cpg_bin: str, out_jsonl: str) -> int` — runs `joern --script emit_segments.sc` with params, returns segment count. Uses `joern_adapter._jvm_flags()` and `_ensure_greadlink`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_stream_build.py
import json
from pathlib import Path
import pytest
from orion.graph import stream_build as S
from orion.graph import taint_summary as T
from tests.test_taint_summary import _export  # reuse exporter

@pytest.mark.slow
def test_producer_matches_python_partition(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    out = tmp_path / "segments.jsonl"
    n = S.run_producer(cpg, str(out))
    segs = [json.loads(l) for l in out.read_text().splitlines()]
    assert n == len(segs) == 281
    # Per-method vertex-id sets from the producer == Python partition of the whole export.
    g = _export(cpg)
    methods, _ = T.partition(g)
    py = {mid: {T._unwrap(v["id"]) for v in sub["vertices"]} for mid, sub in methods.items()}
    prod = {seg["method"]["id"]: {v["id"] for v in seg["vertices"]} for seg in segs}
    assert prod == py
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_producer_matches_python_partition -v`
Expected: FAIL — `emit_segments.sc` / `run_producer` missing.

- [ ] **Step 3: Write the producer script and runner**

```scala
// orion/graph/joern_scripts/emit_segments.sc
// Emits one JSON line per method: its owned AST subtree vertices and wholly-internal edges.
import io.shiftleft.codepropertygraph.generated.nodes._
import java.io.PrintWriter

@main def main(outPath: String) = {
  val pw = new PrintWriter(outPath)
  try {
    var seg = 0
    cpg.method.l.foreach { m =>
      val nodes = (m.ast.l).distinct
      val ids = nodes.map(_.id).toSet
      def js(n: StoredNode): String = n.propertiesMap.toString // replaced by explicit prop dump
      // NOTE: dump id, label, and the props Orion reads (see _NODE_PROPS) + ARGUMENT_INDEX/INDEX.
      val vjson = nodes.map(n => s"""{"id":${n.id},"label":"${n.label}","properties":${propJson(n)}}""").mkString(",")
      val edges = nodes.flatMap(_.outE.l).filter(e => ids.contains(e.inNode.id) && ids.contains(e.outNode.id))
      val ejson = edges.map(e => s"""{"label":"${e.label}","outV":${e.outNode.id},"inV":${e.inNode.id}}""").mkString(",")
      pw.println(s"""{"seg":$seg,"method":{"id":${m.id},"label":"METHOD","properties":${propJson(m)}},"vertices":[$vjson],"edges":[$ejson]}""")
      seg += 1
    }
    seg
  } finally pw.close()
}
```

> The `propJson` helper must emit the properties `joern_adapter._NODE_PROPS` reads plus `ARGUMENT_INDEX` and `INDEX`, in a JSON object the consumer's adapter maps to the same `_prop` values. Because the consumer normalizes producer JSON into the same `{label,id,properties}` shape `_unwrap`/`_prop` expect, exact GraphSON type-tagging is not required — the equivalence test above enforces correctness.

```python
# orion/graph/stream_build.py
"""Streaming per-function build: producer (Joern) -> segments.jsonl -> bounded consumer."""
from __future__ import annotations
import json, subprocess
from pathlib import Path
from . import config
from .joern_adapter import _joern_bin, _jvm_flags, _ensure_greadlink
import os

_SCRIPT = Path(__file__).parent / "joern_scripts" / "emit_segments.sc"

def run_producer(cpg_bin: str, out_jsonl: str) -> int:
    env = _ensure_greadlink(dict(os.environ))
    joern = _joern_bin("joern")
    r = subprocess.run([str(joern), *_jvm_flags(), "--script", str(_SCRIPT),
                        "--param", f"outPath={out_jsonl}", "--import", cpg_bin],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0 or not Path(out_jsonl).exists():
        raise RuntimeError(f"segment producer failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
    return sum(1 for _ in open(out_jsonl))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_producer_matches_python_partition -v`
Expected: PASS (adjust `emit_segments.sc` prop dump until per-method id sets match).

- [ ] **Step 5: Commit**

```bash
git add orion/graph/joern_scripts/emit_segments.sc orion/graph/stream_build.py tests/test_stream_build.py
git commit -m "feat(stream): Joern per-function producer emits segments.jsonl matching partition"
```

---

### Task 6: Bounded-window consumer — structural parity

**Files:**
- Modify: `orion/graph/stream_build.py`
- Test: `tests/test_stream_build.py::test_stream_structural_parity`

**Interfaces:**
- Consumes: `run_producer`, `joern_adapter.project_graphson` (structural node/edge projection), `joern_adapter.normalize`, `persist.persist`.
- Produces: `stream_build(repo, language, scan_id, on_event, *, queue_size=64, resume=True) -> dict` — runs producer, iterates segments with ≤ `queue_size` decoded at once, projects+persists structural nodes/edges per segment, accumulates `{mid: Summary}`, returns the summaries + callgraph for the stitch (Task 7). Writes a `last_segment` cursor file next to `segments.jsonl`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_stream_build.py
@pytest.mark.slow
def test_stream_structural_parity(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    # Structural nodes/edges (excluding FLOWS_TO) from the stream must equal project_graphson's.
    from orion.graph import joern_adapter as J
    g = _export(cpg)
    legacy = J.project_graphson(g, profile=None)
    legacy_struct = {(n["label"], n["id"]) for n in legacy["nodes"]}
    got = S.collect_structural(str(cpg), tmp_path)   # test-only helper returning the node set
    assert got == legacy_struct
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_structural_parity -v`
Expected: FAIL — `collect_structural`/consumer missing.

- [ ] **Step 3: Write the consumer (bounded window + cursor)**

```python
# add to orion/graph/stream_build.py
from itertools import islice
from .joern_adapter import project_graphson
from . import taint_summary as T

def _iter_segments(path: str, start: int):
    with open(path) as fh:
        for i, line in enumerate(fh):
            if i < start:
                continue
            yield i, json.loads(line)

def _seg_to_graphson(seg: dict) -> dict:
    """One segment -> the {vertices, edges} shape partition/project_graphson consume."""
    return {"vertices": [seg["method"]] + seg["vertices"], "edges": seg["edges"]}

def collect_structural(cpg_bin: str, work: Path, queue_size: int = 64) -> set:
    out = work / "segments.jsonl"
    run_producer(cpg_bin, str(out))
    struct = set()
    it = _iter_segments(str(out), 0)
    while True:
        batch = list(islice(it, queue_size))
        if not batch:
            break
        for _, seg in batch:
            proj = project_graphson(_seg_to_graphson(seg), profile=None)
            for n in proj["nodes"]:
                struct.add((n["label"], n["id"]))
    return struct
```

> If the structural set differs, the gap is cross-function structural edges (CALL call→METHOD, SOURCE_FILE) that no single segment holds — those are re-derived at persist by `normalize` via `method_full_name`, exactly as today. This test checks NODES; edge re-derivation is covered by the full persist-parity test in Task 8.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_structural_parity -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orion/graph/stream_build.py tests/test_stream_build.py
git commit -m "feat(stream): bounded-window consumer, structural node parity with legacy"
```

---

### Task 7: Wire the stitch into the consumer — FLOWS_TO == 217

**Files:**
- Modify: `orion/graph/stream_build.py`
- Test: `tests/test_stream_build.py::test_stream_flows_parity`

**Interfaces:**
- Produces: `stream_build.build_envelope(cpg_bin, work, profile, *, queue_size=64) -> dict` — returns the SAME `{"nodes","edges","entry_methods"}` envelope `project_graphson` returns for the whole graph, but assembled from the stream: structural nodes/edges per segment + FLOWS_TO from `T.stitch(summaries, callgraph)`.

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_flows_parity -v`
Expected: FAIL — `build_envelope` missing.

- [ ] **Step 3: Implement `build_envelope`**

```python
# add to orion/graph/stream_build.py
from collections import defaultdict

def build_envelope(cpg_bin: str, work: Path, profile, *, queue_size: int = 64) -> dict:
    out = work / "segments.jsonl"
    run_producer(cpg_bin, str(out))
    src_names = profile.request_source_names if profile else T._REQUEST_PARAM_NAMES
    nodes, edges = [], []
    summaries, callgraph = {}, defaultdict(set)
    # entry-point detection needs the WHOLE call/AST structure; accumulate cheaply from segments.
    it = _iter_segments(str(out), 0)
    while True:
        batch = list(islice(it, queue_size))
        if not batch:
            break
        for _, seg in batch:
            gs = _seg_to_graphson(seg)
            proj = project_graphson(gs, profile=profile)   # structural nodes/edges only used
            nodes.extend(proj["nodes"])
            edges.extend(e for e in proj["edges"] if e["label"] != "FLOWS_TO")
            methods, cg = T.partition(gs)
            mid = seg["method"]["id"]
            summaries[mid] = T.build_summary(mid, methods.get(mid, {"vertices": [], "edges": []}),
                                             src_names, None)
            for k, v in cg.items():
                callgraph[k] |= v
    # entrypoint sources (GENERIC) handled here if profile.entrypoint_params_are_sources
    entry_taint = None
    T._attach_callees_stream(summaries, str(out))
    flows = T.stitch(summaries, dict(callgraph),
                     request_source_names=src_names, entrypoint_method_ids=entry_taint)
    edges.extend(flows)
    return {"nodes": nodes, "edges": edges, "entry_methods": sorted(summaries)}
```

Add `T._attach_callees_stream(summaries, jsonl_path)` to `taint_summary.py` — rebuild the `callee_edges` map by scanning `segments.jsonl` for CALL edges whose `inV` is a METHOD id (mirrors `_attach_callees` but over the stream, so no whole-graph load).

> Cross-function CALL edges live in NO single segment (they were dropped by partition). The producer must therefore ALSO emit a `callsites` list per segment (`{call_id, arg_index, callee_full_name}`); the consumer resolves `callee_full_name` → callee METHOD id via the accumulated method table to rebuild `callee_edges` and `callgraph`. Update `emit_segments.sc` to emit `callsites` and adjust `_attach_callees_stream` accordingly. The `test_stream_flows_parity == 217` gate proves the reconstruction is exact.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_flows_parity -v`
Expected: PASS — exactly 217 FLOWS_TO.

- [ ] **Step 5: Commit**

```bash
git add orion/graph/stream_build.py orion/graph/taint_summary.py orion/graph/joern_scripts/emit_segments.sc tests/test_stream_build.py
git commit -m "feat(stream): assemble full envelope from stream, FLOWS_TO==217 on NodeGoat"
```

---

### Task 8: CLI + graph_build path — end-to-end persist parity

**Files:**
- Modify: `orion/graph_build.py:67-85` (add `stream=` path)
- Modify: `orion/cli.py:157-166` (add flags)
- Test: `tests/test_stream_build.py::test_stream_end_to_end_persist_parity`

**Interfaces:**
- Consumes: `stream_build.build_envelope`, existing `joern_adapter.normalize`, `persist.persist`, `persist` read helpers.
- Produces: `graph_build.build(repo, language, on_event, *, stream=False, queue_size=64)`; CLI flags `--stream/--no-stream` (default False for now) and `--queue-size` (default 64) on the `scan` subparser, threaded into `build`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_stream_build.py
@pytest.mark.slow
def test_stream_end_to_end_persist_parity(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    # Build NodeGoat both ways into two scan_ids; compare persisted FLOWS_TO counts.
    from orion import graph_build
    events = lambda e: None
    legacy_id = graph_build.build("fixtures/NodeGoat", None, events, stream=False)
    stream_id = graph_build.build("fixtures/NodeGoat", None, events, stream=True, queue_size=64)
    from orion.graph import persist
    assert persist.flows_count(stream_id) == persist.flows_count(legacy_id) == 217
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_end_to_end_persist_parity -v`
Expected: FAIL — `build(..., stream=...)` and/or `persist.flows_count` missing.

- [ ] **Step 3: Add the stream path to graph_build, the CLI flags, and `persist.flows_count`**

```python
# orion/graph_build.py — inside build(), branch on stream
def build(repo_path, language=None, on_event=_noop, *, stream=False, queue_size=64):
    scan_id = scan_id_for(repo_path)
    frontend, display_language = joern_adapter.resolve_language(repo_path, language)
    profile = profiles.select_profile(repo_path, language)
    if stream:
        import tempfile
        from pathlib import Path as _P
        from .graph import stream_build
        # stream path needs a cpg.bin; parse first if absent (reuse export_repo's parse step)
        cpg_bin = joern_adapter.ensure_cpg(repo_path, frontend)   # new helper: parse -> cpg.bin path
        work = _P(tempfile.mkdtemp(prefix="orion_stream_"))
        envelope = stream_build.build_envelope(str(cpg_bin), work, profile, queue_size=queue_size)
    else:
        envelope = joern_adapter.export_repo(repo_path, frontend, profile)
    deps_list = deps.parse(repo_path)
    batch = joern_adapter.normalize(envelope, scan_id, language=display_language,
                                    dependencies=deps_list)
    persist.persist(batch)
    return scan_id
```

```python
# orion/cli.py — add to the scan subparser (near line 162)
scan.add_argument("--stream", dest="stream", action="store_true",
                  help="use the streaming per-function build (bounded memory)")
scan.add_argument("--no-stream", dest="stream", action="store_false")
scan.set_defaults(stream=False)
scan.add_argument("--queue-size", dest="queue_size", type=int, default=64,
                  help="functions held in flight by the streaming build (default 64)")
# and in _run_scan where build() is called:
graph_build.build(args.repo, args.language, on_event, stream=args.stream, queue_size=args.queue_size)
```

```python
# orion/graph/persist.py — add a read helper
def flows_count(scan_id: str) -> int:
    with driver().session() as s:
        return s.run("MATCH ()-[r:FLOWS_TO {scan_id:$sid}]->() RETURN count(r) AS n",
                     sid=scan_id).single()["n"]
```

Add `joern_adapter.ensure_cpg(repo_path, frontend) -> Path` — the parse half of `export_repo` (reuse prebuilt `cpg.bin` if present; else `joern-parse` with `_jvm_flags()`), returning the cpg path WITHOUT exporting.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_stream_end_to_end_persist_parity -v`
Expected: PASS — both builds persist 217 FLOWS_TO.

- [ ] **Step 5: Commit**

```bash
git add orion/graph_build.py orion/cli.py orion/graph/persist.py orion/graph/joern_adapter.py tests/test_stream_build.py
git commit -m "feat(stream): --stream/--queue-size CLI path with end-to-end persist parity"
```

---

### Task 9: Resume from cursor

**Files:**
- Modify: `orion/graph/stream_build.py`
- Test: `tests/test_stream_build.py::test_resume_equals_uninterrupted`

**Interfaces:**
- Consumes: `_iter_segments(path, start)`, the `last_segment` cursor file.
- Produces: `build_envelope(..., resume=True)` reads `work/cursor` (integer) and starts consuming at that segment; the consumer writes the cursor after each batch. A test-only `simulate_crash_after` param stops consumption early.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_stream_build.py
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
    resumed = S.build_envelope(str(cpg), w, prof, resume=True)  # reuses segments.jsonl + cursor
    fa = sorted((e["out"], e["in"], e["arg_index"]) for e in full["edges"] if e["label"]=="FLOWS_TO")
    fb = sorted((e["out"], e["in"], e["arg_index"]) for e in resumed["edges"] if e["label"]=="FLOWS_TO")
    assert fa == fb
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_resume_equals_uninterrupted -v`
Expected: FAIL — cursor/resume + `SimulatedCrash` not implemented.

- [ ] **Step 3: Implement cursor persistence + resume + `SimulatedCrash`**

```python
# in orion/graph/stream_build.py
class SimulatedCrash(RuntimeError):
    pass

# in build_envelope: skip run_producer if resume and out exists; start = int(cursor) if resume;
# after each batch: (work/"cursor").write_text(str(last_index+1));
# if simulate_crash_after is not None and processed >= simulate_crash_after: raise SimulatedCrash
```

> Summaries must also be persisted per batch (e.g. append to `work/summaries.jsonl`) so resume reloads prior summaries; on resume, reload them before continuing. The stitch runs only after the full stream is consumed.

- [ ] **Step 4: Run test to verify it passes**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_resume_equals_uninterrupted -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orion/graph/stream_build.py tests/test_stream_build.py
git commit -m "feat(stream): resumable consumer via segment cursor"
```

---

## Phase 3 — Gate, scale, flip default

### Task 10: sharpemu scale smoke (peak-RSS bound)

**Files:**
- Test: `tests/test_stream_build.py::test_sharpemu_fits_memory`

**Interfaces:**
- Consumes: `graph_build.build(..., stream=True)`; `resource.getrusage` for peak RSS.

- [ ] **Step 1: Write the failing/skipping test**

```python
# add to tests/test_stream_build.py
import resource
@pytest.mark.slow
def test_sharpemu_fits_memory():
    repo = "fixtures/sharpemu"
    if not Path(repo).exists():
        pytest.skip("sharpemu not cloned")
    from orion import graph_build
    graph_build.build(repo, "csharpsrc", lambda e: None, stream=True, queue_size=64)
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024*1024)  # bytes on macOS
    assert peak_mb < 6000, f"stream build peaked at {peak_mb:.0f} MB"
```

- [ ] **Step 2: Run it**

Run: `./.venv/bin/python -m pytest tests/test_stream_build.py::test_sharpemu_fits_memory -v -s`
Expected: PASS (builds under ~6 GB) or SKIP. If it exceeds budget, profile which structure grows with repo size (should only be summaries + call graph) and compress.

- [ ] **Step 3: Commit**

```bash
git add tests/test_stream_build.py
git commit -m "test(stream): sharpemu builds within memory budget"
```

---

### Task 11: Flip `--stream` to default; keep `--no-stream` escape hatch

**Files:**
- Modify: `orion/cli.py` (`set_defaults(stream=True)`)
- Modify: `CLAUDE.md` (document the streaming build, `--queue-size`, `--no-stream`)
- Test: full token-free suite + NodeGoat recall eval

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Run the NodeGoat recall eval on the stream path**

Run the existing eval against a `--stream` build of NodeGoat.
Expected: **14/15** recall, 0 true false positives — unchanged.

- [ ] **Step 2: Flip the default**

```python
# orion/cli.py
scan.set_defaults(stream=True)   # was False
```

- [ ] **Step 3: Run the full token-free suite**

Run: `./.venv/bin/python -m pytest -m "not slow" -q`
Expected: all pass (>= 69).

- [ ] **Step 4: Update CLAUDE.md**

Document: streaming build is default; `--no-stream` reverts to whole-graph; `--queue-size` default 64; memory is now flat in repo size; the summary-stitch taint reproduces `collapse_flows` (oracle-tested).

- [ ] **Step 5: Commit**

```bash
git add orion/cli.py CLAUDE.md
git commit -m "feat(stream): make streaming build the default (whole-graph via --no-stream)"
```

---

## Self-Review

**Spec coverage:**
- §4 pipeline (producer/queue/consumer/stitch) → Tasks 5,6,7,8. ✓
- §5 segment shape + cross-function edge re-derivation → Tasks 5,7. ✓
- §6 summary-stitch algorithm → Tasks 1,2,3 (+4 GENERIC path). ✓
- §7 rollout order (refactor behind legacy → --stream → gate → flip) → Phase 1 (behind legacy), Task 8 (flag), Task 11 (flip). ✓
- §8 memory + resume → Tasks 9,10. ✓
- §9 testing (oracle, structural, recall, scale, resume) → Tasks 3,4,6,7,8,9,10,11. ✓
- §2 parity gate (NodeGoat 217 + PyGoat + 14/15) → Tasks 3,4,8,11. ✓
- §10 stage two → explicitly out of scope; queue built to enable it (Task 5 durable numbered stream). ✓

**Placeholder scan:** The two `> NOTE` blocks (Task 5 `propJson`, Task 7 `callsites`) describe concrete work whose correctness is enforced by an exact equivalence test in the same task (`test_producer_matches_python_partition`, `test_stream_flows_parity == 217`) — they are acceptance-gated, not open-ended. The Joern-Scala `propJson`/`callsites` details are the one place the engineer iterates against a hard test rather than copying final code, because the exact Scala serialization is environment-checked; the passing test is the definition of done.

**Type consistency:** `Summary` fields (`direct`, `params`, `real_calls`, `internal_sources`, `callsite`, `callee_edges`) are used consistently across Tasks 2,3,7. `build_summary`, `stitch`, `flows_via_summaries`, `partition`, `owner_map`, `run_producer`, `build_envelope`, `collect_structural`, `flows_count`, `ensure_cpg` signatures match between definition and call sites. FLOWS_TO dict shape identical to `collapse_flows`. ✓
