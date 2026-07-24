"""Summary-stitch interprocedural taint: factor collapse_flows into bounded per-function
summaries + a global stitch that reproduces it exactly. See
docs/superpowers/specs/2026-07-23-streaming-graph-build-design.md."""
from __future__ import annotations
from dataclasses import dataclass, field
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
    """Split a raw Joern GraphSON graph into per-function subgraphs plus a call graph.

    Returns (methods, callgraph):
      - methods[mid] = {"vertices": [...], "edges": [...]} holds only vertices owned by `mid`
        (via owner_map AST ancestry) and edges wholly inside `mid` (both endpoints owned by the
        same method). Cross-method edges are dropped from every slice by construction.
      - callgraph[caller_mid] = {callee_mid, ...} built from CALL edges (call node -> callee
        METHOD), keyed by the METHOD that owns the calling CALL node.
    """
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


@dataclass
class Summary:
    method_id: int
    direct: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    real_calls: set = field(default_factory=set)
    internal_sources: set = field(default_factory=set)
    callsite: dict = field(default_factory=dict)
    # closure_out[entry] = cross-method REACHING_DEF target nodes reachable from `entry` within this
    # function through transparent nodes. collapse_flows walks the WHOLE-graph `rd` relation, so it
    # follows closure-capture rd edges (an outer var used inside a nested lambda) transparently.
    # partition drops those cross-method edges from every slice, so the stitch must re-introduce them
    # as an explicit crossing that PRESERVES `crossed` (unlike a call->param hop, which sets it True).
    closure_out: dict = field(default_factory=dict)


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


def _reach_full(entry, check_self, rd, cross_rd, verts, arg_parent, arg_index):
    """Closure-aware variant of `_reach`. Returns (direct, closure):
      - `direct`: the (real_call, idx) sites reached from `entry` within this function (exactly what
        `_reach` returns for the same seed) — collapse_flows' inner walk, minus the stitch hop.
      - `closure`: the cross-method REACHING_DEF target nodes the whole-graph walk would step into.
        collapse_flows follows `rd[n]` for every TRANSPARENT node `n` (a node with no enclosing real
        call), and those successors include cross-method closure-capture edges. We collect them so
        the global stitch can continue the flow in the target function with `crossed` UNCHANGED.

    `check_self` mirrors the fact that a closure-target node arrives mid-walk in collapse_flows and is
    itself tested for an enclosing real call: when True, test `entry` first and, if it is a real-call
    argument, emit that single self target and prune (collapse_flows does not walk past a real-call
    arg). A real-call/param/source seed is never self-tested (it sits in `seen` unchecked), so those
    entries pass check_self=False and match `_reach` exactly."""
    direct: set = set()
    closure: set = set()
    if check_self:
        rc, idx = _enclosing_real_arg(entry, verts, arg_parent, arg_index)
        if rc is not None:
            direct.add((rc, idx))
            return direct, closure
    seen = {entry}
    stack = list(rd.get(entry, []))
    if cross_rd:
        closure.update(cross_rd.get(entry, ()))
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        rc, idx = _enclosing_real_arg(n, verts, arg_parent, arg_index)
        if rc is not None:
            direct.add((rc, idx))
            continue
        stack.extend(rd.get(n, []))
        if cross_rd:
            closure.update(cross_rd.get(n, ()))
    return direct, closure


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


def build_summary(method_id, sub, request_source_names, entrypoint_method_ids,
                  cross_rd=None, closure_targets=()) -> Summary:
    """Per-function summary. `cross_rd` (node -> cross-method REACHING_DEF targets) and
    `closure_targets` (the cross-method rd target nodes owned by THIS method) are the closure seam:
    when given, each entry also records its `closure_out` set and every closure target becomes an
    extra self-checked entry, so the global stitch can rejoin flows that collapse_flows follows
    through nested-lambda captures. Omitting them (the Task 1/2 path) yields the original summary
    byte-for-byte via `_reach`."""
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
        if cross_rd is None:
            s.direct[e] = _reach(e, rd, verts, arg_parent, arg_index)
        else:
            d, c = _reach_full(e, False, rd, cross_rd, verts, arg_parent, arg_index)
            s.direct[e] = d
            if c:
                s.closure_out[e] = c
    # Closure targets land mid-walk in collapse_flows, so they are self-checked entries (an IDENTIFIER
    # captured from an outer scope may itself be an argument of a real call in this function).
    if cross_rd is not None:
        for t in closure_targets:
            if t in verts and t not in s.direct:
                d, c = _reach_full(t, True, rd, cross_rd, verts, arg_parent, arg_index)
                s.direct[t] = d
                if c:
                    s.closure_out[t] = c
    # callsite arg indices per real call (callee METHOD resolved globally in stitch)
    for rc in real_calls:
        s.callsite[rc] = dict(arg_children.get(rc, {}))
    return s


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
    callee = _callee_map(summaries, callgraph)

    def stitch_target(rc, idx):
        m = callee.get(rc)
        return param_slot.get((m, idx)) if m is not None else None

    # Two crossing mechanisms, mirroring collapse_flows' single global rd walk:
    #   1. a real-call arg -> its first-party callee param        (stitch_target; sets crossed=True)
    #   2. a transparent node -> a cross-method closure target     (closure_out; keeps crossed)
    # `seen` is keyed (node, crossed) exactly like collapse_flows' `seen`.
    best: dict = {}
    for mid, s in summaries.items():
        for src in s.real_calls:
            frontier = [(src, mid, False)]
            seen = {(src, False)}
            while frontier:
                entry, emid, crossed = frontier.pop()
                summ = summaries[emid]
                for (rc, idx) in summ.direct.get(entry, ()):
                    if rc != src:                       # collapse_flows: `rc is not None and rc != s`
                        key = (src, rc, idx)
                        best[key] = best.get(key, True) and crossed
                        tgt = stitch_target(rc, idx)
                        if tgt is not None and (tgt, True) not in seen:
                            seen.add((tgt, True))
                            frontier.append((tgt, method_of[tgt], True))
                for t in summ.closure_out.get(entry, ()):
                    if (t, crossed) not in seen:
                        seen.add((t, crossed))
                        frontier.append((t, method_of[t], crossed))
    param_flows: set = set()
    for mid, s in summaries.items():
        for src in s.internal_sources:
            frontier = [(src, mid, False)]
            seen = {(src, False)}
            while frontier:
                entry, emid, crossed = frontier.pop()
                summ = summaries[emid]
                for (rc, idx) in summ.direct.get(entry, ()):
                    param_flows.add((rc, idx))
                    tgt = stitch_target(rc, idx)
                    if tgt is not None and (tgt, True) not in seen:
                        seen.add((tgt, True))
                        frontier.append((tgt, method_of[tgt], True))
                for t in summ.closure_out.get(entry, ()):
                    if (t, crossed) not in seen:
                        seen.add((t, crossed))
                        frontier.append((t, method_of[t], crossed))
    flows = [{"label": "FLOWS_TO", "out": a, "in": b, "arg_index": i,
              "provenance": "inferred" if crossed else "proven"}
             for (a, b, i), crossed in best.items()]
    flows += [{"label": "FLOWS_TO", "out": rc, "in": rc, "arg_index": idx,
               "provenance": "inferred"} for (rc, idx) in param_flows]
    return flows


def _closure_edges(g) -> tuple[dict, dict]:
    """The closure seam collapse_flows gets for free by walking the whole-graph `rd`. Returns
    (cross_rd, targets_by_method):
      - cross_rd[src] = [dst, ...] for every REACHING_DEF edge partition DROPPED (endpoints in
        different functions — nested-lambda closure captures). Combined with each slice's intra rd,
        this is exactly collapse_flows' global `rd`.
      - targets_by_method[mid] = {dst, ...} the cross-method rd targets owned by `mid`, which become
        extra self-checked entries in that method's summary."""
    inner = _inner(g)
    own = owner_map(g)
    cross_rd: dict = defaultdict(list)
    targets_by_method: dict = defaultdict(set)
    for e in inner.get("edges", []):
        if e["label"] != "REACHING_DEF":
            continue
        o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
        mo, mi = own.get(o), own.get(i)
        if mo is not None and mo == mi:
            continue                       # intra-function: already inside the slice's own rd
        if mi is None:
            continue                       # target under no method: cannot rejoin a summary
        cross_rd[o].append(i)
        targets_by_method[mi].add(i)
    return dict(cross_rd), dict(targets_by_method)


def flows_via_summaries(g, *, request_source_names=_REQUEST_PARAM_NAMES,
                        entrypoint_method_ids=None) -> list:
    methods, callgraph = partition(g)
    cross_rd, targets_by_method = _closure_edges(g)
    summaries = {mid: build_summary(mid, sub, request_source_names, entrypoint_method_ids,
                                    cross_rd=cross_rd,
                                    closure_targets=targets_by_method.get(mid, ()))
                 for mid, sub in methods.items()}
    # attach the raw callee edges partition saw, for _callee_map
    summaries = _attach_callees(summaries, g)
    return stitch(summaries, callgraph, request_source_names=request_source_names,
                  entrypoint_method_ids=entrypoint_method_ids)


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
