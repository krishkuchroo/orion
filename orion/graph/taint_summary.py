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
