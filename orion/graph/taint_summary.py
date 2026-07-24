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
