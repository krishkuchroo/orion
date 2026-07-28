"""Joern CPG -> Orion canonical graph (a trimmed, standalone fork of sentryV2's adapter).

Three responsibilities, cleanly separated so the load-bearing part needs no JVM:
  1. export_repo(repo)      — I/O: reuse a prebuilt `cpg.bin` (joern-export only, ~3s) or
                              joern-parse+export a fresh repo, then project.
  2. project_graphson(gs)   — reduce raw Joern GraphSON to a compact {nodes, edges} envelope of
                              only the labels we map, synthesizing FLOWS_TO taint edges, and
                              (bug-fix B3) stamping each CALL's owning file_path.
  3. normalize(envelope..)  — deterministic relabel to the canonical 7-node/5-edge schema-of-record,
                              emitted through schema.Batch.

Forked from ~/Documents/sentryV2/collectors/joern_adapter.py, trimmed to the schema-of-record and
made dependency-free: the param-source / request-source catalogs are inlined below (JS request
objects) instead of importing sentry's dispatch.catalog_data.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from .. import config
from .schema import Batch, synthesize_uid

# Joern node labels this adapter maps (everything else — BLOCK, IDENTIFIER, LITERAL, TYPE, … — is
# not part of the canonical reachability subset and is intentionally dropped).
_MAPPED_NODE_LABELS = {
    "FILE", "METHOD", "CALL", "IMPORT", "METHOD_PARAMETER_IN", "METHOD_RETURN",
}
# Joern edges we map, with the (out_label, in_label) filter that selects the structural edge we
# mean (CONTAINS also connects METHOD to BLOCK/LOCAL/…; we take only METHOD->CALL).
_MAPPED_EDGES = {
    "CONTAINS": ("METHOD", "CALL"),
    "CALL": ("CALL", "METHOD"),
    "SOURCE_FILE": ("METHOD", "FILE"),
}
_NODE_PROPS = {
    "FILE": ["NAME"],
    "METHOD": ["FULL_NAME", "NAME", "IS_EXTERNAL", "FILENAME", "LINE_NUMBER"],
    "CALL": ["METHOD_FULL_NAME", "NAME", "CODE", "LINE_NUMBER", "COLUMN_NUMBER"],
    "IMPORT": ["IMPORTED_AS", "IMPORTED_ENTITY", "CODE", "LINE_NUMBER"],
    "METHOD_PARAMETER_IN": ["NAME", "INDEX", "LINE_NUMBER", "CODE"],
    "METHOD_RETURN": ["LINE_NUMBER", "CODE"],
}
_EMPTY_PATHS = frozenset({"", "<empty>", "N/A", "<unknown>"})

# Inlined taint-source catalogs (were sentry's dispatch.catalog_data.param_sources). Orion targets
# JS/Express where the taint source is a request object field-access chain (req.body.x / req.query.y),
# not a typed annotation — so the annotation sets are empty and the request-object names carry it.
_SOURCE_ANNOTATIONS: frozenset[str] = frozenset()
_REQUEST_PARAM_NAMES: frozenset[str] = frozenset({"req", "request"})


# ─────────────────────────────── GraphSON helpers ───────────────────────────────
def _unwrap(x):
    """Strip TinkerPop GraphSON type tags: {"@type":..,"@value":v} -> v, recursively."""
    if isinstance(x, dict) and "@value" in x:
        return _unwrap(x["@value"])
    if isinstance(x, list):
        return [_unwrap(i) for i in x]
    return x


def _prop(vertex: dict, key: str, default=None):
    """One value for a GraphSON vertex property (unwrap type tags, flatten to scalar)."""
    entry = vertex.get("properties", {}).get(key)
    if entry is None:
        return default
    entries = entry if isinstance(entry, list) else [entry]
    vals: list = []
    for e in entries:
        v = _unwrap(e)
        vals.extend(v) if isinstance(v, list) else vals.append(v)
    if not vals:
        return default
    return vals[0] if len(vals) == 1 else vals


def _deepint(x):
    """Pull a plain int out of a (possibly nested) GraphSON g:Int32 wrapper; else None."""
    while isinstance(x, dict) and "@value" in x:
        x = x["@value"]
    return x if isinstance(x, int) else None


def _is_real_call(label: str, method_full_name) -> bool:
    """A *real* call: a CALL whose METHOD_FULL_NAME is not a Joern <operator>.* synthetic.
    Only real calls are taint sources/sinks; operator calls are transparent pass-through hops."""
    return label == "CALL" and not str(method_full_name or "").startswith("<operator>")


def collapse_flows(inner_graph: dict, *,
                   request_source_names: frozenset[str] = _REQUEST_PARAM_NAMES,
                   entrypoint_method_ids: frozenset | None = None) -> list:
    """Collapse Joern's REACHING_DEF data-dependence graph onto real-call -> real-call FLOWS_TO
    edges, each carrying the argument index the flow enters at and its provenance. Transparent
    nodes (IDENTIFIER, LITERAL, <operator>.* calls) are walked through. An interprocedural stitch
    continues a flow across a resolved first-party callee boundary (crossing one marks the flow
    'inferred'; a wholly intraprocedural flow is 'proven'). Pure over the raw {vertices, edges}.

    Taint SOURCES are profile-driven (Orion is framework-agnostic — see graph/profiles.py):
      - `request_source_names`: root identifier names of the request object (req/request for
        Express). Default preserves the original hardcoded behavior.
      - `entrypoint_method_ids`: when given (the GENERIC/no-framework profile), the parameters of
        these entry-point methods are ALSO taint sources — a structural, language-agnostic model
        that needs no request-object naming convention."""
    verts = {_unwrap(v["id"]): v for v in inner_graph.get("vertices", [])}
    rd: dict = {}
    arg_parent: dict = {}
    arg_index: dict = {}
    arg_children: dict = {}
    callee: dict = {}
    mparams: dict = {}
    param_annotations: dict = {}
    for e in inner_graph.get("edges", []):
        lbl = e["label"]
        if lbl == "REACHING_DEF":
            rd.setdefault(_unwrap(e["outV"]), []).append(_unwrap(e["inV"]))
        elif lbl == "ARGUMENT":
            ch = _unwrap(e["inV"])
            parent = _unwrap(e["outV"])
            arg_parent[ch] = parent
            if ch in verts:
                idx = _deepint(_prop(verts[ch], "ARGUMENT_INDEX"))
                arg_index[ch] = idx
                arg_children.setdefault(parent, {})[idx] = ch
        elif lbl == "CALL":
            o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
            if verts.get(o, {}).get("label") == "CALL" and verts.get(i, {}).get("label") == "METHOD":
                callee[o] = i
        elif lbl == "AST":
            o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
            olbl = verts.get(o, {}).get("label")
            ilbl = verts.get(i, {}).get("label")
            if olbl == "METHOD" and ilbl == "METHOD_PARAMETER_IN":
                mparams.setdefault(o, {})[_deepint(_prop(verts[i], "INDEX"))] = i
            elif olbl == "METHOD_PARAMETER_IN" and ilbl == "ANNOTATION":
                names = param_annotations.setdefault(o, set())
                for key in (_prop(verts[i], "FULL_NAME"), _prop(verts[i], "NAME")):
                    if isinstance(key, str) and key:
                        names.add(key)

    def enclosing_real_arg(n):
        cur = n
        while cur in arg_parent:
            pa = arg_parent[cur]
            pv = verts.get(pa)
            if pv is not None and _is_real_call(pv["label"], _prop(pv, "METHOD_FULL_NAME")):
                return pa, arg_index.get(cur)
            cur = pa
        return None, None

    def stitch_target(call_node, idx):
        m = callee.get(call_node)
        return mparams.get(m, {}).get(idx) if m is not None else None

    real_calls = [vid for vid, v in verts.items()
                  if _is_real_call(v["label"], _prop(v, "METHOD_FULL_NAME"))]
    best: dict = {}
    for s in real_calls:
        seen = {(s, False)}
        stack = [(m, False) for m in rd.get(s, [])]
        while stack:
            n, crossed = stack.pop()
            if (n, crossed) in seen:
                continue
            seen.add((n, crossed))
            rc, idx = enclosing_real_arg(n)
            if rc is not None and rc != s:
                key = (s, rc, idx)
                best[key] = best.get(key, True) and crossed
                tgt = stitch_target(rc, idx)
                if tgt is not None:
                    stack.append((tgt, True))
                continue
            for m in rd.get(n, []):
                if (m, crossed) not in seen:
                    stack.append((m, crossed))

    def _base_root_name(fa):
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

    source_params = [p for p, names in param_annotations.items() if names & _SOURCE_ANNOTATIONS]
    # GENERIC/no-framework profile: every parameter of a detected entry-point method is an
    # attacker-controlled source (structural, needs no request-object naming convention).
    if entrypoint_method_ids:
        for m in entrypoint_method_ids:
            source_params.extend(mparams.get(m, {}).values())
    request_source_fas = [
        vid for vid, v in verts.items()
        if v["label"] == "CALL" and _prop(v, "METHOD_FULL_NAME") == "<operator>.fieldAccess"
        and _base_root_name(vid) in request_source_names
    ]

    param_flows: set = set()
    for p in source_params + request_source_fas:
        pseen: set = set()
        stack = [(m, False) for m in rd.get(p, [])]
        while stack:
            n, crossed = stack.pop()
            if (n, crossed) in pseen:
                continue
            pseen.add((n, crossed))
            rc, idx = enclosing_real_arg(n)
            if rc is not None:
                param_flows.add((rc, idx))
                tgt = stitch_target(rc, idx)
                if tgt is not None:
                    stack.append((tgt, True))
                continue
            for m in rd.get(n, []):
                if (m, crossed) not in pseen:
                    stack.append((m, crossed))

    flows = [{"label": "FLOWS_TO", "out": a, "in": b, "arg_index": i,
              "provenance": "inferred" if crossed else "proven"}
             for (a, b, i), crossed in best.items()]
    flows += [{"label": "FLOWS_TO", "out": rc, "in": rc, "arg_index": idx,
               "provenance": "inferred"}
              for (rc, idx) in param_flows]
    return flows


def _call_file_map(g: dict) -> dict:
    """Bug-fix B3: map every CALL vertex to its owning file by climbing the AST parent chain to
    the nearest enclosing METHOD and reading that method's FILENAME. Joern does NOT put FILENAME
    on CALL nodes, and the canonical METHOD->CALL CONTAINS edge is missing for calls nested in
    arrow-functions assigned to object properties — but the AST tree always reaches SOME enclosing
    method (a closure method for an arrow function), which carries a FILENAME. So file attribution
    is total and never depends on CONTAINS_CALL."""
    verts = {_unwrap(v["id"]): v for v in g.get("vertices", [])}
    ast_parent: dict = {}
    for e in g.get("edges", []):
        if e["label"] == "AST":
            ast_parent[_unwrap(e["inV"])] = _unwrap(e["outV"])
    meth_file = {vid: _clean(_prop(v, "FILENAME"))
                 for vid, v in verts.items() if v["label"] == "METHOD"}
    file_map: dict = {}
    for vid, v in verts.items():
        if v["label"] != "CALL":
            continue
        cur, guard = vid, 0
        while cur is not None and guard < 256:
            guard += 1
            node = verts.get(cur)
            if node is None:
                break
            if node["label"] == "METHOD":
                file_map[vid] = meth_file.get(cur)
                break
            cur = ast_parent.get(cur)
    return file_map


def _entry_method_ids_from(method_vertices: dict, called: set, has_param: set,
                           callback_fulls: set) -> set:
    """The pure structural entry-point test over accumulated inputs (see `_entry_method_ids`).

    Framework-FREE entry-point detection: a first-party METHOD that nothing else in the code calls
    (a call-graph root) and that takes parameters is an entry point — a request handler, an exported
    API function, main(). Language-agnostic: it reads only the CALL and AST structure Joern emits for
    every language, never a framework's naming convention. Over-includes (some roots are just uncalled
    helpers), which is fine: EntryPoints are anchors/source hints the verifier still checks, never
    findings on their own. Returns METHOD vertex ids.

    Used by BOTH the whole-graph `_entry_method_ids` wrapper below and the streaming consumer
    (`stream_build.build_envelope`), so there is ONE entry logic, never a re-implementation."""
    entries: set = set()
    for vid, v in method_vertices.items():
        if bool(_prop(v, "IS_EXTERNAL")):
            continue
        if _clean(_prop(v, "FILENAME")) is None or vid not in has_param:
            continue
        name = _prop(v, "NAME") or ""
        if name.startswith("<") or name == ":program":   # synthetic (<global>, <module>, program)
            continue
        is_callback = _prop(v, "FULL_NAME") in callback_fulls
        if vid in called and not is_callback:
            continue        # called by first-party code and not registered as a handler -> not an entry
        entries.add(vid)
    return entries


def _entry_method_ids(g: dict) -> set:
    """Whole-graph wrapper: build the four accumulated inputs from a raw GraphSON graph, then defer to
    the pure `_entry_method_ids_from` test. Behavior-preserving split (delta C.3): the stream builds
    the identical four inputs from its per-segment accumulators."""
    verts = {_unwrap(v["id"]): v for v in g.get("vertices", [])}
    method_vertices = {vid: v for vid, v in verts.items() if v["label"] == "METHOD"}
    # Methods passed as CALLBACKS (referenced by a METHOD_REF): the universal "register a handler"
    # pattern — Express/Koa/Fastify route callbacks, event handlers, etc. Framework-free, and it
    # catches the arrow-function handlers the call-graph-root test alone misses.
    callback_fulls: set = {mfn for v in verts.values() if v["label"] == "METHOD_REF"
                           and isinstance((mfn := _prop(v, "METHOD_FULL_NAME")), str) and mfn}
    called: set = set()
    has_param: set = set()
    for e in g.get("edges", []):
        o, i = _unwrap(e["outV"]), _unwrap(e["inV"])
        lbl = e["label"]
        if lbl == "CALL" and verts.get(i, {}).get("label") == "METHOD":
            called.add(i)                      # something first-party resolves a call to it
        elif (lbl == "AST" and verts.get(o, {}).get("label") == "METHOD"
              and verts.get(i, {}).get("label") == "METHOD_PARAMETER_IN"):
            has_param.add(o)
    return _entry_method_ids_from(method_vertices, called, has_param, callback_fulls)


def project_graphson(graphson: dict, profile=None) -> dict:
    """Reduce a raw Joern GraphSON graph to the compact adapter-input envelope
    {"nodes": [{label,id,props{}}], "edges": [{label,out,in,out_label,in_label}]}, keeping only
    the labels this adapter normalizes, plus synthesized FLOWS_TO taint edges. Each CALL node also
    carries a stamped `file_path` (bug-fix B3).

    `profile` (graph/profiles.Profile) drives framework-specific taint sourcing; when None the
    original Express-style `req`/`request` sourcing is used (behavior-preserving default)."""
    g = graphson["@value"] if "@type" in graphson else graphson
    call_files = _call_file_map(g)
    src_names = _REQUEST_PARAM_NAMES if profile is None else profile.request_source_names
    # Structural entry points (framework-free), emitted for EVERY repo. When the profile is the
    # GENERIC/no-framework fallback, their parameters also become taint sources.
    entry_ids = _entry_method_ids(g)
    entry_taint = frozenset(entry_ids) if (profile is not None and profile.entrypoint_params_are_sources) else None
    nodes = []
    for v in g.get("vertices", []):
        label = v["label"]
        if label not in _MAPPED_NODE_LABELS:
            continue
        props = {k: _prop(v, k) for k in _NODE_PROPS[label]}
        if label == "CALL":
            props["file_path"] = call_files.get(_unwrap(v["id"]))
        nodes.append({"label": label, "id": _unwrap(v["id"]), "props": props})
    edges = []
    for e in g.get("edges", []):
        label = e["label"]
        want = _MAPPED_EDGES.get(label)
        if want is None or (e.get("outVLabel"), e.get("inVLabel")) != want:
            continue
        edges.append({
            "label": label,
            "out": _unwrap(e["outV"]), "in": _unwrap(e["inV"]),
            "out_label": e.get("outVLabel"), "in_label": e.get("inVLabel"),
        })
    edges.extend(collapse_flows(g, request_source_names=src_names, entrypoint_method_ids=entry_taint))
    verts = {_unwrap(v["id"]): v for v in g.get("vertices", [])}
    entry_methods = sorted({
        fn for e in entry_ids
        if (fn := _prop(verts[e], "FULL_NAME")) and verts.get(e) is not None
    })
    return {"nodes": nodes, "edges": edges, "entry_methods": entry_methods}


# ─────────────────────────────── normalize ───────────────────────────────
def _clean(value):
    """Map Joern placeholder strings (<empty>, N/A, …) and non-scalars to None."""
    if value is None or not isinstance(value, str):
        return None
    return None if value in _EMPTY_PATHS else value


def normalize(export: dict, scan_id: str, entry_funcs: list[str] | None = None,
              *, language: str = "javascript",
              dependencies: list[tuple[str, str]] | None = None) -> Batch:
    """Deterministic relabel of a compact Joern envelope to the canonical schema-of-record,
    accumulated in a `schema.Batch` the persist layer writes. `entry_funcs` are declared entry
    function short-names (bound to their CpgMethod as EntryPoints); empty by default.
    `dependencies` are (name, version) pairs parsed from the repo manifest -> Dependency nodes."""
    entry_funcs = entry_funcs or []
    dependencies = dependencies or []
    nodes = export["nodes"]
    edges = export["edges"]
    b = Batch(scan_id)

    id_to_method_fullname: dict = {}
    id_to_call_uid: dict = {}
    id_to_file_uid: dict = {}
    method_by_name: dict[str, list[str]] = {}

    # ---- FILE -> CpgFile ----
    for n in (n for n in nodes if n["label"] == "FILE"):
        path = _clean(n["props"].get("NAME"))
        if path is None:
            continue
        uid = synthesize_uid(scan_id, "FILE", path, 0, 0, path)
        b.emit_node("CpgFile", {"uid": uid, "file_path": path})
        id_to_file_uid[n["id"]] = uid

    # ---- METHOD -> CpgMethod ----
    for n in (n for n in nodes if n["label"] == "METHOD"):
        full = n["props"].get("FULL_NAME")
        if full is None:
            continue
        name = n["props"].get("NAME") or full.rsplit(".", 1)[-1]
        props = {"full_name": full, "name": name, "is_external": bool(n["props"].get("IS_EXTERNAL"))}
        fp = _clean(n["props"].get("FILENAME"))
        if fp is not None:
            props["file_path"] = fp
        line = n["props"].get("LINE_NUMBER")
        if isinstance(line, int):
            props["line"] = line
        b.emit_node("CpgMethod", props)
        id_to_method_fullname[n["id"]] = full
        method_by_name.setdefault(name, []).append(full)

    # ---- IMPORT -> CpgModule ----
    for n in (n for n in nodes if n["label"] == "IMPORT"):
        import_name = _clean(n["props"].get("IMPORTED_AS")) or _clean(n["props"].get("IMPORTED_ENTITY"))
        if import_name is None:
            continue
        b.emit_node("CpgModule", {"import_name": import_name, "language": language})

    # ---- CALL -> CpgCall ----
    for n in (n for n in nodes if n["label"] == "CALL"):
        props_in = n["props"]
        code = props_in.get("CODE") or props_in.get("NAME") or ""
        name = props_in.get("NAME") or ""
        line = props_in.get("LINE_NUMBER") if isinstance(props_in.get("LINE_NUMBER"), int) else 0
        col = props_in.get("COLUMN_NUMBER") if isinstance(props_in.get("COLUMN_NUMBER"), int) else 0
        fp = _clean(props_in.get("file_path")) or "<unknown>"
        uid = synthesize_uid(scan_id, "CALL", fp, line, col, code)
        b.emit_node("CpgCall", {
            "uid": uid, "name": name, "code": code,
            "method_full_name": props_in.get("METHOD_FULL_NAME") or "<unknownFullName>",
            "file_path": fp, "line": line, "column": col})
        id_to_call_uid[n["id"]] = uid

    # ---- METHOD_PARAMETER_IN -> CpgParameter ----
    for n in (n for n in nodes if n["label"] == "METHOD_PARAMETER_IN"):
        name = n["props"].get("NAME")
        if name is None:
            continue
        line = n["props"].get("LINE_NUMBER") if isinstance(n["props"].get("LINE_NUMBER"), int) else 0
        uid = synthesize_uid(scan_id, "METHOD_PARAMETER_IN", "<param>", line, 0, name)
        p = {"uid": uid, "name": name}
        idx = n["props"].get("INDEX")
        if isinstance(idx, int):
            p["index"] = idx
        b.emit_node("CpgParameter", p)

    # ---- METHOD_RETURN -> CpgReturn ----
    for n in (n for n in nodes if n["label"] == "METHOD_RETURN"):
        line = n["props"].get("LINE_NUMBER") if isinstance(n["props"].get("LINE_NUMBER"), int) else 0
        uid = synthesize_uid(scan_id, "METHOD_RETURN", "<return>", line, 0, str(n["id"]))
        b.emit_node("CpgReturn", {"uid": uid})

    # ---- edges ----
    for e in edges:
        if e["label"] == "CONTAINS":
            m = id_to_method_fullname.get(e["out"])
            c = id_to_call_uid.get(e["in"])
            if m is not None and c is not None:
                b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": m}, "CpgCall", {"uid": c})
        elif e["label"] == "CALL":
            c = id_to_call_uid.get(e["out"])
            m = id_to_method_fullname.get(e["in"])
            if c is not None and m is not None:
                b.emit_edge("RESOLVES_TO", "CpgCall", {"uid": c}, "CpgMethod", {"full_name": m})
        elif e["label"] == "SOURCE_FILE":
            m = id_to_method_fullname.get(e["out"])
            f = id_to_file_uid.get(e["in"])
            if m is not None and f is not None:
                b.emit_edge("DEFINED_IN", "CpgMethod", {"full_name": m}, "CpgFile", {"uid": f})
        elif e["label"] == "FLOWS_TO":
            src = id_to_call_uid.get(e["out"])
            dst = id_to_call_uid.get(e["in"])
            if src is not None and dst is not None:
                props = {}
                if isinstance(e.get("arg_index"), int):
                    props["arg_index"] = e["arg_index"]
                b.emit_edge("FLOWS_TO", "CpgCall", {"uid": src}, "CpgCall", {"uid": dst}, props)

    # ---- EntryPoints: structural (framework-free, from the envelope) + declared (entry_funcs) ----
    emitted_fulls = set(id_to_method_fullname.values())
    seen_entry: set[str] = set()

    for full in export.get("entry_methods", []):
        if full not in emitted_fulls or full in seen_entry:
            continue
        seen_entry.add(full)
        uid = synthesize_uid(scan_id, "ENTRYPOINT", full, 0, 0, "structural")
        b.emit_node("EntryPoint", {
            "uid": uid, "kind": "handler", "method_full_name": full, "exposure": "reachable"})
        b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": uid}, "CpgMethod", {"full_name": full})

    for ep in entry_funcs:
        candidates = method_by_name.get(ep)
        if not candidates or candidates[0] in seen_entry:
            continue
        full = candidates[0]
        seen_entry.add(full)
        uid = synthesize_uid(scan_id, "ENTRYPOINT", full, 0, 0, ep)
        b.emit_node("EntryPoint", {
            "uid": uid, "kind": "http", "method_full_name": full, "exposure": "exposed"})
        b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": uid}, "CpgMethod", {"full_name": full})

    # ---- Dependency (from the repo manifest — closes the A9/known-vuln-deps data-gap) ----
    for name, version in dependencies:
        b.emit_node("Dependency", {"name": name, "version": version})

    return b


# ─────────────────────────────── drive Joern (I/O) ───────────────────────────────
def _joern_home() -> Path:
    return Path(config.JOERN_HOME)


def _joern_bin(name: str) -> Path:
    """Locate a joern executable: prefer <home>/<name>, fall back to <home>/bin/<name>."""
    jc = _joern_home()
    root = jc / name
    return root if root.exists() else jc / "bin" / name


def _heap_gb() -> int | None:
    """The `-Xmx` size in whole GB, or None to let the JVM pick its default (RAM unreadable).

    An explicit `config.JOERN_HEAP_GB` (positive number) wins outright -- skip RAM detection so a
    shared/constrained box can cap heap and a giant repo can push it past the fraction. Otherwise
    size to `config.JOERN_HEAP_FRACTION` of physical RAM (default 0.75, the prior hard-coded value).
    Pure and testable without a subprocess."""
    override = config.JOERN_HEAP_GB
    if override:
        try:
            gb = int(float(override))
            if gb > 0:
                return gb
        except ValueError:
            pass   # malformed override -> fall through to RAM-derived sizing (never a hard failure)
    try:
        total_gb = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 1024 ** 3
    except (ValueError, OSError, AttributeError):
        return None
    return max(2, int(total_gb * config.JOERN_HEAP_FRACTION))


def _jvm_flags() -> list[str]:
    """JVM args for the joern subprocesses: G1GC plus a `-J-Xmx` sized to THIS machine instead of
    the JVM's ~25%-of-RAM default. joern-export pretty-prints the whole CPG into a single in-memory
    GraphSON string; on a large repo (paid for by a 427-file C# emulator on a 16GB Mac) the default
    heap OOMs mid-serialize. Size via `_heap_gb` (fraction-of-RAM, or an exact GB override), leaving
    headroom for the OS, the Neo4j container, and the post-export Python parse. If RAM can't be read
    and no override is set, keep only G1GC and let the JVM pick its default (never a hard failure)."""
    flags = ["-J-XX:+UseG1GC"]
    gb = _heap_gb()
    if gb is not None:
        flags.append(f"-J-Xmx{gb}g")
    return flags


def _ensure_greadlink(env: dict) -> dict:
    """Joern's frontend wrappers call `greadlink -f` (GNU coreutils). On a stock Mac that is
    absent; shim greadlink -> readlink so drive_joern works without `brew install coreutils`."""
    if shutil.which("greadlink", path=env.get("PATH")):
        return env
    shim_dir = Path(tempfile.gettempdir()) / "orion_joern_shim"
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / "greadlink"
    if not shim.exists():
        shim.write_text('#!/bin/sh\nexec readlink "$@"\n')
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    env = dict(env)
    env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"
    return env


def _run_export(cpg_bin: Path, export_dir: Path, env: dict, profile=None) -> dict:
    """joern-export a cpg.bin to GraphSON and project it. Raises on failure (never a silent
    empty graph)."""
    if export_dir.exists():
        shutil.rmtree(export_dir)
    r = subprocess.run(
        [str(_joern_bin("joern-export")), *_jvm_flags(), "--repr=all", "--format=graphson",
         "--out", str(export_dir), str(cpg_bin)],
        capture_output=True, text=True, env=env)
    export_json = export_dir / "export.json"
    if r.returncode != 0 or not export_json.exists():
        raise RuntimeError(f"joern-export failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
    return project_graphson(json.loads(export_json.read_text()), profile)


# Python project markers, in strong-signal order. Separate from the single-filename markers below
# because Python's is a set/glob (requirements*.txt) rather than one fixed name.
_PY_MARKERS: tuple[str, ...] = ("setup.py", "pyproject.toml", "Pipfile")


def _python_marker(repo: Path) -> str | None:
    """The Python project marker present in `repo` -- a strong-signal file if any, else the first
    requirements*.txt -- or None when the repo has no Python marker at all."""
    for name in _PY_MARKERS:
        if (repo / name).exists():
            return name
    reqs = sorted(repo.glob("requirements*.txt"))
    return reqs[0].name if reqs else None


def detect_language_markers(repo_path: str | Path) -> list[tuple[str, str]]:
    """Every language marker present in `repo`, as (marker_filename, joern_frontend) pairs, in
    PRIORITY order -- the first pair is the one `_guess_language` picks. Empty when the repo carries
    none. More than one pair means the repo is polyglot; graph_build surfaces that as a 'warn'
    progress event instead of silently guessing.

    package.json sorts LAST on purpose: it is the marker most likely to ride along as build/lint
    tooling beside a "real" backend in another language, so on a collision the non-JS marker is the
    better primary guess. `orion scan --language` overrides whatever this picks."""
    repo = Path(repo_path)
    markers: list[tuple[str, str]] = []
    if (repo / "go.mod").exists():
        markers.append(("go.mod", "golang"))
    if (repo / "pom.xml").exists():
        markers.append(("pom.xml", "javasrc"))
    py = _python_marker(repo)
    if py is not None:
        markers.append((py, "pythonsrc"))
    if (repo / "package.json").exists():
        markers.append(("package.json", "jssrc"))
    return markers


def _guess_language(repo: Path) -> str:
    """The joern frontend for `repo`: the highest-priority language marker present (see
    detect_language_markers), or python when the repo carries none (the historical default). A
    single-marker repo is unchanged from the old package.json-or-python check -- NodeGoat still
    resolves jssrc, PyGoat still resolves pythonsrc."""
    markers = detect_language_markers(repo)
    return markers[0][1] if markers else "pythonsrc"


# Joern frontend id -> the schema-of-record display language stamped on CpgModule.language.
_DISPLAY_LANG = {
    "jssrc": "javascript", "javascriptsrc": "javascript",
    "pythonsrc": "python", "golang": "go", "javasrc": "java",
    "csharpsrc": "csharp", "c": "c",
}


def resolve_language(repo_path: str | Path, language: str | None = None) -> tuple[str, str]:
    """Return (joern_frontend, display_language) for a repo. `language` may be a Joern frontend id
    (e.g. 'jssrc'); when omitted it is guessed from the repo. The display language is what the
    schema-of-record stamps on CpgModule.language (e.g. 'javascript'), which is a different value
    space from the frontend id — hence the explicit mapping rather than a straight pass-through."""
    frontend = language or _guess_language(Path(repo_path))
    return frontend, _DISPLAY_LANG.get(frontend, frontend)


def ensure_cpg(repo_path: str | Path, language: str | None = None) -> Path:
    """Parse `repo` to a cpg.bin and return its path WITHOUT exporting -- the streaming producer reads
    cpg.bin directly, so the whole-graph joern-export (the 85x GraphSON blob) is skipped entirely.
    Reuses a prebuilt `<repo>/cpg.bin` when present (the eval fixtures ship one); otherwise runs
    joern-parse into a temp dir. This is the parse half of `export_repo`, with `_run_export` removed."""
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
    r = subprocess.run(
        [str(parse), *_jvm_flags(), str(repo),
         "--language", language or _guess_language(repo), "--output", str(out_cpg)],
        capture_output=True, text=True, env=env)
    if r.returncode != 0 or not out_cpg.exists():
        raise RuntimeError(f"joern-parse failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
    return out_cpg


def export_repo(repo_path: str | Path, language: str | None = None, profile=None) -> dict:
    """Produce the compact Joern envelope for `repo`. Reuses a prebuilt `cpg.bin` when present
    (joern-export only, ~3s — honest re-export, never a stale cached json); otherwise runs
    joern-parse then joern-export on the source. JVM-dependent; the pure normalizer above is not.

    `profile` (graph/profiles.Profile) selects the framework taint model; None = Express default."""
    repo = Path(repo_path).resolve()
    env = _ensure_greadlink(dict(os.environ))
    env.setdefault("JAVA_HOME", os.environ.get("JAVA_HOME", ""))
    tmp = Path(tempfile.mkdtemp(prefix="orion_joern_"))
    try:
        cpg_bin = repo / "cpg.bin"
        if cpg_bin.exists():
            return _run_export(cpg_bin, tmp / "export", env, profile)

        parse = _joern_bin("joern-parse")
        if not parse.exists():
            raise RuntimeError(f"joern-parse not found under {config.JOERN_HOME} (set JOERN_HOME)")
        out_cpg = tmp / "cpg.bin"
        r = subprocess.run(
            [str(parse), *_jvm_flags(), str(repo),
             "--language", language or _guess_language(repo), "--output", str(out_cpg)],
            capture_output=True, text=True, env=env)
        if r.returncode != 0 or not out_cpg.exists():
            raise RuntimeError(f"joern-parse failed (rc={r.returncode}):\n{r.stdout}\n{r.stderr}")
        return _run_export(out_cpg, tmp / "export", env, profile)
    finally:
        # The 54MB GraphSON export is fully consumed into memory by _run_export; never leave the
        # temp workdir behind (a per-build leak fills the disk fast).
        shutil.rmtree(tmp, ignore_errors=True)
