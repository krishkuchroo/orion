"""Source->sink pathfinding: precompute concrete candidate flows so discovery JUDGES a shortlist
instead of hand-writing variable-length FLOWS_TO Cypher and exploring blind.

Build-time, pure Python (no Neo4j, no APOC/GDS) over the in-memory `schema.Batch`. A bounded
multi-source BFS over the FLOWS_TO graph from attacker-controlled SOURCES to a profile-aware SINK
set enumerates the shortest tainted path to each reachable dangerous call, ranks them
(severity -> centrality -> shortness), and emits one `:CandidateFlow` node per flow:

  (:CandidateFlow {scan_id, uid, source_uid, sink_uid, sink_category, path_uids, rank})

`path_uids` is a JSON string of the CpgCall uids from source to sink (a scalar, so it persists via
`SET n += row.props` with no array-property concerns; `#5` parses it back for the verifier subgraph).
Nothing here touches FLOWS_TO construction -- it only READS the taint edges and adds new nodes, so
the taint-parity tripwires are unaffected. Free-form FLOWS_TO Cypher stays available to the agent as
a fallback for flows this precompute misses (soft signal, never a hard filter).
"""
from __future__ import annotations

import hashlib
import json
from collections import deque

from . import schema

# Sink severity by category name (profile.sink_hints keys). Higher = more dangerous; used both to
# pick the category when a call matches several, and to rank flows. Unknown categories default to 3.
_SINK_SEVERITY = {
    "code_exec": 5, "deserialize": 5,
    "sql": 4, "nosql": 4, "ssrf": 4, "template": 4,
    "path": 3,
    "redirect": 2, "render": 2,
    "log": 1,
}
_DEFAULT_SEVERITY = 3

# Bounds so a large graph can't blow up the build: cap the taint-path length we chase and the number
# of CandidateFlow nodes we persist (kept ranked-best-first).
_MAX_DEPTH = 12
_MAX_FLOWS = 300


def _severity(category: str) -> int:
    return _SINK_SEVERITY.get(category, _DEFAULT_SEVERITY)


def _classify_sink(props: dict, profile) -> str | None:
    """The highest-severity sink category whose hint name appears in this call's name or code, else
    None. Matching is substring + case-insensitive on `name`/`code` -- deliberately generous (this is
    a candidate list a verifier re-checks), but ranked so `eval` outranks `log`."""
    if profile is None:
        return None
    name = str(props.get("name") or "").lower()
    code = str(props.get("code") or "").lower()
    best: str | None = None
    best_sev = -1
    for category, hints in profile.sink_hints.items():
        for hint in hints:
            h = hint.lower()
            if h and (h in name or h in code):
                sev = _severity(category)
                if sev > best_sev:
                    best, best_sev = category, sev
                break
    return best


def _index_and_edges(batch: schema.Batch):
    """call_props (uid -> unioned CpgCall props), FLOWS_TO adjacency (src_uid -> [dst_uid]),
    self-loop source uids (FLOWS_TO src == dst), entry-method full_names, and the CONTAINS_CALL map
    (method full_name -> [call uid])."""
    call_props: dict[str, dict] = {}
    for label, props in batch.nodes:
        if label == "CpgCall":
            uid = props.get("uid")
            if uid is not None:
                call_props[uid] = {**call_props.get(uid, {}), **props}

    flows: dict[str, list[str]] = {}
    self_loops: set[str] = set()
    entry_methods: set[str] = set()
    contains: dict[str, list[str]] = {}
    for rtype, _fl, from_key, _tl, to_key, _props in batch.edges:
        if rtype == "FLOWS_TO":
            src, dst = from_key.get("uid"), to_key.get("uid")
            if src is None or dst is None:
                continue
            if src == dst:
                self_loops.add(src)
            else:
                flows.setdefault(src, []).append(dst)
        elif rtype == "ENTERS_AT":
            m = to_key.get("full_name")
            if m is not None:
                entry_methods.add(m)
        elif rtype == "CONTAINS_CALL":
            m, c = from_key.get("full_name"), to_key.get("uid")
            if m is not None and c is not None:
                contains.setdefault(m, []).append(c)
    return call_props, flows, self_loops, entry_methods, contains


def _sources(self_loops: set[str], entry_methods: set[str], contains: dict[str, list[str]]) -> set[str]:
    """Attacker-controlled source calls: FLOWS_TO self-loops (a call whose own argument is already
    tainted) plus every call contained in an EntryPoint method (its params are untrusted input)."""
    srcs = set(self_loops)
    for m in entry_methods:
        srcs.update(contains.get(m, ()))
    return srcs


def _candidate_uid(scan_id: str, source_uid: str, sink_uid: str) -> str:
    return hashlib.sha1(f"{scan_id}|CandidateFlow|{source_uid}|{sink_uid}".encode("utf-8")).hexdigest()


def pathfind(batch: schema.Batch, profile) -> dict:
    """Emit ranked `:CandidateFlow` nodes for tainted source->sink paths. Pure over the batch
    (appends nodes; reads edges + call props stamped by reachability/centrality). Idempotent given the
    same batch content: deterministic uids + a stable sort.

    Returns a summary {sources, sinks, flows}."""
    call_props, flows, self_loops, entry_methods, contains = _index_and_edges(batch)
    sources = _sources(self_loops, entry_methods, contains)

    # Multi-source BFS over FLOWS_TO: each node learns its nearest source + a parent pointer, so the
    # shortest tainted path to any sink is reconstructable. One O(V+E) pass, depth-bounded.
    parent: dict[str, str | None] = {}
    origin: dict[str, str] = {}
    dist: dict[str, int] = {}
    queue: deque[str] = deque()
    for s in sources:
        if s not in dist:
            dist[s], parent[s], origin[s] = 0, None, s
            queue.append(s)
    while queue:
        u = queue.popleft()
        if dist[u] >= _MAX_DEPTH:
            continue
        for v in flows.get(u, ()):  # noqa: SIM118 -- .get default is the point
            if v not in dist:
                dist[v], parent[v], origin[v] = dist[u] + 1, u, origin[u]
                queue.append(v)

    def _path(uid: str) -> list[str]:
        out = []
        cur: str | None = uid
        while cur is not None:
            out.append(cur)
            cur = parent.get(cur)
        out.reverse()
        return out

    # Every reached call that classifies as a sink is a candidate flow.
    raw: list[tuple[int, float, int, str, str, str, list[str]]] = []
    for uid in dist:
        category = _classify_sink(call_props.get(uid, {}), profile)
        if category is None:
            continue
        centrality = float(call_props.get(uid, {}).get("centrality") or 0.0)
        path = _path(uid)
        raw.append((_severity(category), centrality, len(path), category, origin[uid], uid, path))

    # Rank: severity desc, centrality desc, shorter path first, then uid for a stable tie-break.
    raw.sort(key=lambda r: (-r[0], -r[1], r[2], r[5]))

    n_sinks = len(raw)
    for rank, (_sev, _cent, _plen, category, source_uid, sink_uid, path) in enumerate(raw[:_MAX_FLOWS]):
        batch.emit_node("CandidateFlow", {
            "uid": _candidate_uid(batch.scan_id, source_uid, sink_uid),
            "source_uid": source_uid,
            "sink_uid": sink_uid,
            "sink_category": category,
            "path_uids": json.dumps(path),
            "rank": rank,
        })

    return {"sources": len(sources), "sinks": n_sinks, "flows": min(n_sinks, _MAX_FLOWS)}
