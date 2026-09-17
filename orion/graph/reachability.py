"""Entry-point reachability: tag every method/call with whether an attacker-reachable EntryPoint
can reach it, and at what hop distance.

This is a build-time, pure-Python precompute (no Neo4j, no APOC/GDS): a multi-source BFS over the
in-memory `schema.Batch` from the EntryPoint methods, walking the call/data graph
(CONTAINS_CALL / RESOLVES_TO / FLOWS_TO). It stamps two properties onto every CpgMethod and CpgCall
node IN PLACE:

  - `reachable_from_entry` (bool): can some :EntryPoint reach this node.
  - `hop_distance` (int): fewest hops from the nearest entry method (0 = an entry method itself);
    `-1` for unreached nodes (persisted explicitly so a query can filter on it).

Because `persist._node_create` does `SET n += row.props` over the very dicts held in `batch.nodes`,
mutating those dicts here is the whole persist path -- no schema-key or persist change is needed.

SOFT SIGNAL, NOT A HARD FILTER. The graph lies by omission: calls nested in arrow-functions assigned
to object properties get no CONTAINS_CALL edge (see CLAUDE.md / joern_adapter), so a genuinely
reachable method can look unreachable here. Callers therefore treat `reachable_from_entry=false` as a
priority/skepticism hint, never as grounds to drop a lead. Nothing here touches FLOWS_TO construction,
so the taint edge set (and its 217/1075 parity tripwires) is unaffected -- we only add node props.
"""
from __future__ import annotations

from collections import deque

from . import schema

# Node identity is namespaced by kind so a CpgMethod full_name and a CpgCall uid can never collide in
# the traversal: ("M", full_name) for methods, ("C", uid) for calls.
_METHOD = "M"
_CALL = "C"

# The build-graph edges the reachability walk follows, and how to read each endpoint's identity key
# from the edge's (from_key, to_key) dicts. Direction is attacker-flow: an entry method reaches the
# calls it contains, a call reaches the method it resolves to, and a call reaches the calls its taint
# flows into.
_TRAVERSAL = {
    "CONTAINS_CALL": ((_METHOD, "full_name"), (_CALL, "uid")),   # method -> call
    "RESOLVES_TO":   ((_CALL, "uid"), (_METHOD, "full_name")),   # call   -> method
    "FLOWS_TO":      ((_CALL, "uid"), (_CALL, "uid")),           # call   -> call
}


def _node_props_index(batch: schema.Batch) -> dict[tuple[str, str], list[dict]]:
    """Map each CpgMethod/CpgCall identity to the list of its props dicts in `batch.nodes`.

    A NODE_KEY can appear more than once in `batch.nodes` (persist's `_node_rows` unions the
    duplicates); we keep ALL of them so the stamp is applied to every dict sharing an identity and the
    persisted union is consistent regardless of which duplicate wins per-key. Also defaults every
    method/call to `reachable_from_entry=False, hop_distance=-1` so unreached nodes carry the props
    explicitly (a query can then filter `reachable_from_entry = false`)."""
    index: dict[tuple[str, str], list[dict]] = {}
    for label, props in batch.nodes:
        if label == "CpgMethod":
            key = (_METHOD, props.get("full_name"))
        elif label == "CpgCall":
            key = (_CALL, props.get("uid"))
        else:
            continue
        if key[1] is None:
            continue
        props["reachable_from_entry"] = False
        props["hop_distance"] = -1
        index.setdefault(key, []).append(props)
    return index


def _endpoint(kind_key: tuple[str, str], edge_key: dict):
    """Resolve an edge endpoint dict to a traversal identity, or None if the key is absent."""
    kind, prop = kind_key
    val = edge_key.get(prop)
    return (kind, val) if val is not None else None


def _adjacency_and_sources(batch: schema.Batch):
    """Build the directed adjacency (identity -> list of neighbor identities) over the traversal
    edges, plus the set of source identities (the CpgMethod each ENTERS_AT points at)."""
    adj: dict[tuple[str, str], list[tuple[str, str]]] = {}
    sources: set[tuple[str, str]] = set()
    for rtype, from_label, from_key, to_label, to_key, _props in batch.edges:
        spec = _TRAVERSAL.get(rtype)
        if spec is not None:
            src = _endpoint(spec[0], from_key)
            dst = _endpoint(spec[1], to_key)
            if src is not None and dst is not None:
                adj.setdefault(src, []).append(dst)
        elif rtype == "ENTERS_AT":
            entry_method = _endpoint((_METHOD, "full_name"), to_key)
            if entry_method is not None:
                sources.add(entry_method)
    return adj, sources


def tag_reachability(batch: schema.Batch) -> dict:
    """Stamp `reachable_from_entry` / `hop_distance` onto every CpgMethod and CpgCall in `batch`.

    Pure over the in-memory batch (mutates `batch.nodes` props dicts in place; reads `batch.edges`).
    Multi-source BFS from the entry methods yields the minimum hop distance to each reached node.
    Idempotent: running twice yields identical props. Returns a small summary for a progress event."""
    index = _node_props_index(batch)
    adj, sources = _adjacency_and_sources(batch)

    # Multi-source BFS: every entry method starts at hop 0. First visit wins (min distance) because
    # BFS dequeues nodes in nondecreasing distance order.
    dist: dict[tuple[str, str], int] = {}
    queue: deque[tuple[str, str]] = deque()
    for src in sources:
        if src not in dist:
            dist[src] = 0
            queue.append(src)
    while queue:
        node = queue.popleft()
        d = dist[node]
        for nbr in adj.get(node, ()):
            if nbr not in dist:
                dist[nbr] = d + 1
                queue.append(nbr)

    # Stamp the reached identities (only those that resolve to real batch nodes).
    for identity, d in dist.items():
        for props in index.get(identity, ()):
            props["reachable_from_entry"] = True
            props["hop_distance"] = d

    total_methods = sum(1 for k in index if k[0] == _METHOD)
    total_calls = sum(1 for k in index if k[0] == _CALL)
    reached_methods = sum(1 for k in dist if k[0] == _METHOD and k in index)
    reached_calls = sum(1 for k in dist if k[0] == _CALL and k in index)
    return {
        "reached_methods": reached_methods,
        "reached_calls": reached_calls,
        "total_methods": total_methods,
        "total_calls": total_calls,
    }


# Above this node count, exact betweenness (O(V*E)) is too slow, so fall back to a k-sample
# approximation (networkx samples `k` pivot sources). Seeded so a re-build is reproducible.
_CENTRALITY_EXACT_MAX = 2000
_CENTRALITY_SAMPLE_K = 500
_CENTRALITY_SEED = 1


def _kind_index(batch: schema.Batch) -> dict[tuple[str, str], list[dict]]:
    """identity -> props dicts for CpgMethod/CpgCall, WITHOUT touching reachability props (unlike
    `_node_props_index`, which defaults them). Used by centrality, which runs after reachability."""
    index: dict[tuple[str, str], list[dict]] = {}
    for label, props in batch.nodes:
        if label == "CpgMethod":
            key = (_METHOD, props.get("full_name"))
        elif label == "CpgCall":
            key = (_CALL, props.get("uid"))
        else:
            continue
        if key[1] is None:
            continue
        index.setdefault(key, []).append(props)
    return index


def tag_centrality(batch: schema.Batch) -> dict:
    """Stamp betweenness `centrality` (0-1) onto every CpgMethod/CpgCall, over the ATTACKER-REACHABLE
    call graph. Must run AFTER `tag_reachability` (it reads `reachable_from_entry`).

    High betweenness marks a chokepoint many flows pass through -- a shared sanitizer whose bypass
    compromises everything downstream, or a shared sink wrapper -- which is exactly what we most want
    surfaced. Computing it on the reachable subgraph (not the whole graph) keeps the score about real
    attacker paths and bounds the cost. Unreachable nodes (and nodes off every shortest path) get 0.0.
    Pure over the batch (mutates props in place) and idempotent. Uses networkx; no APOC/GDS."""
    import networkx as nx

    index = _kind_index(batch)
    for plist in index.values():          # default first -> idempotent, and unreachable stays 0.0
        for props in plist:
            props["centrality"] = 0.0

    reachable = {ident for ident, plist in index.items()
                 if any(p.get("reachable_from_entry") for p in plist)}
    adj, _sources = _adjacency_and_sources(batch)

    g = nx.DiGraph()
    g.add_nodes_from(reachable)
    for src, nbrs in adj.items():
        if src in reachable:
            for dst in nbrs:
                if dst in reachable:
                    g.add_edge(src, dst)

    n = g.number_of_nodes()
    if n == 0:
        return {"nodes": 0, "edges": 0, "max_centrality": 0.0}

    if n > _CENTRALITY_EXACT_MAX:
        centrality = nx.betweenness_centrality(
            g, k=min(_CENTRALITY_SAMPLE_K, n), normalized=True, seed=_CENTRALITY_SEED)
    else:
        centrality = nx.betweenness_centrality(g, normalized=True)

    for ident, c in centrality.items():
        for props in index.get(ident, ()):
            props["centrality"] = float(c)

    return {"nodes": n, "edges": g.number_of_edges(),
            "max_centrality": max(centrality.values(), default=0.0)}
