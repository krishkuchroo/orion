"""Persist a `schema.Batch` into Orion's own Neo4j: single-scan clear-and-load.

The one write path in the build layer. In ONE write transaction it clears the scan partition,
then MERGEs all nodes (by their NODE_KEY) and all edges (matching endpoints by their key props),
UNWIND-batched per label so a full NodeGoat graph lands in a handful of round-trips. Doing the
clear and the load atomically means a crash leaves the previous scan intact rather than a half-empty
partition. Idempotent: a re-build of the same scan_id clears then reloads identical data.

FLOWS_TO edges are CREATEd, not MERGEd: `collapse_flows` can legitimately emit two distinct flows
between the same call pair that differ ONLY by `arg_index` (e.g. `sink(x, x)`), and a relationship
MERGE — whose pattern can't carry the differing arg_index — would collapse them and silently drop a
fact. CREATE is safe here because the transaction clears the partition first, so a re-build never
duplicates. Every other edge type is MERGEd (idempotent structural identity).

Not agent-reachable — agents read through GraphDB.run_cypher (writes blocked). Only the harness
build step calls this.
"""
from __future__ import annotations

from collections import defaultdict

from neo4j import GraphDatabase

from .. import config
from .schema import NODE_KEY, Batch


def _index_name(label: str) -> str:
    """Deterministic name for the NODE_KEY range index of a label (so SHOW INDEXES / DROP can target it)."""
    return f"orion_nodekey_{label}"


def _ensure_indexes(session) -> None:
    """Create one RANGE index per node label on its NODE_KEY properties, idempotently (IF NOT EXISTS).
    Without these, persist's per-label `MERGE (n:Label {keyprops})` and the edge-endpoint MATCHes do a
    full label scan per row -- quadratic on large repos (sharpemu's 38,662 CpgCall nodes hung persist
    ~25 min). RANGE indexes are correctness-neutral (they only change lookup speed). DDL is auto-committed,
    so this runs on the session BEFORE the data-write transaction (mirrors embed._ensure_vector_index)."""
    for label, keys in NODE_KEY.items():
        props = ", ".join(f"n.`{k}`" for k in keys)
        session.run(f"CREATE RANGE INDEX `{_index_name(label)}` IF NOT EXISTS "
                    f"FOR (n:`{label}`) ON ({props})")
    # Block until the freshly-created indexes are ONLINE so the very next MERGE is index-backed. Cheap
    # when they already exist (returns immediately). Timeout is seconds.
    session.run("CALL db.awaitIndexes(300)")


def _node_merge(label: str) -> str:
    keypat = ", ".join(f"`{k}`: row.key.`{k}`" for k in NODE_KEY[label])
    return f"UNWIND $rows AS row MERGE (n:`{label}` {{{keypat}}}) SET n += row.props"


def _edge_write(rtype: str, from_label: str, to_label: str,
                from_keys: tuple[str, ...], to_keys: tuple[str, ...]) -> str:
    fpat = ", ".join(f"`{k}`: row.fk.`{k}`" for k in from_keys)
    tpat = ", ".join(f"`{k}`: row.tk.`{k}`" for k in to_keys)
    # FLOWS_TO: CREATE (see module docstring) so parallel arg_index flows survive; else MERGE.
    verb = ("CREATE (a)-[r:`FLOWS_TO`]->(b)" if rtype == "FLOWS_TO"
            else f"MERGE (a)-[r:`{rtype}`]->(b)")
    return (f"UNWIND $rows AS row "
            f"MATCH (a:`{from_label}` {{{fpat}}}) "
            f"MATCH (b:`{to_label}` {{{tpat}}}) "
            f"{verb} SET r += row.props")


def _write_tx(tx, batch: Batch) -> None:
    # Clear this scan first, in the same transaction as the load (atomic clear-and-load).
    tx.run("MATCH (n {scan_id:$sid}) DETACH DELETE n", sid=batch.scan_id)

    # Nodes (so edge endpoints exist to MATCH), grouped per label for UNWIND.
    by_label: dict[str, list[dict]] = defaultdict(list)
    for label, props in batch.nodes:
        key = {k: props[k] for k in NODE_KEY[label]}
        by_label[label].append({"key": key, "props": props})
    for label, rows in by_label.items():
        tx.run(_node_merge(label), rows=rows)

    # Edges grouped by (rtype, endpoints, key-shape) for UNWIND.
    by_edge: dict[tuple, list[dict]] = defaultdict(list)
    for rtype, fl, fk, tl, tk, props in batch.edges:
        sig = (rtype, fl, tl, tuple(fk.keys()), tuple(tk.keys()))
        by_edge[sig].append({"fk": fk, "tk": tk, "props": props})
    for (rtype, fl, tl, fkeys, tkeys), rows in by_edge.items():
        tx.run(_edge_write(rtype, fl, tl, fkeys, tkeys), rows=rows)


def flows_count(scan_id: str) -> int:
    """Count FLOWS_TO edges persisted for a scan partition. FLOWS_TO carries `scan_id` as a
    relationship property (schema.emit_edge stamps it), so this scopes to exactly one build --
    the read-side check that a stream vs legacy build persisted the same taint edge count."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            return s.run("MATCH ()-[r:FLOWS_TO {scan_id:$sid}]->() RETURN count(r) AS n",
                         sid=scan_id).single()["n"]
    finally:
        driver.close()


def persist(batch: Batch) -> dict:
    """Clear the scan partition and load the batch (nodes then edges) in one atomic write
    transaction. Returns a small summary for the build log."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            _ensure_indexes(s)                    # idempotent NODE_KEY range indexes, before the load
            s.execute_write(_write_tx, batch)
    finally:
        driver.close()
    return {"scan_id": batch.scan_id, "nodes": len(batch.nodes), "edges": len(batch.edges)}
