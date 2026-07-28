"""Persist a `schema.Batch` into Orion's own Neo4j: single-scan clear-and-load.

The one write path in the build layer. It clears the scan partition (label-scoped -- see `_clear`),
then CREATEs all nodes and all edges (endpoints MATCHed by NODE_KEY) as bounded UNWIND CHUNKS fanned
across a small session pool (items 3 + 5): O(chunk) per-transaction state, incremental commits, and
disjoint chunks written in parallel, instead of the old single whole-graph transaction. Idempotent:
a re-build of the same scan_id clears then reloads identical data. The chunk/parallel split trades
the old atomic clear-and-load (see `persist` for the crash-window tradeoff).

CREATE, not MERGE (item 1): the partition is DETACH DELETEd first, so every node and edge in the
batch is brand-new -- MERGE's MATCH-then-CREATE is pure wasted work on guaranteed-new data, and
dropping it "practically halves the queries" (Neo4j bulk-update guidance). The two collapses MERGE
gave for free are reproduced in Python before the write so CREATE yields a byte-for-byte identical
graph: `_node_rows` dedups nodes by NODE_KEY (last-wins), and `_edge_rows` dedups non-FLOWS_TO edges
by endpoint pattern (last-wins). FLOWS_TO is never deduped: `collapse_flows` can legitimately emit
two flows between the same call pair that differ ONLY by `arg_index` (e.g. `sink(x, x)`), and both
must survive -- a relationship MERGE (whose pattern can't carry arg_index) would have dropped one,
which is exactly why FLOWS_TO was already CREATEd.

Not agent-reachable — agents read through GraphDB.run_cypher (writes blocked). Only the harness
build step calls this.
"""
from __future__ import annotations

import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

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


def _node_create(label: str) -> str:
    # CREATE, not MERGE: `_write_tx` clears the scan partition first (DETACH DELETE), so every node
    # in the batch is brand-new. MERGE runs a MATCH-then-CREATE (two ops) on guaranteed-new data --
    # pure waste that "practically halves the queries" to drop (Neo4j bulk-update guidance). The
    # NODE_KEY collapse MERGE gave us for free is reproduced in Python by `_node_rows` (dedup), so
    # CREATE never duplicates a key. row.props already carries the key props, so no key pattern here.
    return f"UNWIND $rows AS row CREATE (n:`{label}`) SET n += row.props"


def _edge_create(rtype: str, from_label: str, to_label: str,
                 from_keys: tuple[str, ...], to_keys: tuple[str, ...]) -> str:
    fpat = ", ".join(f"`{k}`: row.fk.`{k}`" for k in from_keys)
    tpat = ", ".join(f"`{k}`: row.tk.`{k}`" for k in to_keys)
    # Every edge is CREATEd now (the partition was just cleared). FLOWS_TO always was; non-FLOWS_TO
    # switches from MERGE to CREATE, its pattern-identity collapse reproduced by `_edge_rows` dedup.
    # Endpoints are still MATCHed by NODE_KEY (index-backed) -- nodes are created before edges.
    return (f"UNWIND $rows AS row "
            f"MATCH (a:`{from_label}` {{{fpat}}}) "
            f"MATCH (b:`{to_label}` {{{tpat}}}) "
            f"CREATE (a)-[r:`{rtype}`]->(b) SET r += row.props")


def _node_rows(nodes) -> dict[str, list[dict]]:
    """label -> CREATE rows ({"props": props}), deduped by NODE_KEY with last-write-wins.

    DETACH DELETE clears the partition first, so CREATE is safe -- but two batch rows can share a
    NODE_KEY (the old per-label MERGE silently collapsed them, the last SET winning). CREATE would
    instead make TWO nodes with the same key, which both duplicates the node and makes an
    edge-endpoint MATCH ambiguous (it would create the edge against an arbitrary one, or two edges).
    So we reproduce MERGE's collapse here: last row wins, exactly like `MERGE ... SET n += props`.
    Pure -- unit-tested without Neo4j."""
    by_label: dict[str, dict[tuple, dict]] = defaultdict(dict)
    for label, props in nodes:
        key = tuple(props[k] for k in NODE_KEY[label])
        by_label[label][key] = props            # last-wins == MERGE ... SET n += props
    return {label: [{"props": p} for p in keyed.values()] for label, keyed in by_label.items()}


def _edge_rows(edges) -> dict[tuple, list[dict]]:
    """(rtype, from_label, to_label, from_keys, to_keys) -> CREATE rows ({"fk","tk","props"}).

    Non-FLOWS_TO edges are deduped to ONE row per (endpoint values), last-write-wins -- reproducing
    a relationship MERGE's pattern identity (`MERGE (a)-[:T]->(b)` matches on the pattern; props are
    not in it), so switching them to CREATE yields the identical single edge. FLOWS_TO keeps EVERY
    row: `collapse_flows` can legitimately emit two flows between the same call pair differing only
    by arg_index (e.g. `sink(x, x)`), and both must survive (see module docstring). First-seen order
    is preserved for determinism. Pure -- unit-tested without Neo4j."""
    flows: dict[tuple, list[dict]] = defaultdict(list)      # FLOWS_TO sigs: append every row
    struct: dict[tuple, dict[tuple, dict]] = defaultdict(dict)  # other sigs: {endpoint-values: row}, last-wins
    order: list[tuple] = []
    for rtype, fl, fk, tl, tk, props in edges:
        sig = (rtype, fl, tl, tuple(fk.keys()), tuple(tk.keys()))
        row = {"fk": fk, "tk": tk, "props": props}
        if rtype == "FLOWS_TO":
            if sig not in flows:
                order.append(sig)
            flows[sig].append(row)
        else:
            if sig not in struct:
                order.append(sig)
            endpoint = (tuple(fk.values()), tuple(tk.values()))
            struct[sig][endpoint] = row        # last-wins == MERGE (a)-[:T]->(b) SET r += props
    out: dict[tuple, list[dict]] = {}
    for sig in order:
        out[sig] = flows[sig] if sig[0] == "FLOWS_TO" else list(struct[sig].values())
    return out


def _clear(driver, scan_id: str) -> None:
    """Clear ONLY this scan's graph-label nodes (the NODE_KEY labels), not every node carrying the
    scan_id. This deliberately SPARES the semantic-index `:Chunk` nodes (same scan_id): once the
    clear is label-scoped, the embed step can run CONCURRENTLY with persist (item 4) without persist
    wiping the chunks embed just wrote. One managed transaction; DETACH removes their edges too."""
    labels = list(NODE_KEY.keys())
    with driver.session(database=config.NEO4J_DATABASE) as s:
        s.execute_write(lambda tx: tx.run(
            "MATCH (n {scan_id:$sid}) WHERE any(l IN labels(n) WHERE l IN $labels) DETACH DELETE n",
            sid=scan_id, labels=labels))


def _chunks(rows: list, size: int):
    """Split `rows` into <= `size`-length chunks (size floored at 1). Each chunk becomes one bounded
    write transaction, so per-tx state is O(chunk) instead of O(whole graph)."""
    step = max(1, size)
    for i in range(0, len(rows), step):
        yield rows[i:i + step]


def _run_write(tx, cypher: str, rows: list) -> None:
    tx.run(cypher, rows=rows)


def _node_jobs(nodes) -> list[tuple[str, list]]:
    """(cypher, rows) chunks for every node label -- deduped by NODE_KEY, then split to chunk size."""
    return [(_node_create(label), chunk)
            for label, rows in _node_rows(nodes).items()
            for chunk in _chunks(rows, config.PERSIST_CHUNK_SIZE)]


def _edge_jobs(edges) -> list[tuple[str, list]]:
    """(cypher, rows) chunks for every edge group -- non-FLOWS_TO deduped, then split to chunk size."""
    return [(_edge_create(*sig), chunk)
            for sig, rows in _edge_rows(edges).items()
            for chunk in _chunks(rows, config.PERSIST_CHUNK_SIZE)]


def _run_jobs(driver, jobs: list[tuple[str, list]], concurrency: int) -> None:
    """Run each (cypher, rows) job as its own managed write transaction -- bounded per-tx state and
    incremental commits (item 3). With concurrency > 1, jobs fan across a bounded thread pool, each
    on its OWN session (item 5): node jobs are disjoint (distinct brand-new nodes, no lock overlap),
    and edge jobs use managed transactions that auto-retry a transient deadlock (concurrent CREATEs
    touching a shared endpoint's relationships). A job that raises propagates -- never a silent
    partial load. concurrency <= 1 keeps the old single-session sequential behavior."""
    if not jobs:
        return
    if concurrency <= 1:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            for cypher, rows in jobs:
                s.execute_write(_run_write, cypher, rows)
        return

    def _one(job: tuple[str, list]) -> None:
        cypher, rows = job
        with driver.session(database=config.NEO4J_DATABASE) as s:
            s.execute_write(_run_write, cypher, rows)

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for _ in ex.map(_one, jobs):   # forces completion + re-raises the first job's exception
            pass


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
    """Clear the scan partition and load the batch (nodes then edges) as CHUNKED, optionally PARALLEL
    writes: bounded per-transaction state + incremental commits (item 3), fanned across a session
    pool of `config.PERSIST_CONCURRENCY` (item 5). Nodes are loaded before edges (edges MATCH their
    endpoints).

    TRADEOFF vs the old single atomic clear-and-load: the clear and the per-chunk loads are now
    SEPARATE transactions, so a crash mid-persist can leave a PARTIAL partition. This is self-healing
    -- the next build of the same scan_id clears then reloads -- and within one `orion scan` a persist
    crash raises and aborts the scan before discovery runs, so discovery never sees a half-loaded
    graph. The narrow exposure is querying a crashed partition via --scan-id before rebuilding.

    Returns a summary incl. a `timings` split (clear/nodes/edges seconds) the build log surfaces."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    timings: dict[str, float] = {}
    conc = config.PERSIST_CONCURRENCY
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            _ensure_indexes(s)                    # idempotent NODE_KEY range indexes, before the load
        t = time.monotonic()
        _clear(driver, batch.scan_id)
        timings["clear"] = time.monotonic() - t
        t = time.monotonic()
        _run_jobs(driver, _node_jobs(batch.nodes), conc)    # nodes first (edge endpoints must exist)
        timings["nodes"] = time.monotonic() - t
        t = time.monotonic()
        _run_jobs(driver, _edge_jobs(batch.edges), conc)
        timings["edges"] = time.monotonic() - t
    finally:
        driver.close()
    return {"scan_id": batch.scan_id, "nodes": len(batch.nodes), "edges": len(batch.edges),
            "timings": timings}
