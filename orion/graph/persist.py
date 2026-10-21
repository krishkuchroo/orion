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
from . import scans
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
    # Block until OUR indexes are ONLINE so the very next CREATE's edge-endpoint MATCH is index-backed.
    # Await each NODE_KEY index BY NAME rather than db.awaitIndexes (ALL): under the item-4 overlap the
    # embed step may be concurrently building its own vector index, and db.awaitIndexes would make
    # persist block on that too. Cheap when an index already exists (returns immediately); seconds unit.
    for label in NODE_KEY:
        session.run("CALL db.awaitIndex($name, 300)", name=_index_name(label))
    scans.ensure_scan_indexes(session)    # scan_id-only lookups (the clear) need their own index


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
    """label -> CREATE rows ({"props": props}), deduped by NODE_KEY, UNIONing props across duplicates.

    DETACH DELETE clears the partition first, so CREATE is safe -- but two batch rows can share a
    NODE_KEY (the old per-label MERGE silently collapsed them). CREATE would instead make TWO nodes
    with the same key, which both duplicates the node and makes an edge-endpoint MATCH ambiguous. So
    we reproduce MERGE's collapse here EXACTLY: `MERGE (n {key}) SET n += props` over duplicate rows
    ACCUMULATES the union of their property keys (last-wins per key, but a key set by an earlier row
    is never dropped by a later row that omits it). We therefore merge dicts (`{**prev, **props}`),
    not replace -- a plain replace would drop a key an earlier row set (e.g. a CpgMethod row carrying
    file_path/line collapsed against a later external-stub row without them, which would then vanish
    from the semantic index's non-null-span filter). Pure -- unit-tested without Neo4j."""
    by_label: dict[str, dict[tuple, dict]] = defaultdict(dict)
    for label, props in nodes:
        key = tuple(props[k] for k in NODE_KEY[label])
        by_label[label][key] = {**by_label[label].get(key, {}), **props}   # union == MERGE SET n += props
    return {label: [{"props": p} for p in keyed.values()] for label, keyed in by_label.items()}


def _edge_rows(edges) -> dict[tuple, list[dict]]:
    """(rtype, from_label, to_label, from_keys, to_keys) -> CREATE rows ({"fk","tk","props"}).

    Non-FLOWS_TO edges are deduped to ONE row per (endpoint values), UNIONing props -- reproducing a
    relationship MERGE's pattern identity (`MERGE (a)-[:T]->(b) SET r += props` matches on the
    pattern; props accumulate across duplicate rows), so switching them to CREATE yields the identical
    single edge with the same accumulated props. (Non-FLOWS_TO edges carry only {scan_id} today, so
    union and replace coincide -- the merge keeps it byte-for-byte correct if edge props ever grow.)
    FLOWS_TO keeps EVERY row: `collapse_flows` can legitimately emit two flows between the same call
    pair differing only by arg_index (e.g. `sink(x, x)`), and both must survive (see module
    docstring). First-seen order is preserved for determinism. Pure -- unit-tested without Neo4j."""
    flows: dict[tuple, list[dict]] = defaultdict(list)      # FLOWS_TO sigs: append every row
    struct: dict[tuple, dict[tuple, dict]] = defaultdict(dict)  # other sigs: {endpoint-values: row}, union props
    order: list[tuple] = []
    for rtype, fl, fk, tl, tk, props in edges:
        sig = (rtype, fl, tl, tuple(fk.keys()), tuple(tk.keys()))
        if rtype == "FLOWS_TO":
            if sig not in flows:
                order.append(sig)
            flows[sig].append({"fk": fk, "tk": tk, "props": props})
        else:
            if sig not in struct:
                order.append(sig)
            endpoint = (tuple(fk.values()), tuple(tk.values()))
            prev = struct[sig].get(endpoint)
            merged = {**(prev["props"] if prev else {}), **props}   # union == MERGE (a)-[:T]->(b) SET r += props
            struct[sig][endpoint] = {"fk": fk, "tk": tk, "props": merged}
    out: dict[tuple, list[dict]] = {}
    for sig in order:
        out[sig] = flows[sig] if sig[0] == "FLOWS_TO" else list(struct[sig].values())
    return out


def _clear(driver, scan_id: str) -> dict[str, int]:
    """Clear ONLY this scan's graph-label nodes (the NODE_KEY labels), not every node carrying the
    scan_id. This deliberately SPARES the semantic-index `:Chunk` nodes (same scan_id): once the
    clear is label-scoped, the embed step can run CONCURRENTLY with persist (item 4) without persist
    wiping the chunks embed just wrote. It also spares the scan's :OrionScan record. Per label, in
    batched transactions over a scan_id index (scans.delete_scan); DETACH removes their edges too.
    Returns {label: nodes deleted}."""
    return scans.delete_scan(driver, scan_id, NODE_KEY)


def _chunks(rows: list, size: int):
    """Split `rows` into <= `size`-length chunks (size floored at 1). Each chunk becomes one bounded
    write transaction, so per-tx state is O(chunk) instead of O(whole graph)."""
    step = max(1, size)
    for i in range(0, len(rows), step):
        yield rows[i:i + step]


class PersistMismatch(RuntimeError):
    """Neo4j's write counters disagree with the batch: fewer edges than rows means an endpoint was
    missing (MATCH...CREATE created nothing, silently); more means a key matched several nodes.
    Raised only in strict mode (config.persist_strict()); otherwise persist reports and the build
    warns. Raised after every job ran, so the partial partition is left for inspection."""


def _run_write(tx, cypher: str, rows: list):
    """Run one job and return its write counters (nodes_created / relationships_created)."""
    return tx.run(cypher, rows=rows).consume().counters


def _keyed_node_jobs(node_rows: dict[str, list[dict]]) -> list[tuple[str, str, list]]:
    """(label, cypher, rows) chunks for every node label, split to chunk size."""
    return [(label, _node_create(label), chunk)
            for label, rows in node_rows.items()
            for chunk in _chunks(rows, config.PERSIST_CHUNK_SIZE)]


def _keyed_edge_jobs(edge_rows: dict[tuple, list[dict]]) -> list[tuple[str, str, list]]:
    """(rel type, cypher, rows) chunks for every edge group, split to chunk size."""
    return [(sig[0], _edge_create(*sig), chunk)
            for sig, rows in edge_rows.items()
            for chunk in _chunks(rows, config.PERSIST_CHUNK_SIZE)]


def _node_jobs(nodes) -> list[tuple[str, list]]:
    """(cypher, rows) chunks for every node label -- deduped by NODE_KEY, then split to chunk size."""
    return [(cypher, rows) for _key, cypher, rows in _keyed_node_jobs(_node_rows(nodes))]


def _edge_jobs(edges) -> list[tuple[str, list]]:
    """(cypher, rows) chunks for every edge group -- non-FLOWS_TO deduped, then split to chunk size."""
    return [(cypher, rows) for _key, cypher, rows in _keyed_edge_jobs(_edge_rows(edges))]


def _run_jobs(driver, jobs: list[tuple[str, list]], concurrency: int) -> list:
    """Run each (cypher, rows) job as its own managed write transaction -- bounded per-tx state and
    incremental commits (item 3). With concurrency > 1, jobs fan across a bounded thread pool, each
    on its OWN session (item 5): node jobs are disjoint (distinct brand-new nodes, no lock overlap),
    and edge jobs use managed transactions that auto-retry a transient deadlock (concurrent CREATEs
    touching a shared endpoint's relationships). A job that raises propagates -- never a silent
    partial load. concurrency <= 1 keeps the old single-session sequential behavior.
    Returns each job's write counters, in job order."""
    if not jobs:
        return []
    if concurrency <= 1:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            return [s.execute_write(_run_write, cypher, rows) for cypher, rows in jobs]

    def _one(job: tuple[str, list]):
        cypher, rows = job
        with driver.session(database=config.NEO4J_DATABASE) as s:
            return s.execute_write(_run_write, cypher, rows)

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        return list(ex.map(_one, jobs))   # forces completion + re-raises the first job's exception


def _tally(keyed_jobs: list[tuple[str, str, list]], counters: list, attr: str) -> dict[str, dict]:
    """{key: {"expected": rows sent, "written": what Neo4j says it created}} per label / rel type."""
    out: dict[str, dict] = {}
    for (key, _cypher, rows), c in zip(keyed_jobs, counters):
        t = out.setdefault(key, {"expected": 0, "written": 0})
        t["expected"] += len(rows)
        t["written"] += getattr(c, attr)
    return out


def _mismatches(counts: dict) -> list[str]:
    return [f"{kind} {key}: expected {t['expected']}, written {t['written']}"
            for kind in ("nodes", "edges")
            for key, t in counts[kind].items() if t["expected"] != t["written"]]


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


def add_nodes(nodes, *, strict: bool | None = None) -> dict:
    """CREATE `nodes` ((label, props) pairs, scan_id already set) into an EXISTING partition, with no
    clear -- the write half of `orion reanalyze`. Same chunked jobs and counter check as `persist`:
    returns {"counts": {label: {expected, written}}, "mismatches": [...]}; strict raises."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    jobs = _keyed_node_jobs(_node_rows(nodes))
    try:
        counters = _run_jobs(driver, [(c, r) for _k, c, r in jobs], config.PERSIST_CONCURRENCY)
    finally:
        driver.close()
    counts = {"nodes": _tally(jobs, counters, "nodes_created"), "edges": {}}
    mismatches = _mismatches(counts)
    if mismatches and (config.persist_strict() if strict is None else strict):
        raise PersistMismatch("wrote a different number of nodes than given: " + "; ".join(mismatches))
    return {"counts": counts["nodes"], "mismatches": mismatches}


def persist(batch: Batch, *, strict: bool | None = None) -> dict:
    """Clear the scan partition and load the batch (nodes then edges) as CHUNKED, optionally PARALLEL
    writes: bounded per-transaction state + incremental commits (item 3), fanned across a session
    pool of `config.PERSIST_CONCURRENCY` (item 5). Nodes are loaded before edges (edges MATCH their
    endpoints).

    TRADEOFF vs the old single atomic clear-and-load: the clear and the per-chunk loads are now
    SEPARATE transactions, so a crash mid-persist can leave a PARTIAL partition. This is self-healing
    -- the next build of the same scan_id clears then reloads -- and within one `orion scan` a persist
    crash raises and aborts the scan before discovery runs, so discovery never sees a half-loaded
    graph. The narrow exposure is querying a crashed partition via --scan-id before rebuilding.

    Every job's write counters are compared with the rows it sent: `counts` holds expected/written
    per node label and rel type, `mismatches` one line per disagreement. With `strict` (default
    `config.persist_strict()`) a mismatch raises PersistMismatch; otherwise the caller warns.

    Returns a summary incl. a `timings` split (clear/nodes/edges seconds) the build log surfaces."""
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    timings: dict[str, float] = {}
    conc = config.PERSIST_CONCURRENCY
    node_jobs = _keyed_node_jobs(_node_rows(batch.nodes))
    edge_jobs = _keyed_edge_jobs(_edge_rows(batch.edges))
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            _ensure_indexes(s)                    # idempotent NODE_KEY range indexes, before the load
        t = time.monotonic()
        _clear(driver, batch.scan_id)
        timings["clear"] = time.monotonic() - t
        t = time.monotonic()
        # nodes first (edge endpoints must exist)
        node_counters = _run_jobs(driver, [(c, r) for _k, c, r in node_jobs], conc)
        timings["nodes"] = time.monotonic() - t
        t = time.monotonic()
        edge_counters = _run_jobs(driver, [(c, r) for _k, c, r in edge_jobs], conc)
        timings["edges"] = time.monotonic() - t
    finally:
        driver.close()
    counts = {"nodes": _tally(node_jobs, node_counters, "nodes_created"),
              "edges": _tally(edge_jobs, edge_counters, "relationships_created")}
    mismatches = _mismatches(counts)
    if mismatches and (config.persist_strict() if strict is None else strict):
        raise PersistMismatch(f"persist of {batch.scan_id} wrote a different number of rows than the "
                              "batch holds: " + "; ".join(mismatches))
    return {"scan_id": batch.scan_id, "nodes": len(batch.nodes), "edges": len(batch.edges),
            "timings": timings, "counts": counts, "mismatches": mismatches}
