"""Scan partitions in Neo4j: which labels a scan owns, and deleting / counting them in batches.

Every Orion node carries `scan_id`, but a label-less `MATCH (n {scan_id:$sid})` can't use an index:
it plans as an AllNodesScan over every scan in the database (~1.2M nodes on the dev box) and the
old deletes ran it as ONE transaction. Here every lookup names its label, is served by a
single-property scan_id RANGE index (the composite NODE_KEY indexes lead with scan_id but Neo4j 5
does not use them for a scan_id-only predicate), and deletes go in LIMIT-sized batches, one
transaction each, until a batch comes back empty.

Which labels each caller deletes is deliberate:
  - persist._clear: NODE_KEY labels only. It spares the semantic-index :Chunk nodes (embed writes
    them concurrently with persist) and the scan's record.
  - GraphDB.clear_scan / gc: SCAN_LABELS, everything the scan owns.
"""
from __future__ import annotations

from .. import config
from .schema import NODE_KEY

# Every label a node carrying a scan_id can have. NODE_KEY = the static graph (persist); Chunk = the
# semantic index (embed.py); OrionScan = the scan record. A new label carrying scan_id must be added
# here or a scan delete misses it (tests/test_scan_delete.py checks the live database).
SCAN_LABELS: tuple[str, ...] = (*NODE_KEY, "Chunk", "OrionScan")

DELETE_BATCH_SIZE = 10000

# `{label}` is filled per label (str.format); `{{ }}` are literal Cypher braces.
DELETE_BATCH = ("MATCH (n:`{label}` {{scan_id:$sid}}) WITH n LIMIT $batch "
                "DETACH DELETE n RETURN count(*) AS n")
COUNT = "MATCH (n:`{label}` {{scan_id:$sid}}) RETURN count(n) AS n"


def _index_name(label: str) -> str:
    return f"orion_scanid_{label}"


def ensure_scan_indexes(session) -> None:
    """Idempotently create a scan_id RANGE index per SCAN_LABELS label and wait until each is
    ONLINE (by name, like persist's NODE_KEY indexes, so an unrelated index build never blocks us).
    DDL auto-commits, so this runs on the session before any write transaction."""
    for label in SCAN_LABELS:
        session.run(f"CREATE RANGE INDEX `{_index_name(label)}` IF NOT EXISTS "
                    f"FOR (n:`{label}`) ON (n.scan_id)").consume()
    for label in SCAN_LABELS:
        session.run("CALL db.awaitIndex($name, 300)", name=_index_name(label)).consume()


def delete_scan(driver, scan_id: str, labels, batch: int = DELETE_BATCH_SIZE) -> dict[str, int]:
    """DETACH DELETE every node of `scan_id` under each of `labels`, `batch` nodes per transaction,
    until none is left. Returns {label: nodes deleted} for every label asked for."""
    deleted: dict[str, int] = {}
    with driver.session(database=config.NEO4J_DATABASE) as s:
        ensure_scan_indexes(s)
        for label in labels:
            cypher = DELETE_BATCH.format(label=label)
            total = 0
            while True:
                n = s.execute_write(
                    lambda tx: tx.run(cypher, sid=scan_id, batch=batch).single()["n"])
                total += n
                if n == 0:
                    break
            deleted[label] = total
    return deleted


def count_scan(session, scan_id: str, labels) -> dict[str, int]:
    """{label: nodes of `scan_id`} for each of `labels` (read-only)."""
    return {label: session.run(COUNT.format(label=label), sid=scan_id).single()["n"]
            for label in labels}
