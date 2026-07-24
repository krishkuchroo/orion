from neo4j import GraphDatabase

from orion import config
from orion.graph import persist, schema


def _index_names(session) -> set:
    return {r["name"] for r in session.run("SHOW INDEXES YIELD name RETURN name")}


def test_persist_ensures_node_key_indexes():
    """persist() must idempotently provision a RANGE index for every NODE_KEY label, so the per-label
    MERGE (and edge-endpoint MATCH) is index-backed rather than a quadratic label scan on large repos.
    Hermetic: drop the indexes, persist a minimal batch, assert persist re-created all of them."""
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        # Start from a known-missing state so the test proves persist CREATES them (not that they linger).
        with drv.session(database=config.NEO4J_DATABASE) as s:
            for label in schema.NODE_KEY:
                s.run(f"DROP INDEX `{persist._index_name(label)}` IF EXISTS")
            assert not (set(persist._index_name(l) for l in schema.NODE_KEY) & _index_names(s))

        # A minimal, valid batch (one CpgFile node is enough -- _ensure_indexes iterates NODE_KEY, not
        # the batch). schema.Batch is constructed with scan_id only; nodes are added via emit_node.
        batch = schema.Batch("test-persist-idx")
        batch.emit_node("CpgFile", {"scan_id": "test-persist-idx", "uid": "f1"})
        persist.persist(batch)

        with drv.session(database=config.NEO4J_DATABASE) as s:
            names = _index_names(s)
        for label in schema.NODE_KEY:
            assert persist._index_name(label) in names, f"missing NODE_KEY index for {label}"

        # Idempotent second call must not raise (IF NOT EXISTS).
        persist.persist(batch)
    finally:
        # Clean the test partition; LEAVE the indexes in place (shared infra other tests benefit from).
        with drv.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n {scan_id:'test-persist-idx'}) DETACH DELETE n")
        drv.close()
