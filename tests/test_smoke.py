"""Phase 0 smoke test: the graph store is reachable and read_cypher works.

Skips cleanly when Neo4j is not up, so the suite is safe to run anywhere. It does NOT call any
agent (that needs the `claude` CLI and costs tokens); it only proves the grounding tool connects.
"""
import pytest

from orion.graphdb import GraphDB


def _db_or_skip() -> GraphDB:
    try:
        db = GraphDB()
        if not db.ping():
            pytest.skip("Neo4j not reachable")
        return db
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")


def test_ping():
    db = _db_or_skip()
    try:
        assert db.ping() is True
    finally:
        db.close()


def test_run_cypher_is_read_only():
    db = _db_or_skip()
    try:
        blocked = db.run_cypher("any", "CREATE (n:Nope) RETURN n")
        assert "error" in blocked and "read-only" in blocked["error"]
    finally:
        db.close()
