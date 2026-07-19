"""Task B: the MCP tool server's impl functions, called directly (no FastMCP/stdio round-trip).

Skips cleanly when Neo4j is not up, matching the pattern in tests/test_smoke.py. Never invokes
`claude -p` (that costs tokens and belongs to integration testing, not this unit suite).
"""
import pytest

from orion.graphdb import GraphDB
from orion.graph_build import scan_id_for
from orion.mcp_server import get_schema_impl, run_cypher_impl, semantic_search_impl


def _db_or_skip() -> GraphDB:
    try:
        db = GraphDB()
        if not db.ping():
            pytest.skip("Neo4j not reachable")
        return db
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")


def test_run_cypher_blocks_writes():
    db = _db_or_skip()
    db.close()
    result = run_cypher_impl("CREATE (n) RETURN n", "any-scan-id")
    assert "error" in result


def test_run_cypher_returns_rows():
    db = _db_or_skip()
    db.close()
    scan_id = scan_id_for("fixtures/NodeGoat")
    result = run_cypher_impl(
        "MATCH (f:CpgFile {scan_id:$scan_id}) RETURN count(f) AS c", scan_id
    )
    assert result.get("row_count", 0) >= 1
    assert result["rows"][0]["c"] > 0


def test_semantic_search_tolerates_missing_embed():
    scan_id = scan_id_for("fixtures/NodeGoat")
    result = semantic_search_impl("anything", scan_id)
    assert isinstance(result, list)


def test_get_schema_lists_known_labels():
    db = _db_or_skip()
    db.close()
    result = get_schema_impl()
    node_labels = {label for row in result["node_properties"] for label in row["nodeLabels"]}
    assert "CpgFile" in node_labels
    assert "CpgMethod" in node_labels
