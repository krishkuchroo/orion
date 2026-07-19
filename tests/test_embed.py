"""Task E: the semantic index (orion/embed.py) — chunk methods, embed locally, search by meaning.

test_index_and_search is marked slow: it downloads the jinaai/jina-embeddings-v2-base-code model
on first run (~300MB) and does local embedding compute — no Claude tokens involved. It writes real
Chunk nodes into the already-loaded NodeGoat scan, which is expected and desirable. Skips cleanly
if Neo4j is down.
"""
import pytest

from orion.graph_build import scan_id_for
from orion.graphdb import GraphDB

from orion import embed


def _db_or_skip() -> GraphDB:
    try:
        db = GraphDB()
        if not db.ping():
            pytest.skip("Neo4j not reachable")
        return db
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")


@pytest.mark.slow
def test_index_and_search():
    _db_or_skip().close()
    scan_id = scan_id_for("fixtures/NodeGoat")

    embed.index("fixtures/NodeGoat", scan_id)
    results = embed.search("where are user passwords compared", scan_id, k=5)

    assert results, "expected non-empty search results"
    for r in results:
        assert set(r.keys()) >= {"file", "span", "text", "score"}
    assert any("user-dao" in r["file"] for r in results), results


def test_search_unindexed_scan_returns_empty_not_error():
    """A scan_id that was never indexed (no matching Chunk nodes) returns [] cleanly — not an
    error — even once the vector index exists from other scans."""
    _db_or_skip().close()
    results = embed.search("this scan id was never indexed", "no-such-scan-id-xyz", k=5)
    assert results == []
