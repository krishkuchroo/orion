"""Task A: the standalone Joern->Neo4j builder.

Proves the build produces a correct, scan-isolated, file-attributed graph:
  - test_build_nodegoat        : real counts (CpgFile/CpgCall/FLOWS_TO > 0)
  - test_call_file_attribution : the eval() calls in contributions.js carry file_path (B3)
  - test_no_cross_scan_bleed   : every RESOLVES_TO edge stays within one scan (B2)

Builds a real NodeGoat graph, so it needs Neo4j up and the prebuilt cpg.bin fixture. Skips
cleanly when the DB is down. Not marked slow: joern-export from the prebuilt cpg.bin is ~3s.
"""
import os
import shutil
import tempfile

import pytest

from orion.graph_build import build
from orion.graphdb import GraphDB


def _db_or_skip() -> GraphDB:
    try:
        db = GraphDB()
        if not db.ping():
            pytest.skip("Neo4j not reachable")
        return db
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Neo4j not reachable: {exc}")


def _count(db: GraphDB, scan_id: str, query: str) -> int:
    res = db.run_cypher(scan_id, query)
    assert "rows" in res, res
    return res["rows"][0]["c"]


def test_build_nodegoat():
    _db_or_skip().close()
    scan_id = build("fixtures/NodeGoat")
    db = GraphDB()
    try:
        files = _count(db, scan_id, "MATCH (f:CpgFile {scan_id:$scan_id}) RETURN count(f) AS c")
        calls = _count(db, scan_id, "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN count(c) AS c")
        flows = _count(
            db, scan_id,
            "MATCH (:CpgCall {scan_id:$scan_id})-[r:FLOWS_TO]->(:CpgCall {scan_id:$scan_id}) "
            "RETURN count(r) AS c",
        )
        assert files > 0, "expected CpgFile nodes"
        assert calls > 200, f"expected >200 CpgCall, got {calls}"
        assert flows > 0, "expected FLOWS_TO taint edges"
    finally:
        db.close()


def test_call_file_attribution():
    """B3: every CALL is stamped with its owning file_path (via AST-ancestry to the enclosing
    method), so file attribution never depends on the fragile CONTAINS_CALL edge. The eval()
    calls in contributions.js are the canonical case."""
    _db_or_skip().close()
    scan_id = build("fixtures/NodeGoat")
    db = GraphDB()
    try:
        res = db.run_cypher(
            scan_id,
            "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.name = 'eval' "
            "RETURN c.code AS code, c.file_path AS file_path ORDER BY c.line",
        )
        rows = res["rows"]
        assert len(rows) >= 1, "expected the eval() calls to be present"
        for row in rows:
            assert row["file_path"] == "app/routes/contributions.js", row
        # Attribution must be total: no CpgCall left null OR stamped with the '<unknown>' sentinel
        # (the sentinel would mean AST-ancestry failed to reach an enclosing method).
        missing = db.run_cypher(
            scan_id,
            "MATCH (c:CpgCall {scan_id:$scan_id}) "
            "WHERE c.file_path IS NULL OR c.file_path = '<unknown>' RETURN count(c) AS c",
        )["rows"][0]["c"]
        assert missing == 0, f"{missing} CpgCall nodes have no real file_path"
    finally:
        db.close()


def test_no_cross_scan_bleed():
    """B2: two scans that share method full_names must not cross-link. A second scan is built
    from a temp copy of the CPG (different abspath -> different scan_id, identical full_names),
    then we assert NO RESOLVES_TO edge connects a call in one scan to a method in another. The
    bug (edge MERGE matching CpgMethod by full_name alone) would bind the wrong scan's method."""
    _db_or_skip().close()
    scan_a = build("fixtures/NodeGoat")

    tmp = tempfile.mkdtemp(prefix="orion_scan_b_")
    db = GraphDB()
    scan_b = None
    try:
        shutil.copy("fixtures/NodeGoat/cpg.bin", os.path.join(tmp, "cpg.bin"))
        scan_b = build(tmp)
        assert scan_a != scan_b, "the two scans must have distinct scan_ids"

        crossing = db.run_cypher(
            scan_a,  # scan_id param is unused by this query; both scans are queried directly
            "MATCH (c:CpgCall)-[r:RESOLVES_TO]->(m:CpgMethod) "
            "WHERE c.scan_id <> m.scan_id RETURN count(r) AS c",
        )["rows"][0]["c"]
        assert crossing == 0, f"{crossing} RESOLVES_TO edges cross scan boundaries (B2 bug)"
    finally:
        if scan_b is not None:
            db.clear_scan(scan_b)
        db.close()
        shutil.rmtree(tmp, ignore_errors=True)
