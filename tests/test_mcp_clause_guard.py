"""Change 9: the Claude agents' `run_cypher` (MCP server -> GraphDB.run_cypher) refuses clauses that
reach past the graph, before the query gets to Neo4j.

The READ-access session (commit 515225b) stops writes, but not these, measured live:
  - LOAD CSV FROM 'http://...' -> the Neo4j SERVER fetches the URL (a prompt injection in a scanned
    repo could send data out in it);
  - SHOW TRANSACTIONS / TERMINATE TRANSACTIONS -> list or kill other sessions' transactions;
  - USE <db> and CALL <procedure>.
Live Neo4j. The LOAD CSV test points Neo4j at a throwaway HTTP server on this machine
(host.docker.internal -> the host's loopback), so nothing leaves the box.
"""
from __future__ import annotations

import http.server
import socketserver
import threading

import pytest

from orion import config
from orion.lm import tools as lm_tools
from orion.mcp_server import run_cypher_impl


@pytest.fixture
def http_hits():
    """A local HTTP server Neo4j can reach as host.docker.internal:<port>; yields (port, hits)."""
    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"a,b\n1,2\n")

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], hits
    srv.shutdown()
    srv.server_close()


def test_load_csv_is_refused_before_neo4j_fetches(neo4j_driver, http_hits):
    port, hits = http_hits
    url = f"http://host.docker.internal:{port}/exfil?d=secret"
    # Control: the channel works, so a fetch WOULD show up (else this test can't prove anything).
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        try:
            s.run(f"LOAD CSV FROM '{url}' AS row RETURN row").consume()
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Neo4j cannot reach the local test server: {exc}")
    if not hits:
        pytest.skip("Neo4j cannot reach the local test server")
    hits.clear()
    result = run_cypher_impl(f"LOAD CSV FROM '{url}' AS row RETURN row", "test-mcp")
    assert hits == [], f"Neo4j fetched {hits}"
    assert "LOAD CSV is not allowed" in result.get("error", ""), result


def test_terminate_is_refused_before_neo4j_runs_it(neo4j_driver):
    victim_session = neo4j_driver.session(database=config.NEO4J_DATABASE)
    tx = victim_session.begin_transaction(metadata={"probe": "mcp-guard-victim"})
    try:
        tx.run("RETURN 1").consume()
        with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
            txid = s.run("SHOW TRANSACTIONS YIELD transactionId, metaData "
                         "WHERE metaData.probe = 'mcp-guard-victim' RETURN transactionId").single()[0]
        result = run_cypher_impl(f"TERMINATE TRANSACTIONS '{txid}'", "test-mcp")
        tx.run("RETURN 2").consume()     # raises Transaction.Terminated if the kill went through
        tx.commit()
    finally:
        if not tx.closed():
            tx.close()
        victim_session.close()
    assert "TERMINATE is not allowed" in result.get("error", ""), result


@pytest.mark.parametrize("query,word", [
    ("SHOW TRANSACTIONS YIELD transactionId, currentQuery RETURN transactionId, currentQuery", "SHOW"),
    ("USE neo4j MATCH (n:CpgFile) RETURN count(n) AS c", "USE"),
    ("CALL dbms.components() YIELD name, versions RETURN name, versions", "CALL"),
    ("call db.labels()", "CALL"),
])
def test_show_use_call_are_refused(neo4j_driver, query, word):
    message = dict(lm_tools._FORBIDDEN)[word]
    assert run_cypher_impl(query, "test-mcp") == {"error": message}


def test_keywords_inside_strings_and_unscoped_reads_still_run(neo4j_driver):
    """No lm scan-scope rule on this path, and the forbidden words are matched as clauses only."""
    r = run_cypher_impl("MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.code CONTAINS 'LOAD CSV' "
                        "OR c.name = 'call' OR c.code CONTAINS 'SHOW USE TERMINATE' RETURN count(c) AS n",
                        "test-mcp")
    assert "error" not in r and r["rows"] == [{"n": 0}]
    r = run_cypher_impl("MATCH (n:CpgFile) RETURN count(n) > 0 AS any", "test-mcp")   # unscoped: allowed
    assert "error" not in r, r
