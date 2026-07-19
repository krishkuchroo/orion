"""Read-only Neo4j access: the grounding tool.

Every agent claim has to be backed by a query result from here. Write keywords are blocked, so
an agent (discovery or verifier) can read the graph but never mutate it. This is the single tool
that keeps the agents honest: they must query for a vulnerability, not assert it.

The MCP server (orion/mcp_server.py) wraps `run_cypher` as the read-only tool the agents call.
The safety contract lives here: read only, scoped to one scan_id. `clear_scan` is the one write,
and it is NOT agent-reachable — only the harness calls it, at the start of a build.
"""
from __future__ import annotations

import re

from neo4j import GraphDatabase

from . import config

_WRITE = re.compile(r"\b(CREATE|MERGE|DELETE|SET|REMOVE|DROP|DETACH)\b", re.IGNORECASE)
# Cypher string literals ('...' or "..."), escaped-quote aware. Blanked before the write-keyword
# scan so a legitimate READ query that searches source text for DML words -- e.g.
# `WHERE c.code CONTAINS 'SET role=admin'` (a natural SQLi-hunting query for a security scanner) --
# is not falsely rejected. Structural writes (SET n.x=1) are outside any literal and still caught.
_STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")


def _has_write_keyword(query: str) -> bool:
    """True if `query` contains a Cypher write clause OUTSIDE any string literal. Pure/testable."""
    return bool(_WRITE.search(_STRING_LITERAL.sub("''", query)))


class GraphDB:
    """A thin read-only wrapper over the scan graph (plus a single-scan clear for reloads)."""

    def __init__(self) -> None:
        self._driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)

    def close(self) -> None:
        self._driver.close()

    def ping(self) -> bool:
        with self._driver.session(database=config.NEO4J_DATABASE) as s:
            return s.run("RETURN 1 AS ok").single()["ok"] == 1

    def files(self, scan_id: str) -> list[str]:
        """The BFS scaffold: the file list handed to the agent up front (deterministic)."""
        with self._driver.session(database=config.NEO4J_DATABASE) as s:
            rows = s.run(
                "MATCH (f:CpgFile {scan_id:$scan_id}) RETURN f.file_path AS p ORDER BY p",
                scan_id=scan_id,
            )
            return [r["p"] for r in rows]

    def clear_scan(self, scan_id: str) -> None:
        """Single-scan lifecycle: remove everything for this scan before a reload (idempotent).

        Not agent-reachable — agents go through `run_cypher`, which blocks writes. The harness
        calls this directly at the start of a build so each scan is self-contained.
        """
        with self._driver.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n {scan_id:$scan_id}) DETACH DELETE n", scan_id=scan_id)

    def schema(self) -> dict:
        """Node labels/properties and relationship types/properties, via Neo4j's built-in
        `db.schema.*` procedures (no APOC — Orion's compose stack doesn't install it). This is
        Orion's own frozen CPG vocabulary (schema.py's NODE_KEY set), not the target repo's
        structure, so the shape is identical regardless of which repo was scanned; unlike
        run_cypher/semantic_search it is intentionally not scan_id-scoped."""
        with self._driver.session(database=config.NEO4J_DATABASE) as s:
            node_properties = [dict(r) for r in s.run("CALL db.schema.nodeTypeProperties()")]
            relationship_properties = [dict(r) for r in s.run("CALL db.schema.relTypeProperties()")]
            return {
                "node_properties": node_properties,
                "relationship_properties": relationship_properties,
            }

    def run_cypher(self, scan_id: str, query: str, limit: int = 50) -> dict:
        """One read-only query. Returns {row_count, rows} or {error}. The scan_id is bound as a
        parameter so the agent's query is always scoped to one scan."""
        if _has_write_keyword(query):
            return {"error": "read-only: write keywords are blocked"}
        try:
            with self._driver.session(database=config.NEO4J_DATABASE) as s:
                rows = [dict(r) for r in s.run(query, scan_id=scan_id)]
                return {"row_count": len(rows), "rows": rows[:limit]}
        except Exception as exc:  # surface the Cypher error straight back to the agent
            return {"error": f"{exc.__class__.__name__}: {exc}"}
