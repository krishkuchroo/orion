"""The MCP tool server: the ONLY way a discovery or verifier agent touches the graph or the
semantic index. Three tools, all read-only.

`run_cypher` delegates straight to GraphDB (write-keyword guard and scan_id binding live there,
not here). `semantic_search` imports `orion.embed` lazily and tolerates it being unimplemented
or empty — Task E builds that module in parallel, and this server must not crash on startup or
on a call just because the semantic index isn't ready yet. `get_schema` reflects Orion's own
frozen CPG vocabulary (schema.py), so unlike the other two it is not scan_id-scoped.

Each tool's logic lives in a plain module-level `*_impl` function so tests can call it directly
without going through FastMCP/stdio. The `@mcp.tool()`-decorated functions are thin wrappers.
"""
from __future__ import annotations

from fastmcp import FastMCP

from .graphdb import GraphDB

mcp = FastMCP("orion")

# One GraphDB, opened lazily and reused across calls (a fresh driver per call would be wasteful
# and would defeat neo4j's own connection pooling).
_db: GraphDB | None = None


def _get_db() -> GraphDB:
    global _db
    if _db is None:
        _db = GraphDB()
    return _db


def run_cypher_impl(query: str, scan_id: str) -> dict:
    """Delegates to GraphDB().run_cypher. Returns {"row_count","rows"} or {"error"}."""
    return _get_db().run_cypher(scan_id, query)


def get_schema_impl() -> dict:
    """Delegates to GraphDB().schema(). Returns {"node_properties","relationship_properties"}."""
    return _get_db().schema()


def semantic_search_impl(query: str, scan_id: str, k: int = 5) -> list[dict]:
    """Nearest code chunks for `query`, or a one-element `_note` list if the semantic index
    isn't ready yet (Task E builds orion/embed.py in parallel; this must never crash)."""
    try:
        from . import embed  # lazy: embed may be unimplemented or absent at import time
        results = embed.search(query, scan_id, k)
        if not results:
            return [{"_note": "semantic index unavailable: no results"}]
        return results
    except (NotImplementedError, ImportError, TypeError) as exc:
        return [{"_note": f"semantic index unavailable: {exc}"}]
    except Exception as exc:  # noqa: BLE001 — any other embed failure must not crash the server
        return [{"_note": f"semantic index unavailable: {exc.__class__.__name__}: {exc}"}]


@mcp.tool()
def run_cypher(query: str, scan_id: str) -> dict:
    """Run a read-only Cypher query scoped to one scan_id. Write keywords are blocked."""
    return run_cypher_impl(query, scan_id)


@mcp.tool()
def semantic_search(query: str, scan_id: str, k: int = 5) -> list[dict]:
    """Nearest code chunks to `query` in the given scan, by meaning (not structure)."""
    return semantic_search_impl(query, scan_id, k)


@mcp.tool()
def get_schema() -> dict:
    """Node labels/properties and relationship types/properties in the graph. Same shape
    regardless of scan_id — this is Orion's own fixed CPG vocabulary, not the target repo's."""
    return get_schema_impl()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
