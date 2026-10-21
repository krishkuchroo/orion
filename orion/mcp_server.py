"""The MCP tool server: the ONLY way a discovery or verifier agent touches the graph or the
semantic index. Four read-only tools (`exploit_search` is verifier-only, gated by the allowlist in
claude_cli.py, not here).

`run_cypher` delegates to GraphDB (write-keyword guard, READ-access session and scan_id binding live
there) after refusing the clauses that reach past the graph -- LOAD CSV, SHOW, TERMINATE, USE, CALL
-- which a read session still runs (see `_forbidden_clause`). `semantic_search` imports `orion.embed`
lazily and tolerates it being unimplemented
or empty — Task E builds that module in parallel, and this server must not crash on startup or
on a call just because the semantic index isn't ready yet. `get_schema` reflects Orion's own
frozen CPG vocabulary (schema.py), so unlike the other two it is not scan_id-scoped.

Each tool's logic lives in a plain module-level `*_impl` function so tests can call it directly
without going through FastMCP/stdio. The `@mcp.tool()`-decorated functions are thin wrappers.
"""
from __future__ import annotations

from fastmcp import FastMCP

from .graphdb import GraphDB, blank
from .lm import tools as lm_tools

mcp = FastMCP("orion")

# Clauses a discovery/verifier query never needs and a READ-access session still runs: LOAD CSV makes
# the Neo4j SERVER fetch a URL (a prompt injection in a scanned repo could send data out in it), SHOW
# / TERMINATE TRANSACTIONS list or kill other sessions' transactions, USE switches database, CALL runs
# procedures. The rule and its messages are the Orion-LM tool's (orion/lm/tools.py), reused, not
# copied. Its scan-scope and syntax rules are deliberately NOT applied: Claude's queries legitimately
# differ (unscoped label scans, UNION, ...), and the two paths need not behave the same.
_MCP_FORBIDDEN = ("LOAD", "SHOW", "TERMINATE", "USE", "CALL")
_FORBIDDEN_RE = [(rx, msg) for (word, _msg), (rx, msg) in zip(lm_tools._FORBIDDEN, lm_tools._FORBIDDEN_RE)
                 if word in _MCP_FORBIDDEN]


def _forbidden_clause(query: str) -> str | None:
    """The message for the first forbidden clause in `query`, or None. Matched on the blanked text
    (strings, comments, backtick names removed), so `c.code CONTAINS 'LOAD CSV'` is still allowed."""
    text = blank(query)
    for rx, msg in _FORBIDDEN_RE:
        if rx.search(text):
            return msg
    return None

# One GraphDB, opened lazily and reused across calls (a fresh driver per call would be wasteful
# and would defeat neo4j's own connection pooling).
_db: GraphDB | None = None


def _get_db() -> GraphDB:
    global _db
    if _db is None:
        _db = GraphDB()
    return _db


def run_cypher_impl(query: str, scan_id: str) -> dict:
    """Refuses a forbidden clause before Neo4j sees the query, else delegates to
    GraphDB().run_cypher. Returns {"row_count","rows"} or {"error"}."""
    bad = _forbidden_clause(query)
    if bad is not None:
        return {"error": bad}
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


def exploit_search_impl(query: str, k: int = 5) -> list[dict]:
    """Nearest exploit-reference modules for `query` from the GLOBAL Metasploit corpus (not
    scan-scoped), or a one-element `_note` list if the corpus isn't indexed yet. ADVISORY -- a real
    published exploit reference, never proof the target is vulnerable. Never crashes the server."""
    try:
        from . import embed  # lazy: embed pulls the driver + (on demand) the embedding model
        results = embed.exploit_search(query, k)
        if not results:
            return [{"_note": "exploit corpus unavailable: not indexed (run `orion index-exploits`)"}]
        return results
    except (NotImplementedError, ImportError, TypeError) as exc:
        return [{"_note": f"exploit corpus unavailable: {exc}"}]
    except Exception as exc:  # noqa: BLE001 — any other embed failure must not crash the server
        return [{"_note": f"exploit corpus unavailable: {exc.__class__.__name__}: {exc}"}]


@mcp.tool()
def run_cypher(query: str, scan_id: str) -> dict:
    """Run a read-only Cypher query scoped to one scan_id. Write keywords and LOAD CSV / SHOW /
    TERMINATE / USE / CALL are blocked."""
    return run_cypher_impl(query, scan_id)


@mcp.tool()
def exploit_search(query: str, k: int = 5) -> list[dict]:
    """Search the global Metasploit exploit-reference corpus by meaning. ADVISORY: a real published
    exploit reference, NEVER proof the target is vulnerable. Not scan-scoped."""
    return exploit_search_impl(query, k)


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
