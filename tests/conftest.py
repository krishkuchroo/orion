"""Shared guards for the live tests in Orion's own suite.

A live test asks for one of these fixtures, so a bare `pytest` on a machine without the service (or without
the opt-in) SKIPS it instead of failing, or worse, touching a shared database or spending Claude tokens.
"""
import os
import shutil

import pytest


def _require_neo4j() -> None:
    """Skip unless Orion's Neo4j (config.NEO4J_URI) answers `GraphDB().ping()`."""
    from orion.graphdb import GraphDB
    try:
        db = GraphDB()
    except Exception as exc:  # bad URI / auth config
        pytest.skip(f"Neo4j not reachable: {type(exc).__name__}: {exc}")
    try:
        ok, why = db.ping(), "ping returned false"
    except Exception as exc:  # ServiceUnavailable, AuthError, ...
        ok, why = False, f"{type(exc).__name__}: {exc}"
    finally:
        db.close()
    if not ok:
        pytest.skip(f"Neo4j not reachable: {why}")


@pytest.fixture
def live_neo4j():
    """Skip unless Orion's Neo4j answers a ping."""
    _require_neo4j()


@pytest.fixture
def live_neo4j_writes():
    """A live Neo4j AND `ORION_LIVE_NEO4J=1`: the test writes to (or drops indexes on) the shared database, so it
    never runs just because a database happens to be up. The opt-in is checked first, before any connection."""
    if os.environ.get("ORION_LIVE_NEO4J") != "1":
        pytest.skip("writes to the shared Neo4j: set ORION_LIVE_NEO4J=1 to run it")
    _require_neo4j()


@pytest.fixture
def spend_tokens():
    """Skip unless `ORION_SPEND_TOKENS=1` and the `claude` CLI is on PATH: the test spawns a real `claude -p`."""
    if os.environ.get("ORION_SPEND_TOKENS") != "1":
        pytest.skip("spends Claude tokens: set ORION_SPEND_TOKENS=1 to run it")
    if shutil.which("claude") is None:
        pytest.skip("the claude CLI is not on PATH")
