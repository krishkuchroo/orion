"""Shared test setup and the guards for the live tests in Orion's own suite.

ORION_PERSIST_STRICT=1 for the whole test process (and every subprocess it starts): a persist whose
write counters disagree with the batch -- e.g. an edge whose endpoint is missing, which
MATCH...CREATE skips silently -- raises in tests, where a normal run only warns. setdefault, so an
explicit ORION_PERSIST_STRICT=0 on the command line still wins.

A live test asks for one of the guard fixtures, so a bare `pytest` on a machine without the service (or without
the opt-in) SKIPS it instead of failing, or worse, touching a shared database or spending Claude tokens.
"""
from __future__ import annotations

import os
import shutil
import uuid

import pytest

os.environ.setdefault("ORION_PERSIST_STRICT", "1")


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


@pytest.fixture
def neo4j_driver():
    """A driver to Orion's own Neo4j, or skip when it is not running."""
    from neo4j import GraphDatabase
    from orion import config
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        drv.verify_connectivity()
    except Exception as exc:  # noqa: BLE001
        drv.close()
        pytest.skip(f"Neo4j not reachable: {exc}")
    yield drv
    drv.close()


@pytest.fixture
def scan_ids(neo4j_driver):
    """Factory for throwaway scan_ids `test-<uuid>[-suffix]` (one uuid per test, so `.base` is a
    gc prefix that matches only this test's scans). Every id it handed out is deleted at teardown
    with a label-less match, so no label that carries the scan_id is left behind."""
    made: list[str] = []
    base = f"test-{uuid.uuid4()}"

    def make(suffix: str = "") -> str:
        sid = f"{base}-{suffix}" if suffix else base
        made.append(sid)
        return sid

    make.base = base
    yield make
    from orion import config
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        for sid in made:
            assert sid.startswith("test-")
            s.run("MATCH (n {scan_id:$sid}) DETACH DELETE n", sid=sid).consume()
