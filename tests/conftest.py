"""Shared test setup.

ORION_PERSIST_STRICT=1 for the whole test process (and every subprocess it starts): a persist whose
write counters disagree with the batch -- e.g. an edge whose endpoint is missing, which
MATCH...CREATE skips silently -- raises in tests, where a normal run only warns. setdefault, so an
explicit ORION_PERSIST_STRICT=0 on the command line still wins.
"""
from __future__ import annotations

import os
import uuid

import pytest

os.environ.setdefault("ORION_PERSIST_STRICT", "1")


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
