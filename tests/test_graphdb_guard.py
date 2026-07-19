"""The read-only write-guard: structural writes are blocked, but a write KEYWORD inside a string
literal (a legitimate read query searching source text for DML) is not falsely rejected.

Pure — exercises `graphdb._has_write_keyword` directly, no Neo4j needed.
"""
from __future__ import annotations

from orion.graphdb import _has_write_keyword


def test_structural_writes_are_blocked():
    for q in (
        "CREATE (n) RETURN n",
        "MATCH (n {scan_id:$scan_id}) SET n.x = 1 RETURN n",
        "MATCH (n) DETACH DELETE n",
        "MERGE (n:X {a:1})",
        "MATCH (n) REMOVE n.p",
    ):
        assert _has_write_keyword(q), q


def test_write_keyword_inside_string_literal_is_allowed():
    # A security scanner legitimately hunts SQLi/command-injection sinks by searching CpgCall.code
    # for DML words — these are READS and must not be blocked.
    for q in (
        "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.code CONTAINS 'SET role=admin' RETURN c",
        'MATCH (c) WHERE c.code CONTAINS "DELETE FROM users" RETURN c',
        "MATCH (c) WHERE c.code CONTAINS 'CREATE TABLE t' RETURN c.code",
        "MATCH (c) WHERE c.code =~ '.*DROP .*' RETURN c",
    ):
        assert not _has_write_keyword(q), q


def test_plain_read_is_allowed():
    assert not _has_write_keyword(
        "MATCH (f:CpgFile {scan_id:$scan_id}) RETURN f.file_path ORDER BY f.file_path"
    )
