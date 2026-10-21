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


def test_quote_inside_backtick_or_comment_cannot_hide_a_write():
    # Strings, comments and backtick identifiers are blanked in ONE left-to-right pass, so a quote
    # inside a backtick identifier or a comment can no longer open a fake "string" that hides DELETE.
    for q in (
        "MATCH (n WHERE true) WITH n AS `'` DETACH DELETE `'`",
        'MATCH (n) WITH n AS `"` DETACH DELETE n',
        "MATCH (n) // it's a comment\nDETACH DELETE n RETURN 'x'",
        "MATCH (n) /* don't */ DETACH DELETE n RETURN 'x'",
        "MATCH (n) WITH n AS `x DETACH DELETE n",          # unterminated backtick stays visible
    ):
        assert _has_write_keyword(q), q


def test_write_word_as_identifier_or_comment_is_not_a_write():
    assert not _has_write_keyword("MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code AS `DELETE`")
    assert not _has_write_keyword("MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c // never DELETE")


# --- GraphDB.run_cypher wiring, against a fake driver (no Neo4j) ---
from types import SimpleNamespace

import neo4j

from orion import graphdb


class _FakeResult:
    def __init__(self, rows, qtype):
        self._rows, self.qtype, self.fetched, self.consumed = list(rows), qtype, 0, False

    def __iter__(self):
        while self._rows:
            self.fetched += 1
            yield self._rows.pop(0)

    def fetch(self, n):
        out, self._rows = self._rows[:n], self._rows[n:]
        self.fetched += len(out)
        return out

    def peek(self):
        return self._rows[0] if self._rows else None

    def consume(self):
        self.consumed = True
        return SimpleNamespace(query_type=self.qtype)


class _FakeDriver:
    def __init__(self, rows, qtype="r"):
        self.rows, self.qtype, self.session_kwargs, self.queries, self.results = rows, qtype, [], [], []

    def session(self, **kw):
        self.session_kwargs.append(kw)
        drv = self

        class _S:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def run(self, query, **params):
                drv.queries.append((query, params))
                res = _FakeResult(drv.rows, drv.qtype)
                drv.results.append(res)
                return res
        return _S()

    def close(self):
        pass


def _db_with(monkeypatch, rows, qtype="r"):
    fake = _FakeDriver(rows, qtype)
    monkeypatch.setattr(graphdb.GraphDatabase, "driver", lambda *a, **k: fake)
    return graphdb.GraphDB(), fake


def test_run_cypher_uses_a_read_access_session(monkeypatch):
    db, fake = _db_with(monkeypatch, [{"c": 1}])
    db.run_cypher("s", "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN 1 AS c")
    assert fake.session_kwargs and all(
        kw.get("default_access_mode") == neo4j.READ_ACCESS for kw in fake.session_kwargs)


def test_default_run_cypher_keeps_its_row_count_and_has_no_timeout(monkeypatch):
    # orion scan (MCP agents, verify, runtime) behaviour is unchanged apart from the read session.
    db, fake = _db_with(monkeypatch, [{"i": i} for i in range(80)])
    out = db.run_cypher("s", "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.line AS i")
    assert out == {"row_count": 80, "rows": [{"i": i} for i in range(50)]}
    query, params = fake.queries[0]
    assert params == {"scan_id": "s"}
    assert getattr(query, "timeout", None) is None


def test_bounded_run_cypher_fetches_at_most_limit_with_timeout_and_query_type(monkeypatch):
    db, fake = _db_with(monkeypatch, [{"i": i} for i in range(1000)])
    out = db.run_cypher("s", "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.line AS i", limit=5,
                        timeout=10, bounded=True)
    assert out == {"row_count": 5, "rows": [{"i": i} for i in range(5)], "truncated": True,
                   "query_type": "r"}
    assert fake.results[0].fetched == 5 and fake.results[0].consumed
    assert isinstance(fake.queries[0][0], neo4j.Query) and fake.queries[0][0].timeout == 10


def test_bounded_run_cypher_not_truncated_when_all_rows_fit(monkeypatch):
    db, _ = _db_with(monkeypatch, [{"i": 1}, {"i": 2}], qtype="r")
    out = db.run_cypher("s", "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.line AS i", limit=5,
                        bounded=True)
    assert out["truncated"] is False and out["row_count"] == 2
