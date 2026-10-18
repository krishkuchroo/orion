"""Token-free tests for orion.lm.tools: scan-scoped, EXPLAIN-validated run_cypher and sandboxed
read_code. Uses a StubDB, so no Neo4j is needed."""
from __future__ import annotations

from orion.lm import tools


class StubDB:
    def __init__(self): self.ran = []
    def run_cypher(self, scan_id, query, limit=50):
        self.ran.append(query)
        if query.startswith("EXPLAIN"):
            return {"error": "SyntaxError: bad"} if "BADSYNTAX" in query else {"row_count": 0, "rows": []}
        return {"row_count": 1, "rows": [{"n": 1}]}


def test_run_cypher_blocks_writes_and_calls():
    db = StubDB()
    assert "error" in tools.run_cypher(db, "s", "MATCH (n) SET n.x=1 RETURN n")
    assert "error" in tools.run_cypher(db, "s", "CALL db.labels()")
    assert db.ran == []  # neither reached EXPLAIN/execution


SCOPED = "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code"


def test_run_cypher_explains_before_running_and_caps_rows():
    db = StubDB()
    out = tools.run_cypher(db, "s", SCOPED)
    assert out["rows"] == [{"n": 1}]
    assert db.ran[0].startswith("EXPLAIN ")          # validated first
    assert any(not q.startswith("EXPLAIN") for q in db.ran)


def test_run_cypher_returns_explain_error():
    db = StubDB()
    assert "error" in tools.run_cypher(db, "s", "MATCH (c:CpgCall {scan_id:$scan_id}) BADSYNTAX RETURN c")


def test_run_cypher_rejects_unscoped_patterns():
    db = StubDB()
    assert "error" in tools.run_cypher(db, "s", "MATCH (n) RETURN n")                       # no label, no scope
    assert "error" in tools.run_cypher(db, "s", "MATCH (c:CpgCall) RETURN c.code")           # label, no scope
    assert "error" in tools.run_cypher(db, "s", "MATCH (c:CpgCall {scan_id:'other'}) RETURN c")  # literal scan
    assert "error" in tools.run_cypher(db, "s",
        "MATCH (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO]->(k:CpgCall) RETURN k")           # second pattern unscoped
    assert db.ran == []
    assert "rows" in tools.run_cypher(db, "s",
        "MATCH (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO*1..3]->(k:CpgCall {scan_id:$scan_id}) RETURN k.code")
    assert "rows" in tools.run_cypher(db, "s",
        "MATCH (c:CpgCall {scan_id:$scan_id}) WITH c MATCH (c)-[:CONTAINS_CALL]-(m) RETURN m")  # (c) rebound: ok


def test_read_code_rejects_escape(tmp_path):
    (tmp_path / "a.js").write_text("line1\nline2\nline3\n")
    assert "error" in tools.read_code(str(tmp_path), "../etc/passwd", 1, 2)
    assert "error" in tools.read_code(str(tmp_path), "/etc/passwd", 1, 2)
    ok = tools.read_code(str(tmp_path), "a.js", 1, 2)
    assert "line1" in ok["lines"]


# --- extra hardening (beyond the brief) ---

def test_string_literals_cannot_fool_the_scope_or_call_guards():
    db = StubDB()
    assert "rows" in tools.run_cypher(
        db, "s", "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.code CONTAINS '(n)' RETURN c")
    assert "rows" in tools.run_cypher(
        db, "s", "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.code CONTAINS 'CALL x' RETURN count(c)")
    assert "error" in tools.run_cypher(
        db, "s", "MATCH (c:CpgCall {x:'scan_id:$scan_id'}) RETURN c")


def test_error_names_offending_pattern_and_standalone_empty_rejected():
    db = StubDB()
    out = tools.run_cypher(db, "s", "MATCH (c:CpgCall) RETURN c")
    assert "(c:CpgCall)" in out["error"]
    assert "error" in tools.run_cypher(db, "s", "MATCH () RETURN 1")


def test_read_code_symlink_escape_and_window(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("s\n")
    (repo / "link").symlink_to(outside)
    assert "error" in tools.read_code(str(repo), "link", 1, 1)
    (repo / "big.js").write_text("\n".join(str(i) for i in range(1000)))
    out = tools.read_code(str(repo), "big.js", 1, 900)
    assert out["end"] - out["start"] < 300
    assert "error" in tools.read_code(str(repo), "missing.js", 1, 2)


# --- review fixes: scope-guard bypasses ---
import pytest

_BAD = [
    "MATCH (c:CpgCall {scan_id:$scan_id}) // (\nMATCH (y:CpgCall) RETURN y",
    "MATCH (c:CpgCall {scan_id:$scan_id}) /* ( */ MATCH (y:CpgCall) RETURN y",
    "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.`(` AS a MATCH (y:CpgCall) RETURN y",
    "MATCH (`x(`:CpgCall) RETURN 1",
    "MATCH (c:CpgCall {scan_id:$scan_id}) OPTIONAL MATCH (y:CpgCall) RETURN y",
    "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c UNION MATCH (y:CpgCall) RETURN y",
    "MATCH (c:CpgCall {scan_id:$scan_id}) MATCH (y:CpgCall) RETURN y",
    "MATCH (c:CpgCall {a:{scan_id:$scan_id}}) RETURN c",
    "MATCH (c:CpgCall {scan_id:$scan_id + 'z'}) RETURN c",
    "MATCH (c:CpgCall {scan_id:$scan_id}) /* unterminated MATCH (y:CpgCall) RETURN y",
    "MATCH (c:CpgCall {scan_id:$scan_id} RETURN c",
]


@pytest.mark.parametrize("q", _BAD)
def test_scope_bypass_probes_rejected(q):
    db = StubDB()
    assert "error" in tools.run_cypher(db, "s", q), q
    assert db.ran == []


@pytest.mark.parametrize("q", [
    "MATCH (c:`CpgCall` {scan_id:$scan_id}) RETURN c",
    "MATCH (c:CpgCall { scan_id : $scan_id }) RETURN c",
    "MATCH (c:CpgCall {name:'a,b', scan_id:$scan_id}) RETURN c  // ok comment",
    "MATCH (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO*]-(m) RETURN m",
])
def test_scope_probes_accepted(q):
    assert "rows" in tools.run_cypher(StubDB(), "s", q), q


def test_read_code_bad_args(tmp_path):
    (tmp_path / "a.js").write_text("x\n")
    assert "error" in tools.read_code(str(tmp_path), "a\0.js", 1, 2)
    assert "error" in tools.read_code(str(tmp_path), "a.js", "x", 2)
    assert "error" in tools.read_code(str(tmp_path), "a.js", 5, 2)
