"""Token-free tests for orion.lm.tools: scan-scoped, EXPLAIN-validated run_cypher and sandboxed
read_code. Uses a StubDB, so no Neo4j is needed."""
from __future__ import annotations

from orion.lm import tools


class StubDB:
    """Stands in for GraphDB. EXPLAIN answers with the planner's query type ("r" = read-only), the way
    GraphDB.run_cypher(..., bounded=True) does; `qtype=None` models a db that does not report it."""
    def __init__(self, qtype="r", truncated=False):
        self.ran, self.kwargs, self.qtype, self.truncated = [], [], qtype, truncated

    def run_cypher(self, scan_id, query, limit=50, **kw):
        self.ran.append(query)
        self.kwargs.append(kw)
        if query.startswith("EXPLAIN"):
            if "BADSYNTAX" in query:
                return {"error": "SyntaxError: bad"}
            out = {"row_count": 0, "rows": []}
            if self.qtype is not None:
                out["query_type"] = self.qtype
            return out
        return {"row_count": 1, "rows": [{"n": 1}], "truncated": self.truncated, "query_type": "r"}


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
    # A bound variable is re-scoped, not trusted: the bare `(c)` reuse form used to be accepted and is
    # now rejected (cross-clause "already bound" trust was the WITH/UNION rebinding hole).
    assert "rows" in tools.run_cypher(db, "s",
        "MATCH (c:CpgCall {scan_id:$scan_id}) WITH c "
        "MATCH (c:CpgCall {scan_id:$scan_id})-[:CONTAINS_CALL]-(m) RETURN m")
    assert "error" in tools.run_cypher(db, "s",
        "MATCH (c:CpgCall {scan_id:$scan_id}) WITH c MATCH (c)-[:CONTAINS_CALL]-(m) RETURN m")


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
    # was `-[:FLOWS_TO*]-` (unbounded) -- now rejected; bounded var-length is the accepted form
    "MATCH (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO*1..3]-(m) RETURN m",
])
def test_scope_probes_accepted(q):
    assert "rows" in tools.run_cypher(StubDB(), "s", q), q


def test_read_code_bad_args(tmp_path):
    (tmp_path / "a.js").write_text("x\n")
    assert "error" in tools.read_code(str(tmp_path), "a\0.js", 1, 2)
    assert "error" in tools.read_code(str(tmp_path), "a.js", "x", 2)
    assert "error" in tools.read_code(str(tmp_path), "a.js", 5, 2)


# --- security review: confirmed bypasses (write, scope, limits). Every one must be rejected BEFORE the
# query reaches the database (db.ran == [], i.e. not even EXPLAIN runs). ---

S = "{scan_id:$scan_id}"

_BYPASSES = {
    # write hidden by a quote inside a backtick identifier (also hit the Claude MCP path)
    "backtick_quote_write": "MATCH (n WHERE true) WITH n AS `'` DETACH DELETE `'`",
    "comment_quote_write": "MATCH (n:CpgCall %s) // it's\nDETACH DELETE n RETURN 'x'" % S,
    # inline WHERE / IS inside a node pattern (Cypher 5)
    "inline_where_node": "MATCH (n WHERE n:CpgCall) RETURN n.scan_id, n.code",
    "inline_where_true": "MATCH (n WHERE true) RETURN n",
    "inline_where_scoped": "MATCH (n:CpgCall %s WHERE n.line > 0) RETURN n" % S,
    "IS_label": "MATCH (n IS CpgCall) RETURN n",
    "count_subquery_inline_where": "RETURN COUNT { MATCH (n WHERE n.scan_id <> $scan_id) } AS other",
    # variable rebinding across WITH / UNION / comprehensions
    "WITH_rebind": "MATCH (a:CpgCall %s) WITH count(a) AS k MATCH (a) RETURN a" % S,
    "WITH_rebind_limit": "MATCH (a:CpgCall %s) WITH a LIMIT 1 WITH 1 AS z MATCH (a)-->(m) RETURN m" % S,
    "UNION_rebind": "MATCH (a:CpgCall %s) RETURN a UNION MATCH (a) RETURN a" % S,
    "comprehension_leak": "MATCH (a:CpgCall %s) WITH [(a)-->(b) | b] AS xs MATCH (b) RETURN b" % S,
    "paren_wrapped_comprehension": "MATCH (a:CpgCall %s) RETURN ([(x:CpgCall)-->(y) | y.code])" % S,
    "pattern_in_node_props": "MATCH (a:CpgCall {scan_id:$scan_id, code:head([(b:CpgCall)-->(c) | c.code])}) RETURN a",
    "no_space_after_MATCH": "MATCH(n:CpgCall) RETURN n.code",
    "selector_single_node": "MATCH ANY (a) RETURN a",
    "selector_no_space": "MATCH p = ANY SHORTEST(a:CpgCall)-[:FLOWS_TO*1..3]-(b) RETURN b",
    # duplicate scan_id key (last one wins in Neo4j)
    "dup_key": "MATCH (n:CpgCall {scan_id:$scan_id, scan_id:'other'}) RETURN n",
    "dup_key_backtick": "MATCH (n:CpgCall {scan_id:$scan_id, `scan_id`:'other'}) RETURN n",
    "dup_key_labelless": "MATCH (c:CpgCall %s)-->(m {scan_id:$scan_id, scan_id:'x'}) RETURN m" % S,
    # external access / admin / procedures
    "LOAD_CSV_http": "LOAD CSV FROM 'http://example.invalid/x' AS row RETURN row",
    "LOAD_CSV_file": "LOAD CSV FROM 'file:///etc/passwd' AS row RETURN row",
    "SHOW_TRANSACTIONS": "SHOW TRANSACTIONS",
    "TERMINATE": "TERMINATE TRANSACTIONS 'neo4j-transaction-1'",
    "USE": "USE neo4j MATCH (c:CpgCall %s) RETURN c" % S,
    "FOREACH": "MATCH (a:CpgCall %s) FOREACH (x IN [1] | MERGE (:Foo)) RETURN a" % S,
    "apoc_fn": "RETURN apoc.cypher.runFirstColumnMany('MATCH (n) RETURN n', {}) AS x",
    "apoc_fn_backticks": "RETURN `apoc`.`cypher`.runFirstColumnMany('MATCH (n) RETURN n', {}) AS x",
    "backtick_fn_name": "RETURN `apoc.cypher.runFirstColumnMany`('MATCH (n) RETURN n', {}) AS x",
    "db_fn": "MATCH (c:CpgCall %s) RETURN db.nameFromElementId(elementId(c)) AS x" % S,
    "dbms_fn": "RETURN dbms.components() AS x",
    "gds_fn": "RETURN gds.version() AS x",
    "call_subquery": "MATCH (c:CpgCall %s) CALL { MATCH (x:CpgCall %s) RETURN x } RETURN x" % (S, S),
    "exists_subquery": "MATCH (c:CpgCall %s) WHERE EXISTS { MATCH (c:CpgCall %s)-->(m) } RETURN c" % (S, S),
    "collect_subquery": "MATCH (c:CpgCall %s) RETURN COLLECT { MATCH (x:CpgCall %s) RETURN x.code } AS xs" % (S, S),
    # unbounded / too-long paths
    "var_len_star": "MATCH (c:CpgCall %s)-[:FLOWS_TO*]-(m) RETURN m" % S,
    "var_len_open_upper": "MATCH (c:CpgCall %s)-[:FLOWS_TO*1..]-(m) RETURN m" % S,
    "var_len_upper_20": "MATCH (c:CpgCall %s)-[*..20]-(m) RETURN m" % S,
    "var_len_exact_13": "MATCH (c:CpgCall %s)-[:FLOWS_TO*13]-(m) RETURN m" % S,
    "shortestPath_unbounded": "MATCH p=shortestPath((a:CpgCall %s)-[*]-(b)) RETURN b" % S,
    "quantified_rel_plus": "MATCH (a:CpgCall %s)-[:FLOWS_TO]->+(b:CpgCall %s) RETURN b" % (S, S),
    "quantified_rel_braces": "MATCH (a:CpgCall %s)-[:FLOWS_TO]->{1,3}(b:CpgCall %s) RETURN b" % (S, S),
    "qpp": "MATCH (a:CpgCall %s) ((x:CpgCall %s)-->(y)){1,3} (b:CpgCall %s) RETURN b" % (S, S, S),
    "rel_inline_where": "MATCH (a:CpgCall %s)-[r WHERE (r.x) = 1]->(b) RETURN b" % S,
}


@pytest.mark.parametrize("name", sorted(_BYPASSES))
def test_review_bypasses_rejected_before_the_database(name):
    db = StubDB()
    out = tools.run_cypher(db, "s", _BYPASSES[name])
    assert "error" in out, (name, out)
    assert db.ran == [], name


_ACCEPTED = {
    "basic": "MATCH (c:CpgCall %s) RETURN c.code" % S,
    "rescoped_bound_var": "MATCH (c:CpgCall %s) WITH c MATCH (c:CpgCall %s)-[:CONTAINS_CALL]-(m) RETURN m" % (S, S),
    "labelless_neighbour": "MATCH (c:CpgCall %s)-[:FLOWS_TO]->(m) RETURN m.code" % S,
    "labelless_long_path": "MATCH (c:CpgCall %s)<-[:CONTAINS_CALL]-(m)-[:DEFINED_IN]->(f) RETURN f" % S,
    "labelless_scoped_alone": "MATCH (n %s) RETURN count(n) AS c" % S,
    "var_len_bounded": "MATCH (c:CpgCall %s)-[:FLOWS_TO*1..3]-(m) RETURN m" % S,
    "var_len_upper_12": "MATCH (c:CpgCall %s)-[:FLOWS_TO*..12]->(m) RETURN m" % S,
    "var_len_exact": "MATCH (c:CpgCall %s)-[:FLOWS_TO*3]->(m) RETURN m" % S,
    "rel_type_alternatives": "MATCH (c:CpgCall %s)-[r:FLOWS_TO|RESOLVES_TO]->(m) RETURN type(r)" % S,
    "shortestPath_bounded": "MATCH p=shortestPath((a:CpgCall %s)-[*..12]-(b:CpgCall %s)) RETURN length(p)" % (S, S),
    "scoped_pattern_predicate": "MATCH (c:CpgCall %s) WHERE NOT (c:CpgCall %s)-[:FLOWS_TO]->() RETURN c" % (S, S),
    "scoped_comprehension": "MATCH (a:CpgCall %s) RETURN [(a:CpgCall %s)-->(b) | b.code] AS xs" % (S, S),
    "functions": "MATCH (c:CpgCall %s) RETURN count(c), collect({f: c.file_path})[..3], size(c.code)" % S,
    "list_predicate": "MATCH p=(a:CpgCall %s)-[:FLOWS_TO*1..4]->(b) WHERE any(x IN nodes(p) WHERE x.line > 0) RETURN p" % S,
    "is_null_outside_parens": "MATCH (c:CpgCall %s) WHERE c.file_path IS NOT NULL RETURN c" % S,
    "keywords_in_strings": "MATCH (c:CpgCall %s) WHERE c.code CONTAINS 'UNION (n WHERE x) LOAD CSV apoc.x(' RETURN c" % S,
    "map_projection": "MATCH (c:CpgCall %s) RETURN c {.code, .line} AS c" % S,
    "builtin_namespace": "MATCH (c:CpgCall %s) RETURN c.code, date.truncate('day', date()) AS d" % S,
    "arithmetic_parens": "MATCH (c:CpgCall %s) RETURN (c.line + 1) * 2 AS x" % S,
    "order_limit": "MATCH (c:CpgCall %s) WHERE c.line > 3 RETURN c.code ORDER BY c.line DESC LIMIT 5" % S,
}


@pytest.mark.parametrize("name", sorted(_ACCEPTED))
def test_legitimate_scoped_queries_still_accepted(name):
    out = tools.run_cypher(StubDB(), "s", _ACCEPTED[name])
    assert "rows" in out, (name, out)


def test_error_messages_name_the_offending_part():
    db = StubDB()
    assert "(n WHERE n:CpgCall)" in tools.run_cypher(db, "s", _BYPASSES["inline_where_node"])["error"]
    assert "WHERE clause" in tools.run_cypher(db, "s", _BYPASSES["inline_where_node"])["error"]
    assert "[:FLOWS_TO*]" in tools.run_cypher(db, "s", _BYPASSES["var_len_star"])["error"]
    assert "12" in tools.run_cypher(db, "s", _BYPASSES["var_len_upper_20"])["error"]
    assert "UNION" in tools.run_cypher(db, "s", _BYPASSES["UNION_rebind"])["error"]
    assert "scan_id" in tools.run_cypher(db, "s", _BYPASSES["dup_key"])["error"]
    assert "apoc.cypher.runFirstColumnMany" in tools.run_cypher(db, "s", _BYPASSES["apoc_fn"])["error"]
    assert "LOAD" in tools.run_cypher(db, "s", _BYPASSES["LOAD_CSV_http"])["error"]
    err = tools.run_cypher(db, "s", _BYPASSES["WITH_rebind"])["error"]
    assert "(a)" in err and "{scan_id:$scan_id}" in err
    # the shown pattern is the query as written (string literals intact), not the blanked text
    err = tools.run_cypher(db, "s", "MATCH (c:CpgCall {name:'exec'}) RETURN c")["error"]
    assert "(c:CpgCall {name:'exec'})" in err


def test_explain_query_type_must_be_read_only():
    for qtype in ("w", "rw", "s", None):          # None: the db did not report a type -> fail closed
        db = StubDB(qtype=qtype)
        out = tools.run_cypher(db, "s", SCOPED)
        assert "error" in out and "read-only" in out["error"], (qtype, out)
        assert len(db.ran) == 1 and db.ran[0].startswith("EXPLAIN ")   # the real query never ran


def test_queries_run_bounded_with_a_timeout():
    db = StubDB()
    tools.run_cypher(db, "s", SCOPED, limit=7)
    assert tools.QUERY_TIMEOUT_S == 10
    assert len(db.kwargs) == 2
    for kw in db.kwargs:                          # both EXPLAIN and the real query
        assert kw.get("timeout") == tools.QUERY_TIMEOUT_S and kw.get("bounded") is True


def test_truncation_is_reported_only_when_rows_were_cut():
    assert tools.run_cypher(StubDB(truncated=True), "s", SCOPED)["truncated"] is True
    assert "truncated" not in tools.run_cypher(StubDB(truncated=False), "s", SCOPED)


def test_max_var_length_matches_pathfind_depth():
    from orion.graph import pathfind
    assert tools.MAX_VAR_LENGTH == pathfind._MAX_DEPTH == 12


@pytest.mark.parametrize("q", [
    "STOP DATABASE neo4j",
    "ALTER DATABASE neo4j SET ACCESS READ WRITE",
    "CYPHER 5 MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c",
    "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c; MATCH (y:CpgCall) RETURN y",
    "RETURN CASE WHEN true THEN 1 END(n)",
])
def test_statement_shape_is_fail_closed(q):
    db = StubDB()
    assert "error" in tools.run_cypher(db, "s", q), q
    assert db.ran == []


@pytest.mark.parametrize("q", [
    "OPTIONAL MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c",
    "UNWIND [1, 2] AS x MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.line = x RETURN c",
    "WITH 3 AS n MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c LIMIT n",
    "RETURN 1 AS one",
    "// look for sinks\nMATCH (c:CpgCall {scan_id:$scan_id}) RETURN c;",
])
def test_statement_starts_accepted(q):
    assert "rows" in tools.run_cypher(StubDB(), "s", q), q


def test_timeout_error_is_translated_for_the_model():
    class Slow(StubDB):
        def run_cypher(self, scan_id, query, limit=50, **kw):
            if query.startswith("EXPLAIN"):
                return super().run_cypher(scan_id, query, limit, **kw)
            return {"error": "ClientError: {neo4j_code: Neo.ClientError.Transaction."
                             "TransactionTimedOutClientConfiguration} {message: ...}"}
    out = tools.run_cypher(Slow(), "s", SCOPED)
    assert out["error"].startswith("query timed out after 10 s")


# Neo4j accepts unicode letters, combining marks and currency symbols in identifiers; a node pattern
# the checker cannot read as one must be rejected, never waved through as an "expression".
@pytest.mark.parametrize("q", [
    "MATCH (ñ:CpgCall) RETURN ñ",
    "MATCH (a€:CpgCall) RETURN 1",
    "MATCH (a€) RETURN 1",
    "MATCH (ʰ) RETURN 1",
    "MATCH (ń) RETURN 1",
    "MATCH (Ⅰ) RETURN 1",
    "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN size(a€:CpgCall)",
])
def test_unicode_identifier_node_patterns_rejected(q):
    db = StubDB()
    assert "error" in tools.run_cypher(db, "s", q), q
    assert db.ran == []


def test_unicode_variable_with_scope_accepted():
    assert "rows" in tools.run_cypher(StubDB(), "s", "MATCH (ñ:CpgCall {scan_id:$scan_id})-->(m_1) RETURN m_1")


def test_overlong_query_rejected_cheaply():
    q = "MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.uid IN [" + ", ".join(["'u'"] * 3000) + "] RETURN c"
    db = StubDB()
    assert "too long" in tools.run_cypher(db, "s", q)["error"] and db.ran == []


def test_read_code_numbers_lines_like_the_code_index(tmp_path):
    """Final review M1: form feed / U+2028 do not split a line, so read_code(start, end) built from snippet or
    graph line numbers returns the same lines RepoIndex.source does."""
    from orion.lm import codeindex as ci
    text = "a = 1\n\x0c b = 2\nc = ' '\nd = 4\n"
    (tmp_path / "m.py").write_text(text)
    out = tools.read_code(str(tmp_path), "m.py", 3, 4)
    assert out["lines"] == ci.RepoIndex(str(tmp_path)).source("m.py", 3, 4) == "c = ' '\nd = 4"
    assert (out["start"], out["end"]) == (3, 4)
