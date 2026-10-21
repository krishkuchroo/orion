"""Read-only tools for the in-process Orion-LM engine: a validated `run_cypher` and a sandboxed
`read_code`. No network, no Claude, no Ollama.

`run_cypher` guard order: write keyword -> static check (`check_query`) -> EXPLAIN pre-flight, whose
plan must be read-only (query type "r") -> the real query. Both database calls run in a READ-access
session (Neo4j refuses writes itself) with a QUERY_TIMEOUT_S transaction timeout, and at most `limit`
rows are fetched.

Why the scope check matters: Neo4j also holds the PATCHED graph of the same CVE (the answer) and every
training graph, so the model's query must stay inside its own scan. Query rules, which the system
prompt and the training templates must follow:

  1. Every labeled node pattern carries `scan_id:$scan_id` in its property map, exactly once.
  2. A label-less node pattern, `(m)` or `()`, is allowed only inside a connected path that also has a
     node carrying `{scan_id:$scan_id}`. Edges only ever join nodes of the same scan (schema.emit_edge
     stamps scan_id on both endpoints; runtime OBSERVED_CALL matches both by scan_id), so such a
     neighbour is in-scan. Comma-separated patterns are separate paths. Variables are NOT trusted
     across clauses: re-scope a carried one, `WITH c MATCH (c:CpgCall {scan_id:$scan_id})-->(m)`.
  3. No WHERE or IS inside parentheses: put conditions in a WHERE clause after the pattern.
  4. Variable-length relationships need an upper bound <= MAX_VAR_LENGTH: `*1..3`, `*..12`, `*3`.
     No quantified paths or relationships (`+`, `*`, `{m,n}` after a relationship or a group).
  5. Not allowed: writes, CALL, UNION, LOAD CSV, SHOW, TERMINATE, USE, FOREACH, `{ }` subqueries
     (EXISTS/COUNT/COLLECT/CALL), functions outside the built-in namespaces (apoc., db., dbms., gds.
     ...), backtick-quoted function names or map keys, label expressions (| & ! %), dynamic labels.
  6. One statement, starting with MATCH, OPTIONAL MATCH, WITH, UNWIND or RETURN.

The checker fails closed: whatever it cannot classify with confidence is rejected, with a short
message naming the offending part (as written) so the model can correct itself.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from orion.graphdb import BT_PLACEHOLDER, STR_PLACEHOLDER, _has_write_keyword, _lex
from orion.lm.codeindex import _split_lines

ROW_LIMIT = 25
MAX_WINDOW = 200  # max lines returned by read_code
QUERY_TIMEOUT_S = 10  # per-query server-side transaction timeout (EXPLAIN and the real query)
MAX_VAR_LENGTH = 12  # upper bound for -[*..n]-; = graph/pathfind._MAX_DEPTH (a test pins this)
MAX_QUERY_CHARS = 8000  # keeps the static check itself cheap; real queries are far shorter

_SHOW_MAX = 120  # longest snippet quoted back in an error

_SCOPE = "{scan_id:$scan_id}"

# Clauses / commands a read-only scan-scoped query never needs.
_FORBIDDEN = (
    ("CALL", "CALL procedures and subqueries are not allowed; use MATCH/RETURN"),
    ("UNION", "UNION is not allowed; run separate queries"),
    ("LOAD", "LOAD CSV is not allowed; query the graph only"),
    ("SHOW", "SHOW commands are not allowed; query the graph only"),
    ("TERMINATE", "TERMINATE is not allowed"),
    ("USE", "USE is not allowed; the database is fixed"),
    ("FOREACH", "FOREACH is not allowed; this tool is read-only"),
)
_FORBIDDEN_RE = [(re.compile(rf"\b{w}\b", re.IGNORECASE), msg) for w, msg in _FORBIDDEN]
# A read query starts with one of these; anything else (admin commands, CYPHER/EXPLAIN prefixes) is out.
_START = re.compile(r"^\s*(?:MATCH|OPTIONAL\s+MATCH|WITH|UNWIND|RETURN)\b", re.IGNORECASE)
_SUBQUERY = re.compile(r"\b(EXISTS|COUNT|COLLECT|CALL)\s*\{", re.IGNORECASE)
_CLAUSE_IN_BRACES = re.compile(r"\b(MATCH|OPTIONAL|RETURN|WITH|UNWIND|WHERE|ORDER)\b", re.IGNORECASE)
# Namespaced function call `a.b.c(` (a property lookup can never be followed by `(`).
_NS_CALL = re.compile(r"(?<![\w.$])(\w+)((?:\s*\.\s*\w+)+)\s*\(")
_BUILTIN_NS = {"date", "datetime", "localdatetime", "localtime", "time", "duration", "point", "vector"}
_BANNED_NS = re.compile(r"(?<![\w.$])(apoc|db|dbms|gds|genai)\s*\.", re.IGNORECASE)
_BT_CALL = re.compile(re.escape(BT_PLACEHOLDER) + r"\s*\(")
# A relationship (or a parenthesised path, below) followed by a quantifier: `->+`, `-*`, `-{1,3}`.
_QUANT_REL = re.compile(r"-\s*>?\s*[+*{]")
_INLINE = re.compile(r"\b(WHERE|IS)\b", re.IGNORECASE)

# A word right before `(` that makes the group a function call -- unless it is one of these
# keywords, after which a pattern can start (`MATCH(n)`, `WHERE NOT(...)`, `ANY SHORTEST(a)`).
_KEYWORDS = frozenset("""
    MATCH OPTIONAL MERGE CREATE WHERE AND OR XOR NOT WHEN THEN ELSE CASE RETURN WITH UNWIND AS IN
    DISTINCT IS SET DELETE DETACH REMOVE ON YIELD ORDER BY SKIP LIMIT OFFSET ASC DESC ASCENDING
    DESCENDING STARTS ENDS CONTAINS SHORTEST GROUPS GROUP ANY ALL NONE SINGLE PATH PATHS WALK TRAIL
    ACYCLIC SIMPLE REPEATABLE DIFFERENT ELEMENTS ELEMENT RELATIONSHIPS RELATIONSHIP NODETACH FILTER
    LET NEXT FINISH NULL TRUE FALSE END
""".split())

# Identifiers: unicode word characters, not starting with a digit. Neo4j also allows characters that
# are not `\w` (currency symbols, combining marks); a group using one fails to parse here and is
# rejected below rather than taken for an expression.
_IDENT = r"(?!\d)\w+"
_NODE_HEAD = re.compile(rf"^\s*(?P<var>{_IDENT})?\s*(?P<labels>(?::\s*{_IDENT}\s*)*)$")
# `x IN list WHERE pred` -- the body of any()/all()/none()/single(); never a node pattern.
_LIST_PRED = re.compile(rf"^\s*{_IDENT}\s+IN\b", re.IGNORECASE)
# Evidence that a parenthesised group is an expression (property access, operator, call, list,
# number, boolean keyword) rather than a node pattern, which can never contain any of these.
_EXPR_HINT = re.compile(r"[.+\-*/%^=<>!(\[]|\b(?:AND|OR|XOR|NOT|IN|CONTAINS|STARTS|ENDS|CASE)\b|^\s*[0-9]",
                        re.IGNORECASE)
_REL_HEAD = re.compile(
    rf"^\s*(?:{_IDENT})?\s*(?::\s*{_IDENT}(?:\s*\|\s*:?\s*{_IDENT})*)?\s*"
    r"(?P<len>\*\s*(?P<lo>[0-9]+)?\s*(?:(?P<dots>\.\.)\s*(?P<hi>[0-9]+)?)?)?\s*$")
# Text allowed between two node patterns of one path (rel bracket already collapsed to `[]`).
_REL_GAP = re.compile(r"^\s*<?-\s*(?:\[\]\s*)?-\s*>?\s*$")


def _word_before(text: str, i: int) -> str:
    """The run of word characters ending right before index i ('' if none)."""
    j = i
    while j > 0 and (text[j - 1].isalnum() or text[j - 1] == "_"):
        j -= 1
    return text[j:i]


def _after_dash(text: str, i: int) -> bool:
    """The last non-space character before index i is `-` (so a `[` at i opens a relationship)."""
    j = i - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    return j >= 0 and text[j] == "-"


def _matching(text: str, i: int) -> int:
    """Index of the bracket closing the one opened at `i` (text is known to be balanced)."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] in "([{":
            depth += 1
        elif text[j] in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return len(text) - 1


def _depth0(s: str) -> str:
    """`s` with the contents of every nested (), [] and {} removed (the brackets themselves kept)."""
    out, depth = [], 0
    for ch in s:
        if ch in "([{":
            if depth == 0:
                out.append(ch)
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append(ch)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _top_level_entries(props: str) -> list[str]:
    """Split a `{k:v, ...}` map body on top-level commas (nesting-aware)."""
    inner = props.strip()[1:-1]
    if not inner.strip():
        return []
    out, depth, cur = [], 0, []
    for ch in inner:
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _split_props(body: str) -> tuple[str, str] | None:
    """(head, props) where props is the single trailing balanced `{...}` map ('' if none);
    None when anything but whitespace follows the map."""
    i = body.find("{")
    if i < 0:
        return body, ""
    j = _matching(body, i)
    if body[j] != "}" or body[j + 1:].strip():
        return None
    return body[:i], body[i:j + 1]


def _scope_of(props: str) -> tuple[bool, str | None]:
    """(carries scan_id:$scan_id exactly once, problem). A duplicate scan_id key (Neo4j keeps the
    last), a scan_id with any other value, or a key that may hide one (backticked) is a problem."""
    values = []
    for ent in _top_level_entries(props) if props else []:
        key, sep, val = ent.partition(":")
        key = key.strip()
        if not sep or key in (BT_PLACEHOLDER, STR_PLACEHOLDER) or not re.fullmatch(_IDENT, key):
            return False, "use plain property keys (no backticks)"
        if key == "scan_id":
            values.append(val.strip())
    if len(values) > 1:
        return False, f"duplicate scan_id key: use {_SCOPE} exactly once"
    if values and values[0] != "$scan_id":
        return False, f"scan_id must be exactly $scan_id, as in {_SCOPE}"
    return len(values) == 1, None


@dataclass
class _Group:
    start: int            # index of "(" in the blanked text
    end: int = -1         # index just past ")"
    parent: int | None = None
    children: list[int] = field(default_factory=list)
    func: bool = False    # a function call's argument list, not a pattern
    node: bool = False
    labeled: bool = False
    scoped: bool = False
    has_node: bool = False  # this group or a descendant is a node pattern


def _groups(text: str) -> tuple[list[_Group], list[int]]:
    """Every parenthesised group (nested ones too), plus the indices of the top-level ones."""
    groups: list[_Group] = []
    top: list[int] = []
    stack: list[int] = []
    for i, ch in enumerate(text):
        if ch == "(":
            g = _Group(start=i, parent=stack[-1] if stack else None)
            groups.append(g)
            idx = len(groups) - 1
            (groups[g.parent].children if g.parent is not None else top).append(idx)
            stack.append(idx)
        elif ch == ")":
            groups[stack.pop()].end = i + 1
    return groups, top


def _is_function_call(text: str, i: int) -> bool:
    """`(` at i directly follows a word that names a function (not a keyword or a number)."""
    word = _word_before(text, i)
    return bool(word) and not word.isdigit() and word.upper() not in _KEYWORDS


def check_query(query: str) -> str | None:
    """Static read-only + scan-scope check. Returns an error message for the model, or None."""
    if len(query) > MAX_QUERY_CHARS:
        return f"query too long (max {MAX_QUERY_CHARS} characters)"
    text, spans = _lex(query)

    def shown(a: int, b: int) -> str:
        s = query[spans[a][0]:spans[b - 1][1]] if b > a else ""
        return s if len(s) <= _SHOW_MAX else s[:_SHOW_MAX] + "..."

    if "`" in text or "'" in text or '"' in text or "/*" in text:
        return "unterminated string, comment or backtick"
    for rx, msg in _FORBIDDEN_RE:
        if rx.search(text):
            return msg
    if not _START.match(text):
        return "a query must start with MATCH, OPTIONAL MATCH, WITH, UNWIND or RETURN"
    if re.search(r";\s*\S", text):
        return "one statement per query (nothing after ';')"
    m = _SUBQUERY.search(text)
    if m:
        return f"{m.group(1).upper()} {{ }} subqueries are not allowed; use a pattern or a second MATCH"
    m = _NS_CALL.search(text)
    while m:
        if m.group(1).lower() not in _BUILTIN_NS:
            return f"function {shown(m.start(), m.end() - 1).strip()} is not allowed; use built-in functions only"
        m = _NS_CALL.search(text, m.end())
    m = _BANNED_NS.search(text)
    if m:
        return f"{m.group(1)}.* procedures and functions are not allowed; use built-in functions only"
    if _BT_CALL.search(text):
        return "backtick-quoted function names are not allowed"

    # Brackets must balance and nest properly (fail closed otherwise); remember each pair.
    pair: dict[int, int] = {}
    stack: list[int] = []
    for i, ch in enumerate(text):
        if ch in "([{":
            stack.append(i)
        elif ch in ")]}":
            if not stack or text[stack[-1]] != "([{"[")]}".index(ch)]:
                return "unbalanced brackets in the query"
            pair[stack.pop()] = i
    if stack:
        return "unbalanced brackets in the query"

    # { } bodies: maps and quantifiers only, never a subquery.
    for i, j in pair.items():
        if text[i] == "{" and _CLAUSE_IN_BRACES.search(_depth0(text[i + 1:j])):
            return f"subqueries in {{ }} are not allowed: {shown(i, j + 1)}"

    # Relationship brackets: strict syntax, bounded variable length.
    for i, j in sorted(pair.items()):
        if text[i] == "[" and _after_dash(text, i):
            body, what = text[i + 1:j], shown(i, j + 1)
            if _INLINE.search(_depth0(body)):
                return f"inline WHERE/IS inside {what} is not allowed: use a WHERE clause after the pattern"
            split = _split_props(body)
            rm = _REL_HEAD.match(split[0]) if split else None
            if rm is None:
                return (f"unsupported relationship pattern {what}: use [var:TYPE*min..max {{props}}] "
                        "and put conditions in a WHERE clause")
            if rm.group("len"):
                lo, hi = rm.group("lo"), rm.group("hi")
                bound = (int(hi) if hi else None) if rm.group("dots") else (int(lo) if lo else None)
                if bound is None or bound > MAX_VAR_LENGTH:
                    return (f"variable-length relationship {what} needs an upper bound of at most "
                            f"{MAX_VAR_LENGTH}, e.g. [:FLOWS_TO*1..5]")
    m = _QUANT_REL.search(text)
    if m:
        return (f"quantified relationship {shown(m.start(), m.end())!r} is not allowed; use a bounded "
                "variable-length relationship like -[:FLOWS_TO*1..5]->")

    # Parenthesised groups: classify every one (nested included), failing closed.
    groups, top = _groups(text)
    for g in groups:
        body = text[g.start + 1:g.end - 1]
        what = shown(g.start, g.end)
        d0 = _depth0(body)
        g.func = _is_function_call(text, g.start)
        if not _LIST_PRED.match(body) and _INLINE.search(d0):
            return f"inline WHERE/IS inside {what} is not allowed: use a WHERE clause after the pattern"
        if g.func:
            if ":" in d0:  # a label colon in an argument list: maybe a node pattern after all
                return f"cannot tell whether {what} is a node pattern; write nodes as (x:Label {_SCOPE})"
            continue
        split = _split_props(body)
        nm = _NODE_HEAD.match(split[0]) if split else None
        if nm is None:
            if ":" in d0:
                return (f"unsupported node pattern {what}: use (var:Label {_SCOPE}) with one plain "
                        "label per colon, no | & ! % or dynamic labels")
            if not _EXPR_HINT.search(d0):  # neither a readable node nor clearly an expression
                return f"cannot tell whether {what} is a node pattern; write nodes as (x:Label {_SCOPE})"
            continue  # an expression or a parenthesised path: its children are checked on their own
        scoped, problem = _scope_of(split[1])
        if problem:
            return f"bad node pattern {what}: {problem}"
        g.node, g.labeled, g.scoped = True, bool(nm.group("labels").strip()), scoped

    for g in reversed(groups):  # children come after their parent, so this is bottom-up
        g.has_node = g.node or (not g.func and any(groups[c].has_node for c in g.children))
    for g in groups:
        if g.has_node and re.match(r"\s*[+*{]", text[g.end:]):
            return (f"quantified path pattern {shown(g.start, g.end)} is not allowed; use a bounded "
                    "variable-length relationship like -[:FLOWS_TO*1..5]->")

    # Scope, per path: siblings joined by a relationship form one path.
    for siblings in [top] + [g.children for g in groups]:
        chain: list[_Group] = []
        for idx in siblings + [None]:
            g = groups[idx] if idx is not None else None
            joined = (g is not None and g.node and chain and chain[-1].node
                      and _REL_GAP.match(_collapse(text[chain[-1].end:g.start])))
            if not joined:
                problem = _chain_problem(chain, shown)
                if problem:
                    return problem
                chain = []
            if g is not None and g.node:
                chain.append(g)
    return None


def _collapse(gap: str) -> str:
    """Collapse each (possibly nested) [...] in a gap to `[]`."""
    prev = None
    while prev != gap:
        prev, gap = gap, re.sub(r"\[[^\[\]]*\]", "[]", gap)
    return gap


def _chain_problem(chain: list[_Group], shown) -> str | None:
    in_scan = any(g.scoped for g in chain)
    for g in chain:
        what = shown(g.start, g.end)
        if g.labeled and not g.scoped:
            return (f"unscoped pattern {what}: every labeled node needs {_SCOPE}, "
                    f"e.g. (x:CpgCall {_SCOPE})")
        if not g.labeled and not in_scan:
            return (f"unscoped pattern {what}: a node without a label must be in the same path as a "
                    f"node with {_SCOPE}, e.g. (c:CpgCall {_SCOPE})-[:FLOWS_TO]->(m); variables are "
                    f"not trusted across clauses, so re-scope them")
    return None


def is_scoped(query: str) -> bool:
    """True when `query` passes the full static check (read-only, scan-scoped, bounded)."""
    return check_query(query) is None


def _timed_out(err: str) -> bool:
    # Neo.ClientError.Transaction.TransactionTimedOut[ClientConfiguration]
    return "TransactionTimedOut" in err


def run_cypher(db, scan_id: str, query: str, *, limit: int = ROW_LIMIT) -> dict:
    if _has_write_keyword(query):
        return {"error": "write clauses are not allowed; this tool is read-only"}
    bad = check_query(query)
    if bad is not None:
        return {"error": bad}
    opts = {"timeout": QUERY_TIMEOUT_S, "bounded": True}
    pre = db.run_cypher(scan_id, "EXPLAIN " + query, limit=0, **opts)
    if "error" in pre:
        return {"error": pre["error"]}
    if pre.get("query_type") != "r":  # the planner's own verdict; a missing one fails closed
        return {"error": f"query is not read-only (Neo4j plans it as type {pre.get('query_type')!r}); "
                         "use MATCH ... RETURN"}
    res = db.run_cypher(scan_id, query, limit=limit, **opts)
    if "error" in res:
        if _timed_out(res["error"]):
            return {"error": f"query timed out after {QUERY_TIMEOUT_S} s: narrow it (fewer hops, "
                             "a LIMIT, a more specific label or property)"}
        return {"error": res["error"]}
    out = {"rows": res["rows"], "row_count": res["row_count"]}
    if res.get("truncated"):
        out["truncated"] = True  # more rows existed than `limit`; only the first `limit` are shown
    return out


def read_code(repo_path: str, file: str, start: int, end: int) -> dict:
    try:
        start, end = int(start), int(end)
    except (TypeError, ValueError):
        return {"error": "start and end must be integers"}
    if start > end:
        return {"error": f"start ({start}) is after end ({end})"}
    if not isinstance(file, str) or "\0" in file or "\0" in str(repo_path):
        return {"error": "invalid path"}
    root = os.path.realpath(repo_path)
    if os.path.isabs(file):
        return {"error": f"path escapes the repo: {file}"}
    full = os.path.realpath(os.path.join(root, file))
    if full != root and not full.startswith(root + os.sep):
        return {"error": f"path escapes the repo: {file}"}
    if not os.path.isfile(full):
        return {"error": f"not a file: {file}"}
    start = max(1, start)
    end = max(start, end)
    end = min(end, start + MAX_WINDOW - 1)
    try:
        with open(full, encoding="utf-8", errors="replace") as f:
            lines = _split_lines(f.read())   # "\n" only, as the code index and the graph number lines
    except OSError as e:
        return {"error": str(e)}
    end = min(end, len(lines))
    chunk = lines[start - 1:end]
    return {"file": file, "start": start, "end": end, "lines": "\n".join(chunk)}
