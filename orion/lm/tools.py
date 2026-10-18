"""Read-only tools for the in-process Orion-LM engine: a validated `run_cypher` and a sandboxed
`read_code`. No network, no Claude, no Ollama.

`run_cypher` guard order: write keyword -> CALL -> scan scope -> EXPLAIN pre-flight -> real query.
"""
from __future__ import annotations

import os
import re

from orion.graphdb import _STRING_LITERAL, _has_write_keyword

ROW_LIMIT = 25
MAX_WINDOW = 200  # max lines returned by read_code

_CALL = re.compile(r"\bCALL\b", re.IGNORECASE)
_NODE_BODY = re.compile(r"^\s*(\w*)\s*((?::\s*\w+\s*)*)(\{.*\})?\s*$", re.DOTALL)
# What may sit between two node patterns that are joined by a relationship: -[..]->, <-[..]-, --, etc.
_REL_GAP = re.compile(r"^\s*<?-\s*(\[[^\]]*\])?\s*-?>?\s*$")


# One left-to-right pass so a quote inside a comment, a `//` inside a string, or a paren inside a
# backticked identifier cannot confuse the scanner: strings -> str, comments -> space, `ident` -> bt.
_LEXEME = re.compile(
    _STRING_LITERAL.pattern + r"|(?P<line>//[^\n]*)|(?P<block>/\*.*?\*/)|(?P<bt>`[^`]*`)", re.DOTALL
)


def _blank(query: str) -> str:
    def sub(m: re.Match) -> str:
        if m.group("line") is not None or m.group("block") is not None:
            return " "
        if m.group("bt") is not None:
            return "bt"
        return "str"

    return _LEXEME.sub(sub, query)


def _top_level_entries(props: str) -> list[str]:
    """Split a `{k:v, ...}` map body on top-level commas (nesting-aware)."""
    inner = props.strip()[1:-1]
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


def _has_scope_entry(props: str) -> bool:
    if not props:
        return False
    for ent in _top_level_entries(props):
        key, sep, val = ent.partition(":")
        if sep and key.strip() == "scan_id" and val.strip() == "$scan_id":
            return True
    return False


def _node_patterns(text: str):
    """Yield (start, end, body) for each parenthesised group not preceded by an identifier char
    (so `count(c)` is skipped), matching nested parens."""
    i, n = 0, len(text)
    while i < n:
        if text[i] == "(" and not (i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")):
            depth, j = 0, i
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth != 0:
                yield i, n, None
                return
            yield i, j + 1, text[i + 1:j]
            i = j + 1
        else:
            i += 1


def unscoped_pattern(query: str) -> str | None:
    """Return the first offending node pattern (as written), or None if the query is scan-scoped."""
    text = _blank(query)
    if "`" in text or "/*" in text or "'" in text or '"' in text:
        return "<unterminated comment, quote or backtick>"  # fail closed
    bound: set[str] = set()
    prev_end, prev_ok = -1, False
    for start, end, body in _node_patterns(text):
        shown = text[start:end]
        if body is None:
            return shown  # unbalanced paren: fail closed
        m = _NODE_BODY.match(body)
        if not m:
            if re.match(r"^\s*\w*\s*:", body):  # looks like a node pattern we cannot parse
                return shown
            continue  # parenthesised expression, not a node pattern
        var, labels, props = m.group(1), m.group(2).strip(), m.group(3) or ""
        if var.isdigit():
            continue
        adjacent = prev_ok and prev_end >= 0 and bool(_REL_GAP.match(text[prev_end:start]))
        if labels:
            ok = _has_scope_entry(props)
        else:
            # Assumption: every edge carries scan_id on both endpoints (graph bug B2 fix), so a
            # label-less neighbour reached over any relationship (incl. variable-length) is in-scan.
            # bound variable reuse, or a neighbour reached by a relationship from a scoped node
            # (edges carry scan_id on both endpoints, so the neighbour is in-scan).
            ok = (var != "" and var in bound) or (adjacent and not props)
        if not ok:
            return shown
        if var:
            bound.add(var)
        prev_end, prev_ok = end, True
    return None


def is_scoped(query: str) -> bool:
    return unscoped_pattern(query) is None


def run_cypher(db, scan_id: str, query: str, *, limit: int = ROW_LIMIT) -> dict:
    if _has_write_keyword(query):
        return {"error": "write clauses are not allowed; this tool is read-only"}
    if _CALL.search(_blank(query)):
        return {"error": "CALL procedures are not allowed; use MATCH/RETURN"}
    bad = unscoped_pattern(query)
    if bad is not None:
        return {"error": f"unscoped pattern {bad}: every node needs a label and {{scan_id:$scan_id}}, "
                         f"e.g. (x:CpgCall {{scan_id:$scan_id}}); label-less (x) is allowed only for an "
                         f"already-bound variable or a neighbour of a scoped node"}
    pre = db.run_cypher(scan_id, "EXPLAIN " + query)
    if "error" in pre:
        return {"error": pre["error"]}
    res = db.run_cypher(scan_id, query, limit=limit)
    if "error" in res:
        return {"error": res["error"]}
    return {"rows": res["rows"], "row_count": res["row_count"]}


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
            lines = f.read().splitlines()
    except OSError as e:
        return {"error": str(e)}
    end = min(end, len(lines))
    chunk = lines[start - 1:end]
    return {"file": file, "start": start, "end": end, "lines": "\n".join(chunk)}
