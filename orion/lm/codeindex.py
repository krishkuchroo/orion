"""Tree-sitter code index: function spans, callee names, callers/callees, module windows.

Pure local parsing, no network. Grammars load lazily inside `parse_text` so `import orion.lm`
stays light. Repo text is untrusted: nothing here executes it.
"""
from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass


LANG_BY_EXT = {".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
               ".ts": "typescript", ".tsx": "tsx", ".py": "python", ".java": "java"}
MAX_FILE_BYTES = 1_000_000
MODULE_WINDOW = 20
SKIP_DIRS = ("node_modules", "vendor", "dist", "build", "target", ".git", "__pycache__", "venv", ".venv")
MODULE = "<module>"
_TEST_MARKERS = ("/test/", "/tests/", ".test.", "_test.", "spec.")


def is_test_path(path: str) -> bool:
    p = "/" + path
    return any(m in p for m in _TEST_MARKERS)


def _split_lines(text: str) -> list[str]:
    """Lines as tree-sitter counts them: split on "\n" only (not \x0c, U+2028, ...)."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines

_JS_FUNCS = {"function_declaration", "generator_function_declaration", "method_definition"}
_JS_EXPRS = {"arrow_function", "function_expression", "function", "generator_function"}
_PY_FUNCS = {"function_definition"}
_JAVA_FUNCS = {"method_declaration", "constructor_declaration"}


@dataclass(frozen=True)
class Span:
    file: str
    name: str
    start: int
    end: int
    calls: tuple[str, ...]


_parsers: dict = {}


def _parser(lang: str):
    if lang not in _parsers:
        import tree_sitter as ts
        if lang == "javascript":
            import tree_sitter_javascript as m; cap = m.language()
        elif lang == "typescript":
            import tree_sitter_typescript as m; cap = m.language_typescript()
        elif lang == "tsx":
            import tree_sitter_typescript as m; cap = m.language_tsx()
        elif lang == "python":
            import tree_sitter_python as m; cap = m.language()
        elif lang == "java":
            import tree_sitter_java as m; cap = m.language()
        else:
            return None
        _parsers[lang] = ts.Parser(ts.Language(cap))
    return _parsers[lang]


def _txt(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _last_ident(node) -> str:
    """`a.b.c` / `a.b` / `a` -> the last identifier, or '' when there is none."""
    if node is None:
        return ""
    t = node.type
    if t in ("identifier", "property_identifier", "private_property_identifier", "shorthand_property_identifier"):
        return _txt(node)
    if t == "member_expression":
        return _last_ident(node.child_by_field_name("property"))
    if t == "attribute":
        return _last_ident(node.child_by_field_name("attribute"))
    if t == "subscript_expression":
        return ""
    return ""


def _func_name(node, lang: str) -> str | None:
    """Name if `node` is a function we index (declaration, method, or named function/arrow), else None."""
    t = node.type
    if lang == "python":
        if t in _PY_FUNCS:
            return _txt(node.child_by_field_name("name")) or None
        return None
    if lang == "java":
        if t in _JAVA_FUNCS:
            return _txt(node.child_by_field_name("name")) or None
        return None
    if t in _JS_FUNCS:
        return _last_ident(node.child_by_field_name("name")) or None
    if t in _JS_EXPRS:
        own = _last_ident(node.child_by_field_name("name")) if t != "arrow_function" else ""
        if own:
            return own
        p = node.parent
        if p is None:
            return None
        if p.type == "variable_declarator" and p.child_by_field_name("value") == node:
            return _last_ident(p.child_by_field_name("name")) or None
        if p.type == "assignment_expression" and p.child_by_field_name("right") == node:
            return _last_ident(p.child_by_field_name("left")) or None
        if p.type in ("pair", "public_field_definition", "field_definition") and \
                (p.child_by_field_name("value") == node):
            return _last_ident(p.child_by_field_name("key") or p.child_by_field_name("name")) or None
    return None


def _callee(node, lang: str) -> str:
    t = node.type
    if lang == "python" and t == "call":
        return _last_ident(node.child_by_field_name("function"))
    if lang == "java" and t == "method_invocation":
        return _txt(node.child_by_field_name("name"))
    if lang in ("javascript", "typescript", "tsx") and t == "call_expression":
        return _last_ident(node.child_by_field_name("function"))
    return ""


def _collect_calls(fn, lang: str) -> tuple[str, ...]:
    """Callee names in body order, deduplicated; nested indexed functions are their own spans."""
    seen: dict[str, None] = {}
    stack = [c for c in reversed(fn.children)]
    while stack:
        n = stack.pop()
        if _func_name(n, lang):
            continue
        name = _callee(n, lang)
        if name:
            seen.setdefault(name)
        stack.extend(reversed(n.children))
    return tuple(seen)


def parse_text(rel: str, text: str) -> list[Span] | None:
    """Spans for one file; None for an unsupported extension or when no parser is available."""
    lang = LANG_BY_EXT.get(posixpath.splitext(rel)[1].lower())
    if lang is None:
        return None
    try:
        parser = _parser(lang)
    except Exception:
        return None
    if parser is None:
        return None
    tree = parser.parse(text.encode("utf-8", "replace"))
    spans: list[Span] = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        name = _func_name(n, lang)
        if name:
            spans.append(Span(rel, name, n.start_point[0] + 1, n.end_point[0] + 1, _collect_calls(n, lang)))
        stack.extend(reversed(n.children))
    spans.sort(key=lambda s: (s.start, -s.end, s.name))
    return spans


class RepoIndex:
    def __init__(self, root: str):
        self.root = root
        self.files: dict[str, list[Span]] = {}
        self.skipped: dict[str, str] = {}
        self._lines: dict[str, int] = {}
        self._text: dict[str, str] = {}   # only for files re-parsed via update()
        self._by_name: dict[str, list[Span]] | None = None
        self._walk()

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for fn in sorted(filenames):
                if posixpath.splitext(fn)[1].lower() not in LANG_BY_EXT:
                    continue
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                if fn.endswith(".min.js"):
                    self.skipped[rel] = "minified"
                    continue
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        self.skipped[rel] = "too large"
                        continue
                except OSError as e:
                    self.skipped[rel] = f"unreadable: {e}"
                    continue
                if is_test_path(rel):
                    self.skipped[rel] = "test file"
                    continue
                try:
                    with open(full, encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except OSError as e:
                    self.skipped[rel] = f"unreadable: {e}"
                    continue
                self._ingest(rel, text)

    def _ingest(self, rel: str, text: str) -> None:
        try:
            spans = parse_text(rel, text)
        except Exception as e:
            self.skipped[rel] = f"parse error: {type(e).__name__}"
            return
        if spans is None:
            self.skipped[rel] = "no parser"
            return
        self.files[rel] = spans
        self._lines[rel] = len(_split_lines(text))
        self._by_name = None

    def update(self, rel: str, text: str) -> None:
        self.files.pop(rel, None)
        self.skipped.pop(rel, None)
        self._text[rel] = text
        self._ingest(rel, text)
        self._by_name = None

    def source(self, file: str, start: int, end: int) -> str:
        text = self._text.get(file)
        if text is None:
            with open(os.path.join(self.root, file), encoding="utf-8", errors="replace") as f:
                text = f.read()
        return "\n".join(_split_lines(text)[max(start, 1) - 1:end])

    def enclosing(self, file: str, line: int) -> Span | None:
        spans = self.files.get(file)
        if spans is None:
            return None
        inside = [s for s in spans if s.start <= line <= s.end]
        if inside:
            return min(inside, key=lambda s: (s.end - s.start, -s.start))
        n = self._lines.get(file, 0)
        if n and not 1 <= line <= n:
            return None
        return Span(file, MODULE, max(1, line - MODULE_WINDOW), max(line, min(n, line + MODULE_WINDOW)), ())

    def _names(self) -> dict[str, list[Span]]:
        if self._by_name is None:
            d: dict[str, list[Span]] = {}
            for rel in sorted(self.files):
                for s in self.files[rel]:
                    d.setdefault(s.name, []).append(s)
            self._by_name = d
        return self._by_name

    @staticmethod
    def _order(origin: Span):
        odir = posixpath.dirname(origin.file)

        def key(s: Span):
            tier = 0 if s.file == origin.file else 1 if posixpath.dirname(s.file) == odir else 2
            return (tier, s.file, s.start)
        return key

    def callees(self, span: Span, limit: int) -> list[Span]:
        key, out = self._order(span), []
        for name in span.calls:
            cands = [s for s in self._names().get(name, ()) if s != span]
            if cands:
                out.append(min(cands, key=key))
            if len(out) >= limit:
                break
        return out[:limit]

    def callers(self, span: Span, limit: int) -> list[Span]:
        if span.name == MODULE:
            return []
        found = [s for spans in self.files.values() for s in spans if span.name in s.calls and s != span]
        found.sort(key=self._order(span))
        return found[:limit]
