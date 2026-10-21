"""Zero-context git diffs -> line-range hunks, from a LOCAL repo/mirror (no GitHub API).

* ``git_diff_u0(repo_dir, a, b, *, run=None)`` runs
  ``git -C repo_dir diff -U0 --no-color --find-renames a b`` (plus ``--no-ext-diff`` and explicit
  ``a/``/``b/`` prefixes, so a user's ``diff.external`` / ``diff.noprefix`` config cannot change the
  output) and returns the text.
* ``parse_u0(diff_text)`` returns one dict per ``@@ -a,b +c,d @@`` hunk:
  ``{"file": <new path>, "old_file": <old path>, "old_start", "old_end", "new_start", "new_end"}``.
  Ranges are 1-based and inclusive. An empty old range (add-only) has ``old_end = old_start - 1``
  (``old_start`` = the old line the insertion follows); an empty new range (delete-only) has
  ``new_end = new_start - 1``. A new file has ``old_file None``; a deleted file has ``file None``.

The parser counts each hunk's ``-``/``+`` lines from its header instead of sniffing ``---`` lines,
so a removed line that itself starts with ``--`` is never mistaken for a file header.
"""
from __future__ import annotations

import re
import subprocess

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_ESC = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _default_run(cmd: list[str]) -> str:
    # errors="replace": file CONTENT in a diff can be any encoding; only headers are parsed, and git
    # C-quotes non-ASCII paths (core.quotePath), so headers are always ASCII.
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          check=True).stdout


def git_diff_u0(repo_dir: str, a: str, b: str, *, run=None) -> str:
    """Zero-context diff a..b in `repo_dir` (a bare mirror works). Raises CalledProcessError on a bad
    revision (default runner)."""
    run = run or _default_run
    return run(["git", "-C", repo_dir, "diff", "-U0", "--no-color", "--find-renames", "--no-ext-diff",
                "--src-prefix=a/", "--dst-prefix=b/", a, b])


def _unquote(s: str) -> str:
    """Undo git's C-style path quoting ("a/caf\\303\\251.js" -> a/café.js)."""
    if not (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
        return s
    body, out, i = s[1:-1], bytearray(), 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            if re.fullmatch(r"[0-7]{3}", body[i + 1:i + 4]):
                out.append(int(body[i + 1:i + 4], 8))
                i += 4
                continue
            if body[i + 1] in _ESC:
                out.append(_ESC[body[i + 1]])
                i += 2
                continue
        out.extend(body[i].encode("utf-8"))
        i += 1
    return out.decode("utf-8", errors="replace")


def _path(raw: str, prefix: str) -> str | None:
    if raw.endswith("\t"):          # git appends a tab to ---/+++ names that contain a space
        raw = raw[:-1]
    if raw == "/dev/null":
        return None
    p = _unquote(raw)
    return p[len(prefix):] if p.startswith(prefix) else p


def parse_u0(diff_text: str) -> list[dict]:
    """Hunks of a ``git diff -U0`` text, in diff order (see module doc for the shape)."""
    out: list[dict] = []
    old = new = None
    minus = plus = 0
    for line in diff_text.split("\n"):   # not splitlines(): \f, \x1c, U+2028 can sit inside a line
        if minus > 0 or plus > 0:
            if line.startswith("-") and minus > 0:
                minus -= 1
                continue
            if line.startswith("+") and plus > 0:
                plus -= 1
                continue
            if line.startswith("\\"):    # "\ No newline at end of file"
                continue
            minus = plus = 0             # truncated hunk: resync on headers
        if line.startswith("diff --git "):
            old = new = None
        elif line.startswith("--- "):
            old = _path(line[4:], "a/")
        elif line.startswith("+++ "):
            new = _path(line[4:], "b/")
        else:
            m = _HUNK.match(line)
            if m:
                a, c = int(m[1]), int(m[3])
                b = 1 if m[2] is None else int(m[2])
                d = 1 if m[4] is None else int(m[4])
                out.append({"file": new, "old_file": old, "old_start": a, "old_end": a + b - 1,
                            "new_start": c, "new_end": c + d - 1})
                minus, plus = b, d
    return out
