import subprocess

import pytest

from train import diffs
from train.tests._git import GitRepo

pytestmark = pytest.mark.usefixtures("hermetic_git")

KEYS = {"file", "old_file", "old_start", "old_end", "new_start", "new_end"}
TEN = "".join(f"line {i}\n" for i in range(1, 11))


def _diff(r, a, b):
    return diffs.parse_u0(diffs.git_diff_u0(r.path, a, b))


def test_modify_hunk_has_matching_inclusive_ranges(tmp_path):
    """A changed line yields one hunk with 1-based inclusive old and new ranges and exactly the agreed
    keys; guards against off-by-one ranges that would map the fix to the wrong graph lines."""
    r = GitRepo(tmp_path / "r")
    a = r.commit({"a.js": TEN})
    b = r.commit({"a.js": TEN.replace("line 3\n", "LINE 3\n").replace("line 4\n", "LINE 4\n")})
    (h,) = _diff(r, a, b)
    assert set(h) == KEYS
    assert h == {"file": "a.js", "old_file": "a.js", "old_start": 3, "old_end": 4, "new_start": 3, "new_end": 4}


def test_add_only_hunk_has_empty_old_range(tmp_path):
    """Pure insertion after line 5: old range is empty (old_end = old_start - 1, old_start = the line it
    follows), new range covers the added lines; guards against treating an insertion as a one-line edit."""
    r = GitRepo(tmp_path / "r")
    a = r.commit({"a.js": TEN})
    b = r.commit({"a.js": TEN.replace("line 5\n", "line 5\nguard();\ncheck();\n")})
    (h,) = _diff(r, a, b)
    assert (h["old_start"], h["old_end"], h["new_start"], h["new_end"]) == (5, 4, 6, 7)


def test_delete_only_hunk_has_empty_new_range_and_dash_lines_are_not_headers(tmp_path):
    """Deleting two lines (one of which starts with '--', so the diff shows '--- ...') gives an empty
    new range and no phantom file; guards against a parser that sniffs '---' as a file header instead of
    counting the hunk's lines."""
    r = GitRepo(tmp_path / "r")
    src = "a\n-- drop table\n++ odd\nd\n"
    a = r.commit({"q.sql": src})
    b = r.commit({"q.sql": "a\nd\n"})
    hs = _diff(r, a, b)
    assert hs == [{"file": "q.sql", "old_file": "q.sql", "old_start": 2, "old_end": 3,
                   "new_start": 1, "new_end": 0}]


def test_multiple_files_and_hunks(tmp_path):
    """Two files, one with two separate hunks: every hunk is attributed to its own file in order;
    guards against hunks bleeding into the previous file's entry."""
    r = GitRepo(tmp_path / "r")
    a = r.commit({"a.js": TEN, "lib/b.py": TEN})
    b = r.commit({"a.js": TEN.replace("line 2\n", "X\n").replace("line 9\n", "Y\n"),
                  "lib/b.py": TEN.replace("line 7\n", "Z\n")})
    hs = _diff(r, a, b)
    assert [(h["file"], h["old_start"], h["new_start"]) for h in hs] == [("a.js", 2, 2), ("a.js", 9, 9), ("lib/b.py", 7, 7)]


def test_rename_with_edit_keeps_old_and_new_paths_and_added_deleted_files_use_none(tmp_path):
    """A renamed-and-edited file reports old_file (old path) and file (new path); a brand-new file has
    old_file None and a deleted file has file None; guards against looking up the vulnerable side
    under the patched path (or a '/dev/null' path)."""
    r = GitRepo(tmp_path / "r")
    a = r.commit({"src/old name.js": TEN, "gone.js": "x\n"})
    r.mv("src/old name.js", "src/new.js")
    b = r.commit({"src/new.js": TEN.replace("line 6\n", "SIX\n"), "added.js": "y\n", "gone.js": None})
    hs = {(h["old_file"], h["file"]): h for h in _diff(r, a, b)}
    assert hs[("src/old name.js", "src/new.js")]["old_start"] == 6
    assert (None, "added.js") in hs and ("gone.js", None) in hs
    assert hs[(None, "added.js")]["old_end"] == hs[(None, "added.js")]["old_start"] - 1


def test_git_diff_u0_uses_injected_runner_with_the_agreed_command():
    """git_diff_u0 goes through the injected runner with -U0/--no-color/--find-renames between a and
    b; guards against a hidden subprocess call that tests (and offline runs) cannot control."""
    seen = []
    out = diffs.git_diff_u0("/m.git", "aaa", "bbb", run=lambda cmd: seen.append(cmd) or "DIFF")
    (cmd,) = seen
    assert out == "DIFF" and cmd[:4] == ["git", "-C", "/m.git", "diff"]
    assert {"-U0", "--no-color", "--find-renames"} <= set(cmd) and cmd[-2:] == ["aaa", "bbb"]


def test_parse_u0_handles_missing_counts_and_quoted_paths():
    """'@@ -3 +3 @@' (count omitted = 1) and C-quoted non-ASCII paths parse correctly; guards against
    silently dropping hunks of one-line edits or of files with unusual names."""
    text = ('diff --git "a/caf\\303\\251.js" "b/caf\\303\\251.js"\n'
            "index 1..2 100644\n"
            '--- "a/caf\\303\\251.js"\n'
            '+++ "b/caf\\303\\251.js"\n'
            "@@ -3 +3 @@ ctx\n"
            "-old\n"
            "+new\n")
    assert diffs.parse_u0(text) == [{"file": "café.js", "old_file": "café.js", "old_start": 3, "old_end": 3,
                                     "new_start": 3, "new_end": 3}]


def test_git_diff_u0_failure_raises():
    """A bad revision surfaces as CalledProcessError (the caller records it); guards against an empty
    diff being mistaken for 'the fix changed nothing'."""
    with pytest.raises(subprocess.CalledProcessError):
        diffs.git_diff_u0("/nonexistent-dir-xyz", "a", "b")
