import pytest

from train import snapshot
from train.tests._git import GitRepo, git


@pytest.fixture
def repo(tmp_path, hermetic_git):
    src = GitRepo(tmp_path / "src")
    git(src.path, "config", "uploadpack.allowFilter", "true")
    git(src.path, "config", "uploadpack.allowAnySHA1InWant", "true")
    c1 = src.commit({"a.py": "v1\n", "blob.bin": b"\0" * 1000, "README.md": "r"}, "c1")
    c2 = src.commit({"a.py": "v2\n"}, "c2")
    return src, c1, c2


def test_fetch_checks_out_only_language_files_at_sha(tmp_path, repo):
    """Only *.py is materialised, at the requested (older) commit."""
    src, c1, c2 = repo
    snap = tmp_path / "snap"
    out = snapshot.fetch(f"file://{src.path}", c1, str(snap), globs=["*.py"])
    assert out["ok"] and out["error"] is None and out["seconds"] >= 0 and out["bytes"] > 0
    assert (snap / "a.py").read_text() == "v1\n"
    assert not (snap / "blob.bin").exists() and not (snap / "README.md").exists()
    assert snapshot.show(str(snap), c2, "a.py") == "v2\n"
    assert snapshot.show(str(snap), c2, "nope.py") is None


def test_missing_sha_or_repo_is_reported_not_raised(tmp_path, repo):
    """Review Focus 4."""
    src, _, _ = repo
    bad_sha = snapshot.fetch(f"file://{src.path}", "0" * 40, str(tmp_path / "s1"), globs=["*.py"])
    assert bad_sha["ok"] is False and bad_sha["error"] and bad_sha["bytes"] is None
    bad_repo = snapshot.fetch(f"file://{tmp_path}/nope", "0" * 40, str(tmp_path / "s2"), globs=["*.py"])
    assert bad_repo["ok"] is False and bad_repo["error"]


def test_fetch_runs_the_three_git_steps_in_order(tmp_path):
    calls = []
    snapshot.fetch("file:///x", "abc", str(tmp_path / "d"), globs=["*.py", "*.js"],
                   run=lambda cmd: calls.append(cmd) or "")
    d = str(tmp_path / "d")
    assert calls == [
        ["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet", "file:///x", d],
        ["git", "-C", d, "sparse-checkout", "set", "--no-cone", "*.py", "*.js"],
        ["git", "-C", d, "checkout", "--quiet", "abc"],
    ]


def test_lang_globs():
    assert snapshot.LANG_GLOBS["py"] == ["*.py"] and snapshot.LANG_GLOBS["java"] == ["*.java"]
    assert "*.tsx" in snapshot.LANG_GLOBS["js"]
