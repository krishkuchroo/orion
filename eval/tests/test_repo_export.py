import subprocess

from eval import repo


def test_vulnerable_commit_uses_mirror_C_flag():
    calls = []

    def run(cmd):
        calls.append(cmd)
        return "PARENT\n"
    assert repo.vulnerable_commit("FIX", "/m", run=run) == "PARENT"
    assert calls[0] == ["git", "-C", "/m", "rev-parse", "FIX^"]


def test_export_tree_archives_without_git(tmp_path):
    seen = []

    def run(cmd):
        seen.append(cmd)
        return ""
    repo.export_tree("/m", "SHA", str(tmp_path / "t"), run=run)
    assert seen[0][:4] == ["git", "-C", "/m", "archive"] and "SHA" in seen[0]
    assert seen[1][0] == "tar"                      # extract is a second argv, not a shell pipe
    assert not any("clone" in c for c in seen)      # never a working clone


def test_mirror_clones_when_absent_and_fetches_when_present(tmp_path):
    seen = []

    def run(cmd):
        seen.append(cmd)
        return ""
    m = tmp_path / "m"
    repo.mirror("https://x/y.git", str(m), run=run)
    assert seen[-1] == ["git", "clone", "--bare", "https://x/y.git", str(m)]
    m.mkdir()
    repo.mirror("https://x/y.git", str(m), run=run)
    assert seen[-1][:4] == ["git", "-C", str(m), "fetch"]


def test_export_tree_real_git_has_no_dotgit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    (src / "a.js").write_text("x\n")
    subprocess.run(["git", "-C", str(src), "add", "."], check=True)
    subprocess.run(["git", "-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "c"], check=True)
    repo.mirror(str(src), str(tmp_path / "m"))
    sha = subprocess.run(["git", "-C", str(tmp_path / "m"), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    repo.export_tree(str(tmp_path / "m"), sha, str(tmp_path / "t"))
    assert (tmp_path / "t" / "a.js").exists() and not (tmp_path / "t" / ".git").exists()
    assert not (tmp_path / "t.tar").exists()
