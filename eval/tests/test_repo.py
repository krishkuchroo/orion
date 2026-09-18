from eval import repo


def test_vulnerable_commit_resolves_parent():
    calls = []

    def run(cmd):
        calls.append(cmd)
        return "PARENTSHA\n"
    out = repo.vulnerable_commit("FIXSHA", run=run)
    assert out == "PARENTSHA"
    assert calls[0] == ["git", "rev-parse", "FIXSHA^"]


def test_prepare_clones_when_absent(tmp_path):
    dest = tmp_path / "nope"
    seen = []

    def run(cmd):
        seen.append(cmd)
        return ""
    repo.prepare("https://x/y.git", str(dest), "SHA", run=run)
    assert ["git", "clone", "https://x/y.git", str(dest)] in seen
    assert ["git", "-C", str(dest), "checkout", "--detach", "SHA"] in seen
