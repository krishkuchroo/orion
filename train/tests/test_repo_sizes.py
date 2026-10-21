import json
import subprocess

from train import repo_sizes


def test_fetch_sizes_caches_every_answer_and_maps_404_to_none(tmp_path):
    cache = str(tmp_path / "sizes.jsonl")
    calls = []

    def run(cmd):
        calls.append(cmd)
        if cmd[2] == "repos/o/gone":
            raise subprocess.CalledProcessError(1, cmd, stderr="gh: Not Found (HTTP 404)")
        return "123\n"

    got = repo_sizes.fetch_sizes(["o/a", "o/gone", "o/a"], cache, run=run)
    assert got == {"o/a": 123, "o/gone": None}
    assert calls[0] == ["gh", "api", "repos/o/a", "--jq", ".size"] and len(calls) == 2   # duplicate asked once
    rows = [json.loads(ln) for ln in open(cache)]
    assert {r["repo"]: r["size_kb"] for r in rows} == {"o/a": 123, "o/gone": None}


def test_fetch_sizes_resumes_from_cache_and_skips_a_torn_last_line(tmp_path):
    cache = tmp_path / "sizes.jsonl"
    cache.write_text(json.dumps({"repo": "o/a", "size_kb": 5}) + "\n" + json.dumps({"repo": "o/n", "size_kb": None})
                     + "\n" + '{"repo": "o/t", "size_')
    asked = []

    def run(cmd):
        asked.append(cmd[2])
        return "77"

    got = repo_sizes.fetch_sizes(["o/a", "o/n", "o/t"], str(cache), run=run)
    assert got == {"o/a": 5, "o/n": None, "o/t": 77} and asked == ["repos/o/t"]
    assert repo_sizes.fetch_sizes(["o/a", "o/n", "o/t"], str(cache), run=lambda c: 1 / 0)["o/t"] == 77   # re-read intact


def test_fetch_sizes_other_errors_propagate_and_are_not_cached(tmp_path):
    import pytest
    cache = str(tmp_path / "sizes.jsonl")

    def run(cmd):
        raise RuntimeError("HTTP 403: API rate limit exceeded")

    with pytest.raises(RuntimeError):
        repo_sizes.fetch_sizes(["o/a"], cache, run=run)
    assert not open(cache).read().strip() if __import__("os").path.exists(cache) else True
    assert repo_sizes.fetch_sizes(["o/a"], cache, run=lambda c: "9") == {"o/a": 9}
