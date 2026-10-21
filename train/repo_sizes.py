"""GitHub repository sizes (KB) for the Stage 2 subset choice (plan Task H8).

`fetch_sizes` asks ``gh api repos/<owner>/<repo> --jq .size`` once per repo and caches every answer as
JSONL ``{"repo", "size_kb"}`` (``size_kb`` null = the repo is gone, HTTP 404). The cache is appended after
each repo, so an interrupted run resumes where it stopped; a torn last line is ignored. Any other failure
(rate limit, network) propagates and is NOT cached: a size is measured or null, never guessed.

The `gh` call goes through an injectable runner ``run(cmd: list[str]) -> str`` so tests never use the network.
"""
from __future__ import annotations

import json
import os
import subprocess

GH_TIMEOUT_S = 60


def _default_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=GH_TIMEOUT_S).stdout


def _is_404(exc: BaseException) -> bool:
    text = " ".join(str(x) for x in (exc, getattr(exc, "stderr", ""), getattr(exc, "stdout", ""),
                                     getattr(exc, "output", "")) if x)
    return "404" in text or "Not Found" in text


def _read_cache(path: str) -> dict[str, int | None]:
    got: dict[str, int | None] = {}
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    got[r["repo"]] = r["size_kb"]
                except (ValueError, KeyError, TypeError):
                    continue
    return got


def fetch_sizes(repos: list[str], cache: str, *, run=None) -> dict[str, int | None]:
    """{repo: size in KB, or None when the repo is gone}, for every repo in `repos` (de-duplicated)."""
    run = run or _default_run
    got = _read_cache(cache)
    out: dict[str, int | None] = {}
    os.makedirs(os.path.dirname(os.path.abspath(cache)), exist_ok=True)
    if os.path.exists(cache) and os.path.getsize(cache):
        with open(cache, "rb+") as fh:      # a torn last line must not swallow the next record
            fh.seek(-1, os.SEEK_END)
            if fh.read(1) != b"\n":
                fh.write(b"\n")
    for repo in dict.fromkeys(repos):
        if repo not in got:
            try:
                size = int(str(run(["gh", "api", f"repos/{repo}", "--jq", ".size"])).strip())
            except Exception as e:  # noqa: BLE001 -- 404 is an answer; everything else is an error
                if not _is_404(e):
                    raise
                size = None
            got[repo] = size
            with open(cache, "a") as fh:
                fh.write(json.dumps({"repo": repo, "size_kb": size}) + "\n")
                fh.flush()
        out[repo] = got[repo]
    return out
