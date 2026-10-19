"""Partial git snapshots: fetch only the language files of a repo at a commit (Stage 1 data).

Partial clone (`--filter=blob:none`) + no-cone sparse checkout means only the blobs matching `globs`
are downloaded when `sha` is checked out. Nothing here raises on a git failure: `fetch` reports it."""
from __future__ import annotations

import os
import shutil
import subprocess
import time

from train.build import _err

CLONE_TIMEOUT_S = 900
SHOW_TIMEOUT_S = 120


class SnapshotError(RuntimeError):
    """A git call failed for a reason other than 'path absent' (network, bad sha/dest, timeout)."""


def _default_run(cmd: list[str], timeout: float | None = None) -> str:
    """git runner. GIT_TERMINAL_PROMPT=0: a deleted/private repo fails instead of prompting."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          check=True, env=env, timeout=timeout).stdout

LANG_GLOBS = {
    "js": ["*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx"],
    "py": ["*.py"],
    "java": ["*.java"],
}


def _dir_bytes(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def fetch(repo_url: str, sha: str, dest: str, *, globs: list[str], run=None,
          timeout: float = CLONE_TIMEOUT_S) -> dict:
    """Clone `repo_url` partially into `dest`, sparse-checkout `globs`, check out `sha`.

    Returns {ok, seconds, bytes (size of dest on disk, None on failure), error (head of the failure
    text, None on success)}. A failed fetch removes a `dest` it created, so a retry starts clean."""
    run = run or _default_run
    existed = os.path.exists(dest)
    t0 = time.monotonic()
    try:
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet", repo_url, dest],
            timeout=timeout)
        run(["git", "-C", dest, "sparse-checkout", "set", "--no-cone", *globs], timeout=timeout)
        run(["git", "-C", dest, "checkout", "--quiet", sha], timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        if not existed:
            shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "seconds": time.monotonic() - t0, "bytes": None,
                "error": f"timeout after {timeout:g} s" if isinstance(exc, subprocess.TimeoutExpired)
                else _head(exc)}
    return {"ok": True, "seconds": time.monotonic() - t0, "bytes": _dir_bytes(dest), "error": None}


def _head(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        text = (exc.stderr or exc.stdout or "").strip()
        if text:
            return text[:1500]
    return _err(exc)[:1500]


def show(dest: str, sha: str, path: str, *, run=None, timeout: float = SHOW_TIMEOUT_S) -> str | None:
    """`git show <sha>:<path>` in `dest`; None ONLY if the path does not exist at that commit.

    Any other failure (network, bad sha, bad dest, timeout) raises SnapshotError, so a caller never
    mistakes a failed fetch for an absent file."""
    run = run or _default_run
    try:
        # ls-tree exits 0 with empty output for an absent path, non-zero for a bad sha/dest.
        listing = run(["git", "-C", dest, "ls-tree", "--name-only", "-z", sha, "--", path],
                      timeout=timeout)
        if path not in listing.split("\0"):
            return None
        return run(["git", "-C", dest, "show", f"{sha}:{path}"], timeout=timeout)
    except subprocess.TimeoutExpired:
        raise SnapshotError(f"timeout after {timeout:g} s") from None
    except Exception as exc:  # noqa: BLE001
        raise SnapshotError(_head(exc)) from exc
