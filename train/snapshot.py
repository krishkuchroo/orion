"""Partial git snapshots: fetch only the language files of a repo at a commit (Stage 1 data).

Partial clone (`--filter=blob:none`) + no-cone sparse checkout means only the blobs matching `globs`
are downloaded when `sha` is checked out. Nothing here raises on a git failure: `fetch` reports it."""
from __future__ import annotations

import os
import shutil
import subprocess
import time

from train.build import _default_run, _err

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


def fetch(repo_url: str, sha: str, dest: str, *, globs: list[str], run=None) -> dict:
    """Clone `repo_url` partially into `dest`, sparse-checkout `globs`, check out `sha`.

    Returns {ok, seconds, bytes (size of dest on disk, None on failure), error (head of the failure
    text, None on success)}. A failed fetch removes a `dest` it created, so a retry starts clean."""
    run = run or _default_run
    existed = os.path.exists(dest)
    t0 = time.monotonic()
    try:
        run(["git", "clone", "--filter=blob:none", "--no-checkout", "--quiet", repo_url, dest])
        run(["git", "-C", dest, "sparse-checkout", "set", "--no-cone", *globs])
        run(["git", "-C", dest, "checkout", "--quiet", sha])
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        if not existed:
            shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "seconds": time.monotonic() - t0, "bytes": None,
                "error": _head(exc)}
    return {"ok": True, "seconds": time.monotonic() - t0, "bytes": _dir_bytes(dest), "error": None}


def _head(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        text = (exc.stderr or exc.stdout or "").strip()
        if text:
            return text[:1500]
    return _err(exc)[:1500]


def show(dest: str, sha: str, path: str, *, run=None) -> str | None:
    """`git show <sha>:<path>` in `dest`; None if the path does not exist at that commit."""
    run = run or _default_run
    try:
        return run(["git", "-C", dest, "show", f"{sha}:{path}"])
    except subprocess.CalledProcessError:
        return None
