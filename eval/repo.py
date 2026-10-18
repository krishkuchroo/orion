import os
import subprocess


def _default_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def mirror(repo_url: str, mirror_dir: str, *, run=_default_run) -> None:
    """Reusable bare mirror (no working tree): clone once, fetch afterwards."""
    if os.path.isdir(mirror_dir):
        run(["git", "-C", mirror_dir, "fetch", "--all", "--tags", "--prune"])
    else:
        run(["git", "clone", "--bare", repo_url, mirror_dir])


def vulnerable_commit(fix_sha: str, mirror_dir: str, *, run=_default_run) -> str:
    return run(["git", "-C", mirror_dir, "rev-parse", f"{fix_sha}^"]).strip()


def export_tree(mirror_dir: str, sha: str, dest: str, *, run=_default_run) -> None:
    """Fresh working tree of `sha` with NO .git (so the fix commit is not reachable).

    Known limits: export-ignore files and submodules are not exported.
    """
    tar = f"{dest}.tar"
    os.makedirs(dest, exist_ok=True)
    try:
        run(["git", "-C", mirror_dir, "archive", "--format=tar", "-o", tar, sha])
        run(["tar", "-xf", tar, "-C", dest])
    finally:
        if os.path.exists(tar):
            os.remove(tar)
