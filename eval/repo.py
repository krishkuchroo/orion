import os
import subprocess


def _default_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def vulnerable_commit(fix_sha: str, *, run=_default_run) -> str:
    return run(["git", "rev-parse", f"{fix_sha}^"]).strip()


def prepare(repo_url: str, dest: str, commit: str, *, run=_default_run) -> None:
    if not os.path.isdir(dest):
        run(["git", "clone", repo_url, dest])
    else:
        run(["git", "-C", dest, "fetch", "--all"])
    run(["git", "-C", dest, "checkout", "--detach", commit])
