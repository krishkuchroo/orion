"""Tiny real-git helper for tests: build a repo in tmp_path, commit file dicts, bare-clone it."""
from __future__ import annotations

import os
import subprocess


def git(cwd, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True,
                          check=True).stdout


class GitRepo:
    def __init__(self, path) -> None:
        self.path = str(path)
        os.makedirs(self.path, exist_ok=True)
        git(self.path, "init", "-q", "-b", "main")

    def commit(self, files: dict, msg: str = "c") -> str:
        """Write/delete files (value None deletes) and commit; returns the full sha."""
        for name, content in files.items():
            p = os.path.join(self.path, name)
            if content is None:
                git(self.path, "rm", "-q", name)
                continue
            os.makedirs(os.path.dirname(p) or self.path, exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(p, mode) as fh:
                fh.write(content)
            git(self.path, "add", name)
        git(self.path, "commit", "-q", "--allow-empty", "-m", msg)
        return self.head()

    def mv(self, src: str, dst: str) -> None:
        os.makedirs(os.path.dirname(os.path.join(self.path, dst)) or self.path, exist_ok=True)
        git(self.path, "mv", src, dst)

    def head(self) -> str:
        return git(self.path, "rev-parse", "HEAD").strip()

    def checkout(self, *args: str) -> None:
        git(self.path, "checkout", "-q", *args)


def bare_mirror(repo_path, dest) -> str:
    subprocess.run(["git", "clone", "-q", "--bare", str(repo_path), str(dest)], check=True,
                   capture_output=True)
    return str(dest)
