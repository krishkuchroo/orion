"""Deterministic by-repo splits: pair id -> "train" | "dev" | "oldcve".

Every pair of a repo lands in one split, so dev / old-CVE never share a repo with training. A repo is its
lowercased ``repo_canonical`` (else ``repo``), so a renamed repo's raw spellings are one repo.
``oldcve`` is drawn only from repos whose pairs all come from the ready-made old-CVE sources
(OpenSSF CVE Benchmark, CWE-Bench-Java; spec §5.4); ``dev`` from the remaining repos.

Repo order is a seeded SHA-256 rank, so it does not depend on input order or Python's hash seed.
Once written, a split file is frozen: ``write`` refuses to overwrite and ``load`` refuses a pair
set that differs from the one that was split.
"""
from __future__ import annotations

import hashlib
import json
import os

OLDCVE_SOURCES = frozenset({"openssf", "cwe-bench-java"})


def _rank(seed: int, repo: str) -> str:
    return hashlib.sha256(f"{seed}:{repo}".encode()).hexdigest()


def _take(frac: float, n: int) -> int:
    return 0 if frac <= 0 or n == 0 else min(n, max(1, round(frac * n)))


def _repo(p: dict) -> str:
    return (p.get("repo_canonical") or p["repo"]).lower()


def assign(pairs: list[dict], *, seed: int = 0, dev_frac: float = 0.15, oldcve_frac: float = 0.20) -> dict[str, str]:
    by_repo: dict[str, list[dict]] = {}
    for p in pairs:
        by_repo.setdefault(_repo(p), []).append(p)
    repos = sorted(by_repo, key=lambda r: (_rank(seed, r), r))
    eligible = [r for r in repos if all(p.get("source") in OLDCVE_SOURCES for p in by_repo[r])]
    oldcve = set(eligible[:_take(oldcve_frac, len(eligible))])
    rest = [r for r in repos if r not in oldcve]
    dev = set(rest[:_take(dev_frac, len(rest))])
    out = {}
    for r, ps in by_repo.items():
        split = "oldcve" if r in oldcve else "dev" if r in dev else "train"
        for p in ps:
            out[p["id"]] = split
    return out


def write(path: str, assignment: dict[str, str], *, seed: int, dev_frac: float = 0.15,
          oldcve_frac: float = 0.20) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"{path} exists; a frozen split is never overwritten")
    with open(path, "w") as f:
        json.dump({"seed": seed, "dev_frac": dev_frac, "oldcve_frac": oldcve_frac,
                   "assignment": dict(sorted(assignment.items()))}, f, indent=1)
        f.write("\n")


def extend(path: str, old_pairs: list[dict], pairs: list[dict], *, note: str) -> dict[str, str]:
    """Grow a frozen split to a new pair set without moving any frozen pair (never a re-split).

    ``old_pairs`` must be exactly the pair set that was frozen; it gives each frozen pair's repo. A
    frozen pair keeps its split; a new pair joins its repo's split when that repo is already split;
    repos new to the split are divided among themselves by ``assign`` with the file's seed and
    fractions. Frozen pairs missing from ``pairs`` are removed and listed. Every extension is logged
    under ``extensions``. Refuses (ValueError) when a frozen pair's repo now belongs to another split,
    since one repo would then sit in two splits.
    """
    with open(path) as f:
        data = json.load(f)
    frozen = data["assignment"]
    if set(frozen) != {p["id"] for p in old_pairs}:
        raise ValueError(f"old_pairs is not the pair set frozen in {path}")
    repo_split: dict[str, str] = {}
    for p in old_pairs:
        repo_split.setdefault(_repo(p), frozen[p["id"]])
    out: dict[str, str] = {}
    for p in pairs:                                   # frozen pairs first: they pin their repos
        s = frozen.get(p["id"])
        if s is None:
            continue
        r = _repo(p)
        if repo_split.setdefault(r, s) != s:
            raise ValueError(f"{p['id']} is frozen in {s} but its repo {r} is in {repo_split[r]}")
        out[p["id"]] = s
    fresh = []
    for p in pairs:
        if p["id"] in out:
            continue
        if _repo(p) in repo_split:
            out[p["id"]] = repo_split[_repo(p)]
        else:
            fresh.append(p)
    out.update(assign(fresh, seed=data["seed"], dev_frac=data["dev_frac"], oldcve_frac=data["oldcve_frac"]))
    added = [i for i in out if i not in frozen]
    data.setdefault("extensions", []).append({
        "note": note, "added": len(added), "removed": sorted(set(frozen) - set(out)),
        "added_by_split": {s: sum(1 for i in added if out[i] == s) for s in ("train", "dev", "oldcve")},
        "new_repos": len({_repo(p) for p in fresh})})
    data["assignment"] = dict(sorted(out.items()))
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
    os.replace(tmp, path)
    return out


def load(path: str, pairs: list[dict]) -> dict[str, str]:
    with open(path) as f:
        data = json.load(f)
    a = data["assignment"]
    ids = {p["id"] for p in pairs}
    if set(a) != ids:
        raise ValueError(f"pair ids differ from the frozen split in {path}: "
                         f"{len(ids - set(a))} new, {len(set(a) - ids)} missing — refusing to re-split")
    return a
