"""Fix-commit metadata from the GitHub REST API: cached, resumable, rate-limit aware.

One JSON line per fetched object is appended to a cache file (default
``~/Documents/OrionLutherLeo/orion-lm-research/raw/gh-cache/github.jsonl``). A rerun skips every key
whose record is final (``ok`` / ``commit_missing`` / ``pr_missing``) and retries ``error`` records.

* commit: ``GET /repos/{repo}/commits/{sha}`` -> author/committer dates, changed file names,
  canonical repo (renamed repos redirect), truncation flag (>300 files => paginated).
  404/422 => ``commit_missing``; 410/451 (repo gone/blocked) => ``commit_missing`` too.
* pull request (advisories that only link a PR): ``GET /repos/{repo}/pulls/{n}`` ->
  merged + merge_commit_sha; the merge commit is then fetched like any other commit.
* repo (a name no fetched commit already resolves): ``GET /repos/{repo}`` -> canonical repo (renamed
  repos redirect). 404/410/451 => ``repo_missing``. Used for rows whose dates and files come from a
  dump (CVEfixes, CrossVul, MoreFixes) and for the leak set, so a renamed repo is one repo everywhere.

Rate limits: after every response ``X-RateLimit-Remaining``/``-Reset`` are read; when the quota
falls to ``reserve`` the client sleeps until the reset. A 403/429 rate-limit answer sleeps until the
reset (or ``Retry-After``) and retries. 5xx / network errors back off and retry, then record
``error`` (retried on the next run). Nothing is ever guessed: a value GitHub does not return stays
``None``.

Run (resumable; safe to Ctrl-C and rerun)::

    ./.venv/bin/python -I train/enrich_gh.py --candidates <candidates.json> [--repos <repos.json>] [--cache <file>] [--limit N]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

if __package__ in (None, ""):  # run as a script under `python -I`: put the repo root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from train.sources import SUPPORTED_LANGUAGES, _date, _is_test, file_lang, language_from_files  # noqa: E402

API = "https://api.github.com"
DEFAULT_CACHE = os.path.expanduser("~/Documents/OrionLutherLeo/orion-lm-research/raw/gh-cache/github.jsonl")
FINAL = {"ok", "commit_missing", "pr_missing", "repo_missing"}


def commit_key(repo: str, sha: str) -> str:
    return f"commit:{repo}@{sha}"


def pr_key(repo: str, number: int) -> str:
    return f"pr:{repo}#{number}"


def repo_key(repo: str) -> str:
    return f"repo:{repo}"


def _token() -> str:
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def urllib_get(token: str):
    def get(url: str):
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                                   "Accept": "application/vnd.github+json",
                                                   "X-GitHub-Api-Version": "2022-11-28",
                                                   "User-Agent": "orion-train-enrich"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read() or b""
    return get


class GitHub:
    def __init__(self, get, *, sleep=time.sleep, clock=time.time, reserve: int = 200, log=print, retries: int = 3):
        self.get, self.sleep, self.clock, self.reserve, self.log, self.retries = get, sleep, clock, reserve, log, retries
        self.remaining = None

    def _wait_reset(self, headers, why: str):
        reset = headers.get("x-ratelimit-reset")
        wait = float(headers["retry-after"]) if headers.get("retry-after") else \
            max(0.0, float(reset) - self.clock()) + 5 if reset else 60.0
        self.log(f"[rate-limit] {why}: sleeping {wait:.0f}s")
        self.sleep(wait)

    def request(self, path: str):
        """(status, headers, parsed JSON or None). Rate limits are waited out; transient failures retried."""
        attempt, status, headers = 0, None, {}
        while True:
            try:
                status, headers, body = self.get(API + path)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                status, headers, body = None, {}, str(e).encode()
            if headers.get("x-ratelimit-remaining") is not None:
                self.remaining = int(headers["x-ratelimit-remaining"])
            limited = status in (403, 429) and (headers.get("x-ratelimit-remaining") == "0" or
                                                headers.get("retry-after") or b"rate limit" in (body or b"").lower())
            if limited:
                self._wait_reset(headers, f"HTTP {status}")
                continue
            if status is None or status >= 500:
                attempt += 1
                if attempt >= self.retries:
                    return status, headers, None
                self.sleep(min(60, 2 ** attempt))
                continue
            if self.remaining is not None and self.remaining <= self.reserve:
                self._wait_reset(headers, f"quota at {self.remaining}")
                self.remaining = None
            try:
                data = json.loads(body) if body else None
            except ValueError:
                data = None
            return status, headers, data


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_commit(client: GitHub, repo: str, sha: str) -> dict:
    status, headers, data = client.request(f"/repos/{repo}/commits/{sha}")
    rec = {"key": commit_key(repo, sha), "kind": "commit", "repo": repo, "sha": sha, "http_status": status,
           "fetched_at": _now()}
    if status == 200 and isinstance(data, dict) and data.get("sha"):
        html = data.get("html_url") or ""
        parts = html.split("github.com/", 1)[-1].split("/")
        commit = data.get("commit") or {}
        rec.update(status="ok", sha_full=data["sha"],
                   repo_canonical=f"{parts[0]}/{parts[1]}".lower() if len(parts) >= 2 else None,
                   author_date=_date((commit.get("author") or {}).get("date")),
                   committer_date=_date((commit.get("committer") or {}).get("date")),
                   parents=[p.get("sha") for p in data.get("parents") or []],
                   files=[f.get("filename") for f in data.get("files") or []],
                   truncated='rel="next"' in (headers.get("link") or ""))
    elif status in (404, 410, 422, 451):
        rec["status"] = "commit_missing"
    else:
        rec["status"] = "error"
    return rec


def fetch_pr(client: GitHub, repo: str, number: int) -> dict:
    status, _, data = client.request(f"/repos/{repo}/pulls/{number}")
    rec = {"key": pr_key(repo, number), "kind": "pr", "repo": repo, "number": number, "http_status": status,
           "fetched_at": _now()}
    if status == 200 and isinstance(data, dict):
        rec.update(status="ok", merged=bool(data.get("merged")), merge_commit_sha=data.get("merge_commit_sha"),
                   merged_at=data.get("merged_at"))
    elif status in (404, 410, 451):
        rec["status"] = "pr_missing"
    else:
        rec["status"] = "error"
    return rec


def fetch_repo(client: GitHub, repo: str) -> dict:
    status, _, data = client.request(f"/repos/{repo}")
    rec = {"key": repo_key(repo), "kind": "repo", "repo": repo, "http_status": status, "fetched_at": _now()}
    if status == 200 and isinstance(data, dict) and data.get("full_name"):
        rec.update(status="ok", repo_canonical=data["full_name"].lower())
    elif status in (404, 410, 451):
        rec["status"] = "repo_missing"
    else:
        rec["status"] = "error"
    return rec


class Cache:
    def __init__(self, path: str):
        self.path = path
        self.records: dict[str, dict] = {}
        self.skipped_lines = 0
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:            # a line cut short by Ctrl-C: that key is simply refetched
                        self.skipped_lines += 1
                        continue
                    self.records[rec["key"]] = rec   # later lines win (a retried error becomes ok)

    def done(self, key: str) -> bool:
        return self.records.get(key, {}).get("status") in FINAL

    def add(self, rec: dict) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a+") as f:
            if f.tell() > 0:                  # never glue a record onto a line cut short by Ctrl-C
                f.seek(f.tell() - 1)
                if f.read(1) != "\n":
                    f.write("\n")
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self.records[rec["key"]] = rec


def needs_github(row: dict) -> bool:
    return bool(row.get("repo")) and row.get("enrich_basis") is None and bool(row.get("fix_sha") or row.get("fix_pr"))


def todo(rows, cache: Cache) -> tuple[list[tuple], list[tuple]]:
    """Pending (pr, commit) work items in row order; PR merge commits appear once the PR is cached."""
    prs, commits, seen = [], [], set()
    for r in rows:
        if not needs_github(r):
            continue
        repo, sha = r["repo"], r.get("fix_sha")
        if not sha and r.get("fix_pr"):
            pk = pr_key(repo, r["fix_pr"])
            pr = cache.records.get(pk)
            if not cache.done(pk):
                if pk not in seen:
                    seen.add(pk)
                    prs.append(("pr", repo, r["fix_pr"]))
                continue
            if pr.get("status") == "ok" and pr.get("merged") and pr.get("merge_commit_sha"):
                sha = pr["merge_commit_sha"]
            else:
                continue
        ck = commit_key(repo, sha)
        if not cache.done(ck) and ck not in seen:
            seen.add(ck)
            commits.append(("commit", repo, sha))
    return prs, commits


def canonical_repos(cache) -> tuple[dict[str, str], set[str]]:
    """raw repo name -> canonical (current, lowercased) name from cached commit and repo lookups, and the
    raw names GitHub reports gone (never resolved by any record)."""
    records = cache.records if isinstance(cache, Cache) else cache
    canon, gone = {}, set()
    for rec in records.values():
        if not rec.get("repo"):
            continue
        if rec.get("kind") in ("commit", "repo") and rec.get("status") == "ok" and rec.get("repo_canonical"):
            canon.setdefault(rec["repo"], rec["repo_canonical"])
        elif rec.get("kind") == "repo" and rec.get("status") == "repo_missing":
            gone.add(rec["repo"])
    return canon, gone - set(canon)


def repo_todo(repos, cache: Cache) -> list[tuple]:
    known, _ = canonical_repos(cache)
    return [("repo", r, None) for r in dict.fromkeys(repos) if r and r not in known and not cache.done(repo_key(r))]


def run(rows, cache_path: str = DEFAULT_CACHE, *, repos=(), get=None, sleep=time.sleep, clock=time.time, log=print,
        limit: int | None = None, reserve: int = 200) -> dict:
    cache = Cache(cache_path)
    client = GitHub(get or urllib_get(_token()), sleep=sleep, clock=clock, reserve=reserve, log=log)
    fetched, counts = 0, {}
    for phase in ("pr", "commit", "repo"):         # repos last: a fetched commit already names its repo
        prs, commits = todo(rows, cache)
        items = prs if phase == "pr" else commits if phase == "commit" else repo_todo(repos, cache)
        total = len(items)
        log(f"[enrich] {phase}: {total} to fetch ({len(cache.records)} cached records)")
        for i, (_, repo, ident) in enumerate(items, 1):
            if limit is not None and fetched >= limit:
                break
            rec = fetch_pr(client, repo, ident) if phase == "pr" else fetch_commit(client, repo, ident) \
                if phase == "commit" else fetch_repo(client, repo)
            cache.add(rec)
            fetched += 1
            counts[rec["status"]] = counts.get(rec["status"], 0) + 1
            if i % 25 == 0 or i == total:
                log(f"[{i}/{total}] {phase} {repo} {ident or ''} -> {rec['status']} (quota left {client.remaining})")
    prs, commits = todo(rows, cache)
    return {"fetched": fetched, "statuses": counts, "pending_prs": len(prs), "pending_commits": len(commits),
            "pending_repos": len(repo_todo(repos, cache))}


def _fill_from_files(r: dict, files: list[str], truncated: bool) -> None:
    non_test = [f for f in files if not _is_test(f)]
    if r.get("language") is None:
        lang = language_from_files(files)
        if lang:
            r["language"], r["language_basis"] = lang, "fix_files"
    r["files_truncated"] = truncated
    if truncated:                      # >300 files: GitHub paginates; the exact count was not fetched
        r["n_files"] = r["n_files_total"] = r["n_files_lang"] = None
        return
    r["n_files"], r["n_files_total"] = len(non_test), len(files)
    lang = r.get("language")
    r["n_files_lang"] = sum(1 for f in non_test if file_lang(f) == lang) if lang in SUPPORTED_LANGUAGES else None
    r["fix_files"] = non_test


def apply_repos(rows, canon: dict[str, str], gone: set[str]) -> list[dict]:
    """Copies of ``rows``: a row without a commit-derived canonical repo takes it from ``canon``
    (``repo_canonical_basis = "github_repo"``); a row whose repo GitHub reports gone gets
    ``repo_status = "missing"`` (``filters.keep`` drops it: nothing can be cloned)."""
    out = []
    for row in rows:
        r = dict(row)
        if r.get("repo") and not r.get("repo_canonical"):
            if r["repo"] in canon:
                r["repo_canonical"], r["repo_canonical_basis"] = canon[r["repo"]], "github_repo"
            elif r["repo"] in gone:
                r["repo_status"] = "missing"
        out.append(r)
    return out


def apply(rows, cache) -> list[dict]:
    """Copies of ``rows`` with GitHub metadata filled in where the cache has it."""
    records = cache.records if isinstance(cache, Cache) else cache
    out = []
    for row in rows:
        r = dict(row)
        out.append(r)
        if not needs_github(r):
            continue
        for k in ("fix_commit_date", "n_files", "n_files_total", "n_files_lang"):
            r.setdefault(k, None)
        if not r.get("fix_sha") and r.get("fix_pr"):
            pr = records.get(pr_key(r["repo"], r["fix_pr"]))
            if not pr or pr.get("status") == "error":
                r["pr_status"] = "pending"
                continue
            if pr.get("status") != "ok":
                r["pr_status"] = "missing"
                continue
            if not (pr.get("merged") and pr.get("merge_commit_sha")):
                r["pr_status"] = "not_merged"
                continue
            r["pr_status"], r["fix_via"] = "merged", "pr_merge"
            r["fix_sha"], r["fix_shas"] = pr["merge_commit_sha"], [pr["merge_commit_sha"]]
        rec = records.get(commit_key(r["repo"], r["fix_sha"]))
        if rec is None:
            r["enrich_status"] = "pending"
            continue
        r["enrich_status"], r["enrich_basis"] = rec["status"], "github"
        if rec["status"] != "ok":
            continue
        r["fix_sha_full"], r["repo_canonical"] = rec.get("sha_full"), rec.get("repo_canonical")
        r["author_date"], r["committer_date"] = rec.get("author_date"), rec.get("committer_date")
        dates = [d for d in (rec.get("author_date"), rec.get("committer_date")) if d]
        r["fix_commit_date"] = max(dates) if dates else None
        _fill_from_files(r, rec.get("files") or [], bool(rec.get("truncated")))
    return out


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--candidates", required=True, help="JSON list of rows to enrich (from `train/mine.py collect`)")
    ap.add_argument("--repos", default=None, help="JSON list of repo names to resolve (from `train/mine.py collect`)")
    ap.add_argument("--cache", default=DEFAULT_CACHE)
    ap.add_argument("--limit", type=int, default=None, help="stop after this many API objects")
    ap.add_argument("--reserve", type=int, default=200, help="leave this much hourly quota unused")
    args = ap.parse_args(argv)
    with open(args.candidates) as f:
        rows = json.load(f)
    repos = []
    if args.repos:
        with open(args.repos) as f:
            repos = json.load(f)
    summary = run(rows, args.cache, repos=repos, limit=args.limit, reserve=args.reserve,
                  log=lambda *a: print(*a, flush=True))
    print(json.dumps(summary), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
