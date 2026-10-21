import json

from train import enrich_gh

SHA = "a" * 40
SHA2 = "b" * 40


def commit_body(sha=SHA, repo="Owner/Repo", files=("src/a.js", "test/a.test.js"), author="2025-01-01T23:30:00Z",
                committer="2025-01-02T01:00:00Z"):
    return json.dumps({"sha": sha, "html_url": f"https://github.com/{repo}/commit/{sha}",
                       "commit": {"author": {"date": author}, "committer": {"date": committer}},
                       "parents": [{"sha": "p" * 40}], "files": [{"filename": f} for f in files]}).encode()


class FakeGet:
    """Replays queued (status, headers, body) per URL suffix and records every call."""

    def __init__(self, responses):
        self.responses = {k: list(v) for k, v in responses.items()}
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        for suffix, queue in self.responses.items():
            if url.endswith(suffix):
                return queue.pop(0) if len(queue) > 1 else queue[0]
        return 404, {}, b'{"message": "Not Found"}'


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.slept = []

    def time(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def gh(get, clock=None, reserve=10):
    clock = clock or Clock()
    return enrich_gh.GitHub(get, sleep=clock.sleep, clock=clock.time, reserve=reserve, log=lambda *a: None), clock


OK_HDR = {"x-ratelimit-remaining": "4000", "x-ratelimit-reset": "5000"}


def test_fetch_commit_ok_parses_dates_files_and_canonical_repo():
    client, _ = gh(FakeGet({f"/commits/{SHA}": [(200, OK_HDR, commit_body())]}))
    rec = enrich_gh.fetch_commit(client, "owner/old-name", SHA)
    assert rec["status"] == "ok" and rec["sha_full"] == SHA and rec["repo_canonical"] == "owner/repo"
    assert rec["author_date"] == "2025-01-01" and rec["committer_date"] == "2025-01-02"
    assert rec["files"] == ["src/a.js", "test/a.test.js"] and rec["truncated"] is False
    assert rec["key"] == enrich_gh.commit_key("owner/old-name", SHA)


def test_missing_commits_are_final_and_server_errors_are_retried_then_recorded():
    get = FakeGet({"/commits/404": [(404, OK_HDR, b"{}")], "/commits/422": [(422, OK_HDR, b"{}")],
                   "/commits/500": [(502, OK_HDR, b"")]})
    client, clock = gh(get)
    assert enrich_gh.fetch_commit(client, "o/r", "404")["status"] == "commit_missing"
    assert enrich_gh.fetch_commit(client, "o/r", "422")["status"] == "commit_missing"
    rec = enrich_gh.fetch_commit(client, "o/r", "500")
    assert rec["status"] == "error" and rec["http_status"] == 502
    assert sum(1 for c in get.calls if c.endswith("/500")) == 3 and clock.slept


def test_rate_limit_sleeps_until_reset_and_retries():
    clock = Clock()
    get = FakeGet({f"/commits/{SHA}": [
        (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(clock.t) + 100)}, b'{"message":"API rate limit exceeded"}'),
        (200, OK_HDR, commit_body())]})
    client, _ = gh(get, clock)
    rec = enrich_gh.fetch_commit(client, "o/r", SHA)
    assert rec["status"] == "ok" and clock.slept and clock.slept[0] >= 100


def test_low_remaining_quota_pauses_before_next_call():
    clock = Clock()
    hdr = {"x-ratelimit-remaining": "5", "x-ratelimit-reset": str(int(clock.t) + 60)}
    client, _ = gh(FakeGet({f"/commits/{SHA}": [(200, hdr, commit_body())]}), clock, reserve=10)
    enrich_gh.fetch_commit(client, "o/r", SHA)
    assert clock.slept and clock.slept[-1] >= 60


def test_truncated_file_list_is_flagged():
    hdr = dict(OK_HDR, link='<https://api.github.com/x?page=2>; rel="next"')
    client, _ = gh(FakeGet({f"/commits/{SHA}": [(200, hdr, commit_body())]}))
    assert enrich_gh.fetch_commit(client, "o/r", SHA)["truncated"] is True


def test_fetch_pr():
    body = json.dumps({"merged": True, "merge_commit_sha": SHA2, "merged_at": "2024-01-01T00:00:00Z"}).encode()
    client, _ = gh(FakeGet({"/pulls/7": [(200, OK_HDR, body)]}))
    rec = enrich_gh.fetch_pr(client, "o/r", 7)
    assert rec["status"] == "ok" and rec["merged"] is True and rec["merge_commit_sha"] == SHA2
    assert enrich_gh.fetch_pr(client, "o/r", 8)["status"] == "pr_missing"


def _row(**kw):
    r = {"id": "CVE-1", "repo": "o/r", "fix_sha": SHA, "fix_pr": None, "language": "js", "enrich_status": "pending"}
    r.update(kw)
    return r


def test_run_is_resumable_and_retries_only_errors(tmp_path):
    cache = tmp_path / "c.jsonl"
    cache.write_text(json.dumps({"key": enrich_gh.commit_key("o/r", SHA), "kind": "commit", "status": "ok"}) + "\n" +
                     json.dumps({"key": enrich_gh.commit_key("o/r", SHA2), "kind": "commit", "status": "error"}) + "\n")
    get = FakeGet({f"/commits/{SHA2}": [(200, OK_HDR, commit_body(sha=SHA2))],
                   "/commits/" + "c" * 40: [(404, OK_HDR, b"{}")]})
    clock = Clock()
    rows = [_row(), _row(id="CVE-2", fix_sha=SHA2), _row(id="CVE-3", fix_sha="c" * 40),
            _row(id="CVE-4", enrich_status="ok", enrich_basis="cvefixes", fix_sha="d" * 40)]
    summary = enrich_gh.run(rows, str(cache), get=get, sleep=clock.sleep, clock=clock.time, log=lambda *a: None)
    assert len(get.calls) == 2 and summary["fetched"] == 2
    recs = enrich_gh.Cache(str(cache)).records
    assert recs[enrich_gh.commit_key("o/r", SHA2)]["status"] == "ok"
    assert recs[enrich_gh.commit_key("o/r", "c" * 40)]["status"] == "commit_missing"


def test_run_resolves_pull_requests_then_their_merge_commits(tmp_path):
    body = json.dumps({"merged": True, "merge_commit_sha": SHA2}).encode()
    get = FakeGet({"/pulls/9": [(200, OK_HDR, body)], f"/commits/{SHA2}": [(200, OK_HDR, commit_body(sha=SHA2))]})
    clock = Clock()
    enrich_gh.run([_row(fix_sha=None, fix_pr=9)], str(tmp_path / "c.jsonl"), get=get, sleep=clock.sleep,
                  clock=clock.time, log=lambda *a: None)
    assert [c.rsplit("/", 2)[-2] for c in get.calls] == ["pulls", "commits"]


def test_apply_fills_fields_and_marks_missing():
    cache = {
        enrich_gh.commit_key("o/r", SHA): {"kind": "commit", "status": "ok", "sha_full": SHA, "repo_canonical": "o/r2",
                                           "author_date": "2025-01-01", "committer_date": "2025-01-03",
                                           "files": ["src/a.ts", "src/b.py", "test/a.test.js"], "truncated": False},
        enrich_gh.commit_key("o/r", SHA2): {"kind": "commit", "status": "commit_missing", "http_status": 404},
        enrich_gh.pr_key("o/r", 5): {"kind": "pr", "status": "ok", "merged": True, "merge_commit_sha": SHA},
        enrich_gh.pr_key("o/r", 6): {"kind": "pr", "status": "ok", "merged": False, "merge_commit_sha": None},
    }
    rows = [_row(), _row(id="CVE-2", fix_sha=SHA2), _row(id="CVE-3", fix_sha="e" * 40),
            _row(id="CVE-4", fix_sha=None, fix_pr=5), _row(id="CVE-5", fix_sha=None, fix_pr=6),
            _row(id="CVE-6", language=None)]
    a, b, c, d, e, f = enrich_gh.apply(rows, cache)
    assert a["enrich_status"] == "ok" and a["fix_commit_date"] == "2025-01-03"      # later of author/committer
    assert a["n_files"] == 2 and a["n_files_total"] == 3 and a["n_files_lang"] == 1
    assert a["repo_canonical"] == "o/r2" and a["fix_files"] == ["src/a.ts", "src/b.py"]
    assert b["enrich_status"] == "commit_missing" and b["fix_commit_date"] is None and b["n_files"] is None
    assert c["enrich_status"] == "pending"
    assert d["fix_sha"] == SHA and d["fix_via"] == "pr_merge" and d["enrich_status"] == "ok"
    assert e["fix_sha"] is None and e["pr_status"] == "not_merged"
    assert f["language"] == "mixed" and f["language_basis"] == "fix_files"
    assert rows[0]["enrich_status"] == "pending"                                      # inputs are not mutated


def test_apply_truncated_commit_leaves_counts_null():
    cache = {enrich_gh.commit_key("o/r", SHA): {"kind": "commit", "status": "ok", "sha_full": SHA, "repo_canonical": "o/r",
                                                "author_date": "2025-01-01", "committer_date": "2025-01-01",
                                                "files": ["a.js"] * 300, "truncated": True}}
    [r] = enrich_gh.apply([_row()], cache)
    assert r["enrich_status"] == "ok" and r["n_files"] is None and r["n_files_total"] is None
    assert r["files_truncated"] is True


def test_cache_skips_a_truncated_last_line(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text(json.dumps({"key": "commit:o/r@a", "status": "ok"}) + "\n" + '{"key": "commit:o/r@b", "sta')
    c = enrich_gh.Cache(str(p))
    assert c.done("commit:o/r@a") and not c.done("commit:o/r@b") and c.skipped_lines == 1


def test_fetch_repo_resolves_renames_and_marks_deleted_repos():
    client, _ = gh(FakeGet({"/repos/owner/old-name": [(200, OK_HDR, json.dumps({"full_name": "Owner/New"}).encode())],
                            "/repos/x/flaky": [(502, OK_HDR, b"")]}))
    assert enrich_gh.fetch_repo(client, "owner/old-name")["repo_canonical"] == "owner/new"
    assert enrich_gh.fetch_repo(client, "gone/repo")["status"] == "repo_missing"
    assert enrich_gh.fetch_repo(client, "x/flaky")["status"] == "error"


def test_run_looks_up_only_repos_no_commit_record_already_names(tmp_path):
    cache = tmp_path / "c.jsonl"
    enrich_gh.Cache(str(cache)).add({"key": enrich_gh.commit_key("o/known", SHA), "kind": "commit", "repo": "o/known",
                                     "status": "ok", "repo_canonical": "o/known2"})
    get = FakeGet({"/repos/o/new": [(200, OK_HDR, json.dumps({"full_name": "o/new"}).encode())]})
    s = enrich_gh.run([], str(cache), repos=["o/known", "o/new", "o/gone"], get=get, log=lambda *a: None)
    assert sorted(u.rsplit("/repos/", 1)[1] for u in get.calls) == ["o/gone", "o/new"]
    assert s["statuses"] == {"ok": 1, "repo_missing": 1} and s["pending_repos"] == 0
    canon, gone = enrich_gh.canonical_repos(enrich_gh.Cache(str(cache)))
    assert canon == {"o/known": "o/known2", "o/new": "o/new"} and gone == {"o/gone"}


def test_apply_repos_fills_canonical_only_where_missing_and_flags_gone_repos():
    rows = [{"id": "A", "repo": "o/old"}, {"id": "B", "repo": "o/old", "repo_canonical": "o/kept"},
            {"id": "C", "repo": "o/gone"}, {"id": "D", "repo": None}]
    a, b, c, d = enrich_gh.apply_repos(rows, {"o/old": "o/new"}, {"o/gone"})
    assert a["repo_canonical"] == "o/new" and a["repo_canonical_basis"] == "github_repo"
    assert b["repo_canonical"] == "o/kept" and c["repo_status"] == "missing" and "repo_canonical" not in d
    assert "repo_canonical" not in rows[0]                      # inputs are copied, never mutated
