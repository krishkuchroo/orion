import base64
import json
import zipfile

from eval.dataset import check, mine
from train import enrich_gh


def test_to_manifest_rows_excludes_training_repos_and_fills_commit_pair():
    cands = [{"id": "CVE-A", "repo": "o/test", "cwe": "CWE-89", "fix_sha": "f1", "language": "python",
              "advisory_published": "2026-07-01"},
             {"id": "CVE-B", "repo": "o/trained", "cwe": "CWE-89", "fix_sha": "f2", "language": "python",
              "advisory_published": "2026-07-02"}]
    rows = mine.to_manifest_rows(cands, splits={"P1": "train"}, split_repos={"o/trained"},
                                 classify=lambda c: "headline", parent=lambda repo, sha: sha + "^")
    assert [r["id"] for r in rows] == ["CVE-A"]
    assert rows[0]["patched_commit"] == "f1" and rows[0]["vulnerable_commit"] == "f1^"
    assert rows[0]["fix_sites"] == [] and rows[0]["labelers"] == []


def test_access_control_cwes_are_separated():
    cands = [{"id": "X", "cwe": "CWE-862"}, {"id": "Y", "cwe": "CWE-89"}]
    data, access = mine.split_by_kind(cands)
    assert [c["id"] for c in data] == ["Y"] and [c["id"] for c in access] == ["X"]


# ---- kinds ----

def test_kind_dataflow_wins_over_access_control_and_other_cwes_have_no_kind():
    assert mine.kind_of("CWE-22,CWE-862") == "dataflow"
    assert mine.kind_of(["CWE-285"]) == "access_control"
    assert mine.kind_of("CWE-400") is None and mine.kind_of("") is None and mine.kind_of(None) is None
    data, access = mine.split_by_kind([{"id": "Z", "cwe": "CWE-400"}])
    assert data == [] and access == []


# ---- assess / to_manifest_rows ----

def _cand(i, **kw):
    c = {"id": f"CVE-{i}", "repo": "o/r", "cwe": "CWE-89", "fix_sha": f"s{i}", "language": "py",
         "advisory_published": f"2026-07-{10 + i:02d}"}
    c.update(kw)
    return c


def _kw(**kw):
    base = dict(splits={}, split_repos=set(), classify=lambda c: "headline", parent=lambda repo, sha: "p" + sha)
    base.update(kw)
    return base


def test_classify_tuple_is_normalised_and_non_headline_rows_are_dropped():
    cands = [_cand(1), _cand(2)]
    cls = {"CVE-1": ("control", ["fix_commit_date 2026-05-01 <= 2026-05-31"]), "CVE-2": ("headline", ["ok"])}
    rows = mine.to_manifest_rows(cands, **_kw(classify=lambda c: cls[c["id"]]))
    assert [r["id"] for r in rows] == ["CVE-2"] and rows[0]["tier"] == "headline"
    audit = mine.assess(cands, **_kw(classify=lambda c: cls[c["id"]]))
    assert audit[0]["tier"] == "control" and audit[0]["reasons"] == ["fix_commit_date 2026-05-01 <= 2026-05-31"]
    assert audit[1]["reasons"] == ["ok"]


def test_assess_keeps_every_candidate_with_reasons_and_training_checks_override_classify():
    cands = [_cand(1, repo="o/old", repo_canonical="o/trained"), _cand(2, aliases=["GHSA-x", "CVE-2"]),
             _cand(3)]
    out = mine.assess(cands, **_kw(split_repos={"o/trained"}, splits={"GHSA-x": "dev"}))
    assert [a["tier"] for a in out] == ["excluded", "excluded", "headline"]
    assert out[0]["reasons"][0] == "training_repo: o/trained"
    assert out[1]["reasons"][0] == "training_pair: GHSA-x (dev)"
    assert out[2]["vulnerable_commit"] == "ps3" and out[2]["patched_commit"] == "s3"
    assert "tier" not in cands[0]                                   # inputs are not mutated


def test_training_repo_flag_reaches_the_real_classifier():
    c = _cand(1, repo="o/trained", enrich_status="ok", fix_commit_date="2026-07-01", n_files=1, fix_shas=["s1"])
    out = mine.assess([c], **_kw(split_repos={"o/trained"}, classify=mine.classify_candidate))
    assert out[0]["tier"] == "excluded" and out[0]["reasons"] == ["training_repo: o/trained"]


def test_missing_parent_excludes_the_row():
    out = mine.assess([_cand(1)], **_kw(parent=lambda repo, sha: None))
    assert out[0]["tier"] == "excluded" and out[0]["reasons"] == ["parent_missing"]
    assert mine.to_manifest_rows([_cand(1)], **_kw(parent=lambda repo, sha: None)) == []


def test_parent_is_asked_with_the_raw_repo_and_sha_and_patched_is_the_full_sha():
    asked = []
    c = _cand(1, repo="o/old", repo_canonical="o/new", fix_sha="abc1234", fix_sha_full="abc1234" + "0" * 33,
              ghsa="GHSA-1", cve="CVE-1", kind="dataflow")
    rows = mine.to_manifest_rows([c], **_kw(parent=lambda repo, sha: asked.append((repo, sha)) or "p" * 40))
    assert asked == [("o/old", "abc1234")]
    r = rows[0]
    assert r["patched_commit"] == "abc1234" + "0" * 33 and r["vulnerable_commit"] == "p" * 40
    assert r["repo"] == "o/new" and r["repo_url"] == "https://github.com/o/new" and r["repo_raw"] == "o/old"
    assert r["kind"] == "dataflow" and r["ghsa"] == "GHSA-1" and r["cve"] == "CVE-1"
    assert r["accepted_entry_points"] == [] and r["loc_first_party"] is None
    assert "repo_raw" not in mine.to_manifest_rows([_cand(2)], **_kw())[0]


def test_rows_are_ordered_by_advisory_date_and_capped_per_repo_and_kind():
    cands = [_cand(5), _cand(1), _cand(3), _cand(4, cwe="CWE-862"), _cand(2, repo="o/other")]
    rows = mine.to_manifest_rows(cands, **_kw())
    assert [r["id"] for r in rows] == ["CVE-1", "CVE-2", "CVE-3", "CVE-4"]   # CVE-5 is o/r's 3rd dataflow row
    assert [r["kind"] for r in rows] == ["dataflow", "dataflow", "dataflow", "access_control"]
    kept, capped = mine.select(mine.assess(cands, **_kw()), max_per_repo=2)
    assert [a["id"] for a in capped] == ["CVE-5"]
    assert len(mine.to_manifest_rows(cands, **_kw(), max_per_repo=None)) == 5


def test_manifest_rows_pass_the_f1_validator():
    from eval import manifest
    rows = mine.to_manifest_rows([_cand(1, cve="CVE-1"), _cand(2, repo="o/two")], **_kw())
    assert manifest.validate({"version": 2, "repos": rows}, split_repos={"o/trained"}) == []


# ---- candidates() on a real-shaped OSV zip ----

def _osv(oid, published, *, cwes=("CWE-89",), repo="o/r", shas=("a" * 40,), pr=None, aliases=(), nvd=None,
         withdrawn=None, eco="npm"):
    refs = [{"type": "FIX", "url": f"https://github.com/{repo}/commit/{s}"} for s in shas]
    if pr:
        refs.append({"type": "FIX", "url": f"https://github.com/{repo}/pull/{pr}"})
    ds = {"cwe_ids": list(cwes), "github_reviewed": True}
    if nvd:
        ds["nvd_published_at"] = nvd + "T10:00:00Z"
    d = {"id": oid, "published": published + "T12:00:00Z", "aliases": list(aliases), "references": refs,
         "affected": [{"package": {"ecosystem": eco, "name": "pkg"}}], "database_specific": ds}
    if withdrawn:
        d["withdrawn"] = withdrawn
    return d


def _zip(tmp_path, records, eco="npm"):
    p = tmp_path / f"osv-{eco}" / "all.zip"
    p.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(p, "w") as z:
        for d in records:
            z.writestr(d["id"] + ".json", json.dumps(d))
    return str(p)


def test_candidates_keep_post_cutoff_github_fix_commits_in_target_cwes(tmp_path):
    path = _zip(tmp_path, [
        _osv("GHSA-pre1", "2026-05-01", aliases=["CVE-2026-1"]),
        _osv("GHSA-on01", "2026-05-31", aliases=["CVE-2026-2"], shas=("b" * 40,)),   # strictly after only
        _osv("GHSA-df01", "2026-07-01", aliases=["CVE-2026-3"], shas=("c" * 40,)),
        _osv("GHSA-ac01", "2026-07-02", cwes=("CWE-862",), shas=("d" * 40,)),
        _osv("GHSA-ot01", "2026-07-03", cwes=("CWE-400",), shas=("e" * 40,)),
        _osv("GHSA-pr01", "2026-07-04", shas=(), pr=7),
        _osv("GHSA-wd01", "2026-07-05", shas=("f" * 40,), withdrawn="2026-07-06T00:00:00Z"),
        _osv("MAL-2026-1", "2026-07-06", shas=("1" * 40,)),
    ])
    stats = {}
    got = mine.candidates(path, stats=stats)
    assert [c["id"] for c in got] == ["CVE-2026-3", "GHSA-ac01"]
    c = got[0]
    assert c["repo"] == "o/r" and c["fix_sha"] == "c" * 40 and c["fix_shas"] == ["c" * 40]
    assert c["cwe"] == "CWE-89" and c["kind"] == "dataflow" and c["ghsa"] == "GHSA-df01"
    assert c["cve"] == "CVE-2026-3" and c["advisory_published"] == "2026-07-01" and c["language"] == "js"
    assert c["shared_fix_with"] == [] and c["advisory_first_public"] == "2026-07-01"
    assert got[1]["kind"] == "access_control"
    assert stats["advisories"] == 6 and stats["post_cutoff"] == 4
    assert stats["github_fix_commit"] == 3 and stats["pr_link_only"] == 1
    assert stats["dataflow"] == 1 and stats["access_control"] == 1 and stats["other_cwe"] == 1


def test_candidates_flag_multi_commit_bundled_and_earlier_public_records(tmp_path):
    shared = "9" * 40
    path = _zip(tmp_path, [
        _osv("GHSA-mc01", "2026-07-01", shas=("a" * 40, "b" * 40)),
        _osv("GHSA-bu01", "2026-07-02", shas=(shared,)),
        _osv("GHSA-bu02", "2026-07-03", cwes=("CWE-400",), shas=(shared[:7],)),    # same commit, short sha
        _osv("GHSA-nv01", "2026-07-04", shas=("c" * 40,), nvd="2026-05-20"),
        _osv("GHSA-al01", "2026-07-05", aliases=["CVE-2026-9"], shas=("d" * 40,)),
        _osv("GHSA-al02", "2026-04-01", aliases=["CVE-2026-9"], repo="o/elsewhere", shas=()),
    ])
    got = {c["id"]: c for c in mine.candidates(path, max_per_repo=None)}
    assert got["GHSA-mc01"]["fix_shas"] == ["a" * 40, "b" * 40]
    assert got["GHSA-bu01"]["shared_fix_with"] == ["GHSA-bu02"]
    assert got["GHSA-nv01"]["nvd_published"] == "2026-05-20"
    assert got["GHSA-nv01"]["advisory_first_public"] == "2026-05-20"
    assert got["GHSA-nv01"]["advisory_first_public_basis"] == "nvd_published_at"
    assert got["CVE-2026-9"]["advisory_first_public"] == "2026-04-01"
    assert got["CVE-2026-9"]["advisory_first_public_basis"] == "osv_alias"


def test_candidates_cap_keeps_the_two_earliest_per_repo_and_kind_and_dedupe_across_zips(tmp_path):
    recs = [_osv(f"GHSA-c{i:03d}", f"2026-07-{10 - i:02d}", shas=(f"{i}" * 40,)) for i in range(1, 5)]
    a = _zip(tmp_path, recs + [_osv("GHSA-ac99", "2026-08-01", cwes=("CWE-863",), shas=("e" * 40,))])
    b = _zip(tmp_path, recs[:1], eco="pypi")                     # the same advisory in a second export
    got = mine.candidates([a, b])
    assert [c["id"] for c in got] == ["GHSA-c004", "GHSA-c003", "GHSA-ac99"]
    assert len(mine.candidates([a, b], max_per_repo=None)) == 5


# ---- GitHub facts ----

def _rec(**kw):
    rec = {"key": "k", "kind": "commit", "status": "ok", "sha_full": "f" * 40, "repo_canonical": "o/new",
           "author_date": "2026-07-02", "committer_date": "2026-06-30", "parents": ["p" * 40],
           "files": ["src/a.py", "tests/test_a.py", "CHANGELOG.md"], "truncated": False}
    rec.update(kw)
    return rec


def test_fill_commit_takes_the_earlier_date_non_test_files_and_fix_file_language():
    c = mine.fill_commit(_cand(1, language="js"), _rec())
    assert c["enrich_status"] == "ok" and c["fix_sha_full"] == "f" * 40 and c["repo_canonical"] == "o/new"
    assert c["fix_commit_date"] == "2026-06-30" and c["parents"] == ["p" * 40]
    assert c["n_files"] == 2 and c["n_files_total"] == 3 and c["fix_files"] == ["src/a.py", "CHANGELOG.md"]
    assert c["language"] == "py" and c["language_basis"] == "fix_files" and c["ecosystem_language"] == "js"
    assert c["files_truncated"] is False


def test_fill_commit_truncated_missing_and_unresolved():
    t = mine.fill_commit(_cand(1), _rec(truncated=True))
    assert t["files_truncated"] is True and t["n_files"] is None
    m = mine.fill_commit(_cand(1), {"status": "commit_missing"}, canonical="o/moved")
    assert m["enrich_status"] == "commit_missing" and m["repo_canonical"] == "o/moved"
    assert mine.fill_commit(_cand(1), None)["enrich_status"] == "pending"


def test_filled_candidate_through_the_real_classifier():
    c = mine.fill_commit(_cand(1, fix_shas=["s1"], shared_fix_with=[]), _rec())
    assert mine.classify_candidate(c)[0] == "headline"
    many = mine.fill_commit(c, _rec(files=[f"src/m{i}.py" for i in range(11)]))
    assert mine.classify_candidate(many) == ("excluded", ["n_files 11 > 10"])
    early = mine.fill_commit(c, _rec(author_date="2026-05-30"))
    assert mine.classify_candidate(early)[0] == "control"
    other = mine.fill_commit(c, _rec(files=["web/App.svelte"]))
    assert check.classify(dict(other, lang=other["language"]))[0] == "excluded"


def test_gitmodules_parse_and_submodule_hits():
    text = '[submodule "lib"]\n\tpath = vendor/lib\n\turl = https://x/y\n[submodule "b"]\n  path=docs/theme\n'
    paths = mine.parse_gitmodules(text)
    assert paths == ["vendor/lib", "docs/theme"]
    assert mine.submodule_hits(["vendor/lib", "src/a.js", "docs/theme/x.css", "vendor/library.js"], paths) == \
        ["vendor/lib", "docs/theme/x.css"]


def test_fetch_gitmodules_reads_the_contents_api_at_the_fix_commit():
    body = json.dumps({"type": "file", "encoding": "base64",
                       "content": base64.b64encode(b'[submodule "a"]\n\tpath = ext/a\n').decode()}).encode()
    seen = []

    def get(url):
        seen.append(url)
        if "with-mods" in url:
            return 200, {"x-ratelimit-remaining": "4000"}, body
        if "broken" in url:
            return 403, {}, b'{"message": "Repository access blocked"}'
        return 404, {}, b'{"message": "Not Found"}'

    client = enrich_gh.GitHub(get, sleep=lambda s: None, clock=lambda: 0.0, log=lambda *a: None)
    rec = mine.fetch_gitmodules(client, "o/with-mods", "abc")
    assert seen[0].endswith("/repos/o/with-mods/contents/.gitmodules?ref=abc")
    assert rec["status"] == "ok" and rec["present"] is True and rec["paths"] == ["ext/a"]
    assert rec["key"] == mine.gitmodules_key("o/with-mods", "abc") and rec["kind"] == "gitmodules"
    none = mine.fetch_gitmodules(client, "o/plain", "abc")
    assert none["status"] == "ok" and none["present"] is False and none["paths"] == []
    assert mine.fetch_gitmodules(client, "o/broken", "abc")["status"] == "error"


def test_reason_kind():
    assert mine.reason_kind("n_files 14 > 10") == "n_files"
    assert mine.reason_kind("training_repo: o/r") == "training_repo"
    assert mine.reason_kind("unsupported language: svelte") == "unsupported language"
    assert mine.reason_kind("fix_commit_date 2026-05-01 <= 2026-05-31") == "fix_commit_date"


# ---- the whole run against a fake GitHub (no network) ----

def _commit(sha, repo, files, date="2026-07-01T10:00:00Z"):
    return 200, {"x-ratelimit-remaining": "4000"}, json.dumps(
        {"sha": sha, "html_url": f"https://github.com/{repo}/commit/{sha}",
         "commit": {"author": {"date": date}, "committer": {"date": date}},
         "parents": [{"sha": "p" * 40}], "files": [{"filename": f} for f in files]}).encode()


def test_mine_testset_end_to_end_with_cached_github(tmp_path):
    from eval import manifest
    a, b, c, d = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)
    path = _zip(tmp_path, [_osv("GHSA-ok01", "2026-07-01", shas=(a,)),
                           _osv("GHSA-sm01", "2026-07-02", cwes=("CWE-79",), shas=(b,)),
                           _osv("GHSA-mi01", "2026-07-03", repo="o/gone", shas=(c,)),
                           _osv("GHSA-tr01", "2026-07-04", repo="o/trained", shas=(d,))])
    mods = json.dumps({"encoding": "base64", "content": base64.b64encode(b"[submodule]\n path = vendor/lib\n")
                       .decode()}).encode()
    responses = {f"/repos/o/r/commits/{a}": _commit(a, "O/R", ["src/a.py", "tests/test_a.py"]),
                 f"/repos/o/r/commits/{b}": _commit(b, "O/R", ["src/b.js", "vendor/lib"]),
                 f"/repos/o/trained/commits/{d}": _commit(d, "o/trained", ["src/d.py"]),
                 f"/contents/.gitmodules?ref={b}": (200, {}, mods)}
    calls = []

    def get(url):
        calls.append(url)
        return next((v for k, v in responses.items() if url.endswith(k)), (404, {}, b'{"message": "Not Found"}'))

    kw = dict(cache_path=str(tmp_path / "gh.jsonl"), splits={}, split_repos={"o/trained"}, get=get,
              sleep=lambda s: None, clock=lambda: 0.0, log=lambda *x: None)
    selected, assessed, summary = mine.mine_testset([path], **kw)
    why = {x["id"]: (x["tier"], x["reasons"][0]) for x in assessed}
    assert [x["id"] for x in selected] == ["GHSA-ok01"]
    assert why["GHSA-sm01"] == ("excluded", "submodule: the fix touches vendor/lib")
    assert why["GHSA-mi01"] == ("excluded", "commit_missing")
    assert why["GHSA-tr01"] == ("excluded", "training_repo: o/trained")
    assert summary["submodule_check"]["checked"] == 2 and summary["submodule_check"]["fix_touches_submodule"] == 1
    assert summary["by_kind"]["dataflow"]["manifest"] == 1
    row = mine.manifest_row(selected[0])
    assert row["vulnerable_commit"] == "p" * 40 and row["patched_commit"] == a and row["repo"] == "o/r"
    assert row["language"] == "py" and row["n_files"] == 1 and row["fix_commit_date"] == "2026-07-01"
    assert manifest.validate({"repos": [row]}, split_repos={"o/trained"}) == []
    assert [x["selection"] for x in assessed] == ["manifest", None, None, None]

    calls.clear()                                   # a rerun is served from the cache
    again, _, summary2 = mine.mine_testset([path], **kw)
    assert [x["id"] for x in again] == ["GHSA-ok01"] and summary2 == summary
    assert not any("/contents/" in u or "/commits/" in u for u in calls)
