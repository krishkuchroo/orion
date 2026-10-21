import json
import zipfile
from collections import Counter

from train import enrich_gh, mine

SHA = "a" * 40


def _ghsa(gid, cve, repo, published, sha=SHA, cwes=("CWE-79",)):
    return {"id": gid, "published": published, "aliases": [cve],
            "affected": [{"package": {"ecosystem": "npm", "name": repo.split("/")[1]}}],
            "references": [{"type": "WEB", "url": f"https://github.com/{repo}/commit/{sha}"}],
            "database_specific": {"github_reviewed": True, "cwe_ids": list(cwes)}}


def test_funnel_counts_survivors_per_stage_and_size_buckets():
    dropped = [{"source": "s", "reason": "source_excluded:license_no_rights"}, {"source": "s", "reason": "no_fix_commit"}, {"source": "s", "reason": "language_unsupported:go"},
               {"source": "s", "reason": "post_cutoff_repo"}, {"source": "s", "reason": "duplicate_alias:X"}]
    kept = [{"source": "s", "n_files": 3}, {"source": "s", "n_files": 15}, {"source": "s", "n_files": None}]
    f = mine.funnel(Counter({"s": 8}), dropped, kept)["s"]
    assert f["raw"] == 8 and f["stages"] == [7, 7, 7, 6, 5, 5, 4, 4, 3]
    assert (f["files_le10"], f["files_le20"], f["files_any"], f["files_unknown"]) == (1, 2, 3, 1)


def test_collect_then_build_end_to_end(tmp_path):
    raw, work, out = tmp_path / "raw", tmp_path / "work", tmp_path / "out"
    (raw / "osv-npm").mkdir(parents=True)
    with zipfile.ZipFile(raw / "osv-npm" / "all.zip", "w") as z:
        for rec in [_ghsa("GHSA-good", "CVE-2024-1", "o/a", "2024-01-01T00:00:00Z"),
                    _ghsa("GHSA-leak", "CVE-2024-2", "o/b", "2024-02-01T00:00:00Z", sha="b" * 40),
                    _ghsa("GHSA-new", "CVE-2026-9", "o/b", "2026-08-01T00:00:00Z", sha="c" * 40)]:
            z.writestr(rec["id"] + ".json", json.dumps(rec))
    mine.collect(str(raw), str(work), cve_cache=str(tmp_path / "cve.jsonl"), log=lambda *a: None)
    cand = json.loads((work / "candidates.json").read_text())
    assert [c["id"] for c in cand] == ["CVE-2024-1"]                 # leaky + post-cutoff rows never fetched

    cache = tmp_path / "cache.jsonl"
    enrich_gh.Cache(str(cache)).add({"key": enrich_gh.commit_key("o/a", SHA), "kind": "commit", "status": "ok",
                                     "sha_full": SHA, "repo_canonical": "o/a", "author_date": "2024-01-01",
                                     "committer_date": "2024-01-01", "files": ["index.js"], "truncated": False})
    st = mine.build(str(raw), str(work), str(out), cache_path=str(cache), log=lambda *a: None)
    pairs = json.loads((out / "pairs.json").read_text())
    dropped = {d["id"]: d["reason"] for d in json.loads((out / "dropped.json").read_text())}
    assert [p["id"] for p in pairs] == ["CVE-2024-1"] and pairs[0]["n_files"] == 1
    assert dropped == {"CVE-2024-2": "post_cutoff_repo", "CVE-2026-9": "advisory_after_cutoff"}
    assert st["funnel"]["osv-npm"]["files_le10"] == 1 and st["leak"]["post_cutoff_repos"] == 1
