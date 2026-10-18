from train import filters


def row(id, **kw):
    r = {"id": id, "source": "osv-npm", "source_id": kw.pop("source_id", id), "aliases": [id], "repo": "o/ok",
         "fix_sha": (id.lower().replace("-", "") + "0" * 40)[:40], "fix_pr": None, "language": "js",
         "cwe": ["CWE-79"], "cwe_class": "dataflow", "advisory_published": "2026-04-01",
         "enrich_status": "ok", "fix_commit_date": "2026-04-02", "n_files": 2, "n_files_lang": 2, "packages": []}
    r.update(kw)
    return r


def reasons(dropped):
    return {d["id"]: d["reason"] for d in dropped}


def test_keeps_only_pre_cutoff_pairs_and_drops_leaky_repos():
    pairs = [row("C1", repo="o/leaky"),
             row("C2", advisory_published="2026-07-01", fix_commit_date="2026-07-02"),
             row("C3"),
             row("C4", fix_commit_date="2026-06-15")]
    kept, dropped = filters.keep(pairs, post_cutoff_repos={"o/leaky"})
    assert {p["id"] for p in kept} == {"C3"}
    r = reasons(dropped)
    assert r["C1"].startswith("post_cutoff_repo")
    assert r["C2"].startswith("advisory_after_cutoff")
    assert r["C4"].startswith("fix_after_cutoff")


def test_cutoff_is_strict_on_both_dates():
    pairs = [row("A", advisory_published="2026-05-31"), row("F", fix_commit_date="2026-05-31"),
             row("OK", advisory_published="2026-05-30", fix_commit_date="2026-05-30")]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert [p["id"] for p in kept] == ["OK"]
    assert reasons(dropped) == {"A": "advisory_after_cutoff", "F": "fix_after_cutoff"}


def test_missing_values_stay_null_and_are_counted_under_a_reason():
    pairs = [row("NOADV", advisory_published=None),
             row("PEND", enrich_status="pending", fix_commit_date=None, n_files=None),
             row("GONE", enrich_status="commit_missing", fix_commit_date=None, n_files=None),
             row("ERR", enrich_status="error", fix_commit_date=None, n_files=None),
             row("NODATE", fix_commit_date=None)]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert kept == []
    assert reasons(dropped) == {"NOADV": "advisory_date_missing", "PEND": "enrich_pending",
                                "GONE": "commit_missing", "ERR": "enrich_error", "NODATE": "fix_date_missing"}
    by_id = {d["id"]: d for d in dropped}
    assert by_id["NOADV"]["advisory_published"] is None and by_id["PEND"]["fix_commit_date"] is None


def test_fix_commit_presence_reasons():
    pairs = [row("NG", repo=None, fix_sha=None, repo_url="https://gitlab.com/x/y"),
             row("PR", fix_sha=None, fix_pr=7),
             row("NONE", repo=None, fix_sha=None)]
    _, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert reasons(dropped) == {"NG": "non_github_repo", "PR": "fix_pr_unresolved", "NONE": "no_fix_commit"}


def test_language_filter():
    pairs = [row("GO", language="go"), row("UNK", language=None), row("MIX", language="mixed"),
             row("PY", language="py"), row("JAVA", language="java")]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert {p["id"] for p in kept} == {"PY", "JAVA"}
    assert reasons(dropped) == {"GO": "language_unsupported:go", "UNK": "language_unknown",
                                "MIX": "language_unsupported:mixed"}


def test_post_cutoff_package_and_canonical_repo_leaks():
    pairs = [row("PKG", packages=[["npm", "hot"]]),
             row("REN", repo="old/name", repo_canonical="new/name"),
             row("OK", packages=[["npm", "cold"]])]
    kept, dropped = filters.keep(pairs, post_cutoff_repos={"new/name"}, post_cutoff_packages={("npm", "hot")})
    assert [p["id"] for p in kept] == ["OK"]
    assert reasons(dropped) == {"PKG": "post_cutoff_package", "REN": "post_cutoff_repo"}


def test_fix_touching_no_files_in_the_language_is_dropped():
    pairs = [row("POM", language="java", n_files_lang=0), row("UNKNOWN_LANG_FILES", n_files_lang=None)]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert [p["id"] for p in kept] == ["UNKNOWN_LANG_FILES"]
    assert reasons(dropped) == {"POM": "no_source_files_in_language"}


def test_dedupe_by_alias_then_commit_and_merge_survivor():
    pairs = [row("CVE-1", source="osv-maven", source_id="GHSA-x", aliases=["CVE-1", "GHSA-x"], cwe=["CWE-20"],
                 cwe_class="other", advisory_published="2023-02-01", repo="o/r", fix_sha="a" * 40, language="java"),
             row("CVE-1", source="cwe-bench-java", source_id="slug", aliases=["CVE-1"], cwe=["CWE-22"],
                 cwe_class="dataflow", advisory_published="2023-03-01", repo="o/r", fix_sha="b" * 40, language="java"),
             row("CVE-2", source="osv-maven", aliases=["CVE-2"], repo="o/r", fix_sha="b" * 40, language="java")]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert len(kept) == 1
    k = kept[0]
    assert k["source"] == "cwe-bench-java"                                   # ready-made wins
    assert set(k["aliases"]) == {"CVE-1", "GHSA-x"} and k["cwe"] == ["CWE-20", "CWE-22"]
    assert k["cwe_class"] == "dataflow" and k["advisory_published"] == "2023-02-01"
    assert k["sources"] == ["cwe-bench-java:slug", "osv-maven:GHSA-x"]
    r = sorted(d["reason"] for d in dropped)
    assert r == ["duplicate_alias:CVE-1", "duplicate_commit:CVE-1"]


def test_dedupe_prefers_ghsa_over_pysec_and_happens_after_row_checks():
    pairs = [row("CVE-5", source="osv-pypi", source_id="PYSEC-1", aliases=["CVE-5", "PYSEC-1", "GHSA-5"], language="py"),
             row("CVE-5", source="osv-pypi", source_id="GHSA-5", aliases=["CVE-5", "GHSA-5"], language="py"),
             row("CVE-6", source="cwe-bench-java", aliases=["CVE-6"], language="java", enrich_status="commit_missing",
                 fix_commit_date=None),
             row("CVE-6", source="osv-maven", aliases=["CVE-6"], language="java", fix_sha="e" * 40)]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert sorted((k["id"], k["source_id"]) for k in kept) == [("CVE-5", "GHSA-5"), ("CVE-6", "CVE-6")]
    assert {k["id"]: k["source"] for k in kept}["CVE-6"] == "osv-maven"      # a broken commit never shadows a good one


def test_files_filter_buckets():
    pairs = [row("F5", n_files=5), row("F15", n_files=15), row("F25", n_files=25), row("FUNK", n_files=None)]
    k10, d10 = filters.keep(pairs, post_cutoff_repos=set(), max_files=10)
    assert [p["id"] for p in k10] == ["F5"]
    assert reasons(d10) == {"F15": "too_many_files", "F25": "too_many_files", "FUNK": "files_unknown"}
    k20, _ = filters.keep(pairs, post_cutoff_repos=set(), max_files=20)
    assert {p["id"] for p in k20} == {"F5", "F15"}
    kany, dany = filters.keep(pairs, post_cutoff_repos=set(), max_files=None)
    assert {p["id"] for p in kany} == {"F5", "F15", "F25", "FUNK"} and dany == []


def test_no_per_repo_cap():
    pairs = [row(f"CVE-{i}", aliases=[f"CVE-{i}"], fix_sha=f"{i:040d}") for i in range(6)]
    kept, _ = filters.keep(pairs, post_cutoff_repos=set())
    assert len(kept) == 6


def test_reason_stage_order_covers_every_reason():
    pairs = [row("X", language="go"), row("Y", n_files=99)]
    _, dropped = filters.keep(pairs, post_cutoff_repos=set())
    for d in dropped:
        assert filters.reason_kind(d["reason"]) in filters.STAGES


def test_llm_assisted_rows_are_dropped_unless_explicitly_allowed():
    pairs = [row("CVE-9", source="pyvul", llm_assisted_labels=True, language="py"), row("CVE-10")]
    kept, dropped = filters.keep(pairs, post_cutoff_repos=set())
    assert [p["id"] for p in kept] == ["CVE-10"] and reasons(dropped) == {"CVE-9": "llm_assisted_labels"}
    kept, _ = filters.keep(pairs, post_cutoff_repos=set(), allow_llm_assisted=True)
    assert {p["id"] for p in kept} == {"CVE-9", "CVE-10"}


def test_pre_enrichment_check_lets_pr_only_rows_through_to_be_resolved():
    pr = row("PR", fix_sha=None, fix_pr=7, enrich_status="pending")
    assert filters.row_reason(pr, stop_before_enrichment=True) is None
    assert filters.row_reason(pr) == "fix_pr_unresolved"


def test_survivor_inherits_location_annotations_and_class_tag_from_duplicates():
    pairs = [row("CVE-7", source="osv-npm", aliases=["CVE-7", "GHSA-7"], cwe=[], cwe_class="unknown",
                 packages=[["npm", "a"]]),
             row("CVE-7", source="vulcan", aliases=["CVE-7"], cwe=[], cwe_class="unknown",
                 locations=[{"sink": {"file": "a.js", "lineno": 3}}], packages=[["npm", "a"]]),
             row("CVE-8", source="secbench-js", aliases=["CVE-8"], cwe=[], cwe_class="dataflow",
                 cwe_class_basis="vuln_class", sink_location="a.js:1:1", fix_sha="8" * 40),
             row("CVE-8", source="crossvul", aliases=["CVE-8"], cwe=[], cwe_class="unknown", fix_sha="9" * 40)]
    kept, _ = filters.keep(pairs, post_cutoff_repos=set())
    k = {p["id"]: p for p in kept}
    assert k["CVE-7"]["source"] == "vulcan" and k["CVE-7"]["locations"][0]["sink"]["lineno"] == 3
    assert k["CVE-8"]["cwe_class"] == "dataflow" and k["CVE-8"]["sink_location"] == "a.js:1:1"


def test_unresolved_pr_is_judged_at_the_enrichment_step_not_before_the_date_and_leak_checks():
    pairs = [row("LATE", fix_sha=None, fix_pr=3, advisory_published="2026-07-01"),
             row("LEAK", fix_sha=None, fix_pr=4, repo="o/leaky"),
             row("OPEN", fix_sha=None, fix_pr=5)]
    _, dropped = filters.keep(pairs, post_cutoff_repos={"o/leaky"})
    assert reasons(dropped) == {"LATE": "advisory_after_cutoff", "LEAK": "post_cutoff_repo",
                                "OPEN": "fix_pr_unresolved"}
