from eval.dataset import check

BASE = {"row": "1", "repo": "r", "lang": "py", "ghsa": "G", "cve": "C",
        "advisory_published": "2026-08-01", "cwe": "CWE-89", "summary": "s",
        "fix_commit": "abc", "status": "candidate", "fix_commit_date": "2026-08-01",
        "loc_first_party": "90000"}


def test_headline_when_both_dates_after_cutoff():
    tier, _ = check.classify(BASE)
    assert tier == "headline"


def test_control_when_fix_commit_before_cutoff():
    r = dict(BASE, fix_commit_date="2025-08-28")
    tier, reasons = check.classify(r)
    assert tier == "control" and any("fix_commit_date" in x for x in reasons)


def test_scale_when_repo_over_one_million_loc():
    r = dict(BASE, loc_first_party="1500000")
    assert check.classify(r)[0] == "scale"


def test_excluded_status_passthrough():
    r = dict(BASE, status="excluded:bundled-fix")
    assert check.classify(r)[0] == "excluded"


def test_excluded_unsupported_language():
    r = dict(BASE, lang="go")
    assert check.classify(r)[0] == "excluded"


def test_load_candidates_skips_comments(tmp_path):
    p = tmp_path / "c.tsv"
    p.write_text("# a comment\nrow\trepo\tlang\n1\tr\tpy\n")
    rows = check.load_candidates(str(p))
    assert rows == [{"row": "1", "repo": "r", "lang": "py"}]


# ---- row-driven rules for mined test-set rows (each fires only when its key is present) ----

def _tier(**kw):
    return check.classify(dict(BASE, **kw))


def test_training_repo_is_excluded():
    tier, reasons = _tier(training_repo="o/trained")
    assert tier == "excluded" and reasons[0].startswith("training_repo")


def test_multi_commit_fix_is_excluded_single_is_not():
    tier, reasons = _tier(fix_shas=["a", "b"])
    assert tier == "excluded" and reasons[0].startswith("multi_commit_fix")
    assert _tier(fix_shas=["a"])[0] == "headline"


def test_bundled_fix_is_excluded():
    tier, reasons = _tier(shared_fix_with=["CVE-X"])
    assert tier == "excluded" and reasons[0].startswith("bundled_fix") and "CVE-X" in reasons[0]
    assert _tier(shared_fix_with=[])[0] == "headline"


def test_commit_not_ok_is_excluded():
    assert _tier(enrich_status="commit_missing") == ("excluded", ["commit_missing"])
    assert _tier(enrich_status="error")[1][0].startswith("commit_fetch_error")
    assert _tier(enrich_status="pending")[1][0].startswith("commit_not_fetched")
    assert _tier(enrich_status="ok")[0] == "headline"


def test_truncated_file_list_is_excluded():
    tier, reasons = _tier(files_truncated=True, n_files=None)
    assert tier == "excluded" and reasons[0].startswith("files_truncated")


def test_more_than_ten_non_test_files_is_excluded():
    tier, reasons = _tier(n_files=11)
    assert tier == "excluded" and reasons[0].startswith("n_files 11 > 10")
    assert _tier(n_files=10)[0] == "headline"


def test_fix_inside_a_submodule_is_excluded():
    tier, reasons = _tier(submodule_paths=["vendor/lib"])
    assert tier == "excluded" and reasons[0].startswith("submodule") and "vendor/lib" in reasons[0]
    assert _tier(submodule_paths=[], submodule_check="ok")[0] == "headline"
    assert _tier(submodule_check="error")[1][0].startswith("submodule_check_error")


def test_missing_dates_are_excluded_not_headline():
    assert _tier(fix_commit_date=None) == ("excluded", ["fix_commit_date missing"])
    assert _tier(advisory_published=None) == ("excluded", ["advisory_published missing"])


def test_earlier_public_record_makes_control():
    tier, reasons = _tier(advisory_first_public="2026-05-20", advisory_first_public_basis="nvd_published_at")
    assert tier == "control" and any("advisory_first_public 2026-05-20" in r and "nvd_published_at" in r
                                     for r in reasons)
    assert _tier(advisory_first_public="2026-06-02")[0] == "headline"


def test_loc_missing_is_not_scale_and_does_not_crash():
    assert _tier(loc_first_party=None)[0] == "headline"
