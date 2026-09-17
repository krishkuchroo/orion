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
