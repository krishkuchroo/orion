import json
from eval.dataset import enrich


def fake_run_ok(cmd):
    return json.dumps({"commit": {"author": {"date": "2026-08-20T18:00:00Z"}},
                       "files": [{"filename": "src/app.ts"},
                                 {"filename": "src/app.test.ts"},
                                 {"filename": "lib/util.ts"}]})


def test_commit_meta_parses_date_and_filters_tests():
    m = enrich.commit_meta("o/r", "abc", run=fake_run_ok)
    assert m["fix_commit_date"] == "2026-08-20"
    assert m["files"] == ["src/app.ts", "lib/util.ts"]
    assert m["n_files"] == 2


def test_enrich_all_records_error_without_raising():
    def boom(cmd):
        raise RuntimeError("gh failed")
    out = enrich.enrich_all([{"row": "1", "repo": "o/r", "fix_commit": "abc"}], run=boom)
    assert out[0]["fix_commit_date"] == "" and out[0]["n_files"] is None
    assert "enrich_error" in out[0]
