import json

from train import cve_dates


def test_fetch_and_cache_cve_publication_dates(tmp_path):
    calls = []

    def get(url):
        calls.append(url)
        if url.endswith("CVE-2017-1"):
            return 200, {"ratelimit-remaining": "100"}, json.dumps(
                {"cveMetadata": {"cveId": "CVE-2017-1", "datePublished": "2017-04-18T14:00:00.000Z", "state": "PUBLISHED"}}).encode()
        return 404, {}, b"{}"

    cache = tmp_path / "c.jsonl"
    s = cve_dates.run(["CVE-2017-1", "CVE-2099-9", "CVE-2017-1"], str(cache), get=get, sleep=lambda s: None,
                      log=lambda *a: None)
    assert s["fetched"] == 2 and len(calls) == 2
    idx = cve_dates.index(str(cache))
    assert idx == {"CVE-2017-1": "2017-04-18"}
    cve_dates.run(["CVE-2017-1", "CVE-2099-9"], str(cache), get=get, sleep=lambda s: None, log=lambda *a: None)
    assert len(calls) == 2                                  # both final -> nothing refetched


def test_fill_uses_cve_record_only_for_rows_without_a_date():
    rows = [{"id": "CVE-1", "aliases": ["CVE-1"], "advisory_published": None},
            {"id": "CVE-2", "aliases": ["CVE-2"], "advisory_published": "2020-01-01", "advisory_published_basis": "source"}]
    out = cve_dates.fill(rows, {"CVE-1": "2019-05-05", "CVE-2": "2018-01-01"})
    assert out[0]["advisory_published"] == "2019-05-05" and out[0]["advisory_published_basis"] == "cve_record"
    assert out[1]["advisory_published"] == "2020-01-01"
