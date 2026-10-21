"""CVE publication dates from the official CVE Services API (cveawg.mitre.org), cached + resumable.

Used only for rows that carry no advisory date of their own and none via an alias (some ready-made /
mined datasets list a bare CVE id). ``datePublished`` of the CVE record is a real publication date;
a CVE the API does not know is recorded ``cve_missing`` and the row keeps ``advisory_published=None``.

    ./.venv/bin/python -I train/cve_dates.py --todo <RAW>/mined/cve_todo.json
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

if __package__ in (None, ""):  # run as a script under `python -I`: put the repo root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from train.sources import _date  # noqa: E402

API = "https://cveawg.mitre.org/api/cve/"
DEFAULT_CACHE = os.path.expanduser("~/Documents/OrionLutherLeo/orion-lm-research/raw/cve-cache/cve-records.jsonl")
FINAL = {"ok", "cve_missing"}


def urllib_get(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "orion-train-cve-dates"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read() or b""


def _load(path: str) -> dict[str, dict]:
    recs = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    recs[r["key"]] = r
    return recs


def fetch(cve: str, *, get, sleep, retries: int = 3) -> dict:
    attempt = 0
    while True:
        try:
            status, headers, body = get(API + cve)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            status, headers, body = None, {}, str(e).encode()
        if status == 429:
            sleep(float(headers.get("retry-after") or headers.get("ratelimit-reset") or 60))
            continue
        if status is None or status >= 500:
            attempt += 1
            if attempt >= retries:
                return {"key": cve, "status": "error", "http_status": status}
            sleep(2 ** attempt)
            continue
        if headers.get("ratelimit-remaining") is not None and int(headers["ratelimit-remaining"]) < 10:
            sleep(float(headers.get("ratelimit-reset") or 60))
        if status == 200:
            meta = (json.loads(body) or {}).get("cveMetadata") or {}
            return {"key": cve, "status": "ok", "http_status": 200, "state": meta.get("state"),
                    "date_published": _date(meta.get("datePublished"))}
        if status == 404:
            return {"key": cve, "status": "cve_missing", "http_status": 404}
        return {"key": cve, "status": "error", "http_status": status}


def run(cves, cache_path: str = DEFAULT_CACHE, *, get=urllib_get, sleep=time.sleep, log=print) -> dict:
    recs = _load(cache_path)
    todo = [c for c in dict.fromkeys(cves) if recs.get(c, {}).get("status") not in FINAL]
    log(f"[cve-dates] {len(todo)} to fetch ({len(recs)} cached)")
    os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
    counts: dict[str, int] = {}
    with open(cache_path, "a") as f:
        for i, cve in enumerate(todo, 1):
            rec = fetch(cve, get=get, sleep=sleep)
            f.write(json.dumps(rec, sort_keys=True) + "\n")
            f.flush()
            counts[rec["status"]] = counts.get(rec["status"], 0) + 1
            if i % 50 == 0 or i == len(todo):
                log(f"[{i}/{len(todo)}] {cve} -> {rec['status']}")
    return {"fetched": len(todo), "statuses": counts}


def index(cache_path: str = DEFAULT_CACHE) -> dict[str, str]:
    return {k: r["date_published"] for k, r in _load(cache_path).items()
            if r.get("status") == "ok" and r.get("date_published")}


def fill(rows, idx: dict[str, str]) -> list[dict]:
    out = []
    for r in rows:
        r = dict(r)
        if not r.get("advisory_published"):
            dates = [idx[a] for a in r.get("aliases") or [r["id"]] if a in idx]
            if dates:
                r["advisory_published"], r["advisory_published_basis"] = min(dates), "cve_record"
        out.append(r)
    return out


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--todo", required=True, help="JSON list of CVE ids (from `train/mine.py collect`)")
    ap.add_argument("--cache", default=DEFAULT_CACHE)
    args = ap.parse_args(argv)
    with open(args.todo) as f:
        cves = json.load(f)
    print(json.dumps(run(cves, args.cache, log=lambda *a: print(*a, flush=True))), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
