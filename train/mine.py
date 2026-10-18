"""Training-pair miner driver: collect -> (enrich_gh) -> build.

    # 1. load every downloaded source, build the leak sets, list the commits worth fetching
    ./.venv/bin/python -I train/mine.py collect --raw <RAW> --work <RAW>/mined
    # 2. fetch fix-commit dates + files from GitHub (resumable; Ctrl-C safe)
    ./.venv/bin/python -I train/enrich_gh.py --candidates <RAW>/mined/candidates.json
    # 3. apply the cache, filter, write pairs/dropped + measured count tables
    ./.venv/bin/python -I train/mine.py build --raw <RAW> --work <RAW>/mined --out train/data

<RAW> defaults to ~/Documents/OrionLutherLeo/orion-lm-research/raw (downloads live outside the repo,
one directory per source; they are parsed as data only, never executed).
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict

if __package__ in (None, ""):  # run as a script under `python -I`: put the repo root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from train import cve_dates, enrich_gh, filters, sources  # noqa: E402

DEFAULT_RAW = os.path.expanduser("~/Documents/OrionLutherLeo/orion-lm-research/raw")
OSV_ZIPS = ("osv-npm/all.zip", "osv-pypi/all.zip", "osv-maven/all.zip")

# name -> (relative path under RAW, loader(path, stats) -> rows)
LOADERS = {
    "osv-npm": ("osv-npm/all.zip", lambda p, st: sources.osv_pairs(p, ecosystem="npm", stats=st)),
    "osv-pypi": ("osv-pypi/all.zip", lambda p, st: sources.osv_pairs(p, ecosystem="pypi", stats=st)),
    "osv-maven": ("osv-maven/all.zip", lambda p, st: sources.osv_pairs(p, ecosystem="maven", stats=st)),
    # CWE-Bench-Java v2 (213 CVEs) lives in iris-sast/iris@v2 data/; its advisory JSONs (dates) only exist in
    # the older iris-sast/cwe-bench-java repo for the original 120 CVEs.
    "cwe-bench-java": ("cwe-bench-java-iris-v2", lambda p, st: sources.readymade(
        "cwe-bench-java", p, advisory_dir=os.path.join(os.path.dirname(p), "cwe-bench-java",
                                                       "cwe-bench-java-master", "advisory"))),
    "openssf": ("openssf-cve-benchmark/ossf-cve-benchmark-main",
                lambda p, st: sources.readymade("openssf", p, stats=st)),
    "vul4j": ("vul4j/vul4j_dataset.csv", lambda p, st: sources.readymade("vul4j", p)),
    "sap-kb": ("sap-project-kb/project-kb-vulnerability-data", lambda p, st: sources.sap_kb(p)),
    "crossvul": ("crossvul/metadata.json", lambda p, st: sources.crossvul(p)),
    "cvefixes": ("cvefixes-v1.0.0/CVEfixes_v1.0.0.zip", lambda p, st: sources.cvefixes(p)),
    "vulcan": ("vulcan/repo/dataset/reviews", lambda p, st: sources.vulcan(p)),
    "secbench-js": ("secbench-js/repo", lambda p, st: sources.secbench_js(p)),
    "javavulbench": ("javavulbench/benchmark.jsonl", lambda p, st: sources.javavulbench(p)),
    "repopairbench": ("repopairbench/repopairbench_100.jsonl", lambda p, st: sources.repopairbench(p)),
    "pyvul": ("pyvul", lambda p, st: sources.pyvul(p)),   # LLM-assisted labels: tagged, dropped by default
}

# funnel stages (reason kinds dropped at each step, in check order)
FUNNEL = (("labels not LLM-assisted", {"llm_assisted_labels"}),
          ("has GitHub fix commit", {"no_fix_commit", "non_github_repo", "fix_pr_unresolved"}),
          ("language JS/TS, Python, Java", {"language_unknown", "language_unsupported"}),
          ("advisory < cutoff", {"advisory_date_missing", "advisory_after_cutoff"}),
          ("not a post-cutoff repo/package", {"post_cutoff_repo", "post_cutoff_package"}),
          ("fix commit found, < cutoff, touches language",
           {"enrich_pending", "commit_missing", "enrich_error", "fix_date_missing", "fix_after_cutoff",
            "no_source_files_in_language"}),
          ("after dedupe", {"duplicate_alias", "duplicate_commit"}))


# dropped.json keeps only what is needed to audit a drop (full rows stay in <work>/rows.json)
DROPPED_FIELDS = ("id", "source", "source_id", "cve", "ghsa", "repo", "repo_url", "fix_sha", "fix_pr", "language",
                  "cwe", "cwe_class", "advisory_published", "fix_commit_date", "enrich_status", "n_files", "reason")


def _dump(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=None, separators=(",", ":"), sort_keys=True, default=sorted)
        f.write("\n")


def _load(path):
    with open(path) as f:
        return json.load(f)


def collect(raw: str, work: str, *, cve_cache: str = cve_dates.DEFAULT_CACHE, log=print) -> dict:
    rows, stats = [], {}
    for name, (rel, loader) in LOADERS.items():
        path = os.path.join(raw, rel)
        if not os.path.exists(path):
            stats[name] = {"status": f"not downloaded ({rel} missing)"}
            log(f"[collect] {name}: skipped, {rel} missing")
            continue
        st: dict = {}
        got = loader(path, st)
        st["rows"] = len(got)
        stats[name] = st
        rows += got
        log(f"[collect] {name}: {len(got)} rows {st}")
    idx = sources.advisory_date_index(rows)
    rows = sources.fill_advisory_dates(rows, idx)
    rows = cve_dates.fill(rows, cve_dates.index(cve_cache))
    cve_todo = sorted({a for r in rows if not r.get("advisory_published") and (r.get("fix_sha") or r.get("fix_pr"))
                       for a in r.get("aliases") or [] if a.upper().startswith("CVE-")})
    leak = sources.post_cutoff([os.path.join(raw, z) for z in OSV_ZIPS if os.path.exists(os.path.join(raw, z))])
    # any non-OSV source row published on/after the cutoff also names a test-set-era repo
    extra = {r["repo"] for r in rows if r.get("repo") and r.get("advisory_published")
             and r["advisory_published"] >= sources.CUTOFF and not r["source"].startswith("osv-")}
    leak["repos_from_other_sources"] = extra - leak["repos"]
    leak["repos"] = leak["repos"] | extra
    pre = [r for r in rows if not filters.row_reason(r, post_cutoff_repos=leak["repos"],
                                                      post_cutoff_packages=leak["packages"],
                                                      stop_before_enrichment=True, allow_unknown_language=True,
                                                      allow_llm_assisted=True)]   # fetched last, for the "if allowed" count
    cand = [r for r in pre if enrich_gh.needs_github(r)]
    cand.sort(key=lambda r: (filters._rank(r)[0], {"dataflow": 0, "other": 1}.get(r["cwe_class"], 2), r["id"]))
    _dump(os.path.join(work, "rows.json"), rows)
    _dump(os.path.join(work, "leak.json"), {k: sorted(map(list, v)) if k == "packages" else
                                            sorted(v) if isinstance(v, set) else v for k, v in leak.items()})
    _dump(os.path.join(work, "candidates.json"), cand)
    _dump(os.path.join(work, "cve_todo.json"), cve_todo)
    keys = {(r["repo"], r.get("fix_sha") or f"pr{r.get('fix_pr')}") for r in cand}
    stats["_collect"] = {"rows": len(rows), "pass_pre_enrichment_checks": len(pre),
                         "need_github": len(cand), "distinct_github_objects": len(keys),
                         "cve_ids_without_any_date": len(cve_todo),
                         "post_cutoff_repos": len(leak["repos"]), "post_cutoff_packages": len(leak["packages"]),
                         "post_cutoff_advisories": leak["n_advisories"],
                         "malware_only_repos_not_in_leak_set": len(leak["malware_repos"]),
                         "post_cutoff_repos_from_other_sources": len(leak["repos_from_other_sources"])}
    _dump(os.path.join(work, "collect_stats.json"), stats)
    log(json.dumps(stats["_collect"]))
    return stats


# ---- counting -----------------------------------------------------------------------------------

def funnel(raw_by_source: Counter, dropped_any: list[dict], kept_any: list[dict]) -> dict:
    """Survivors per source after each FUNNEL stage, from the reasons of a max_files=None run, plus
    the size buckets of the deduped survivors (n_files <=10, <=20, any)."""
    drops = defaultdict(Counter)
    for d in dropped_any:
        kind = filters.reason_kind(d["reason"])
        for i, (_, kinds) in enumerate(FUNNEL):
            if kind in kinds:
                drops[d["source"]][i] += 1
                break
    out = {}
    for src in sorted(set(raw_by_source) | set(drops)):
        alive, steps = raw_by_source[src], []
        for i, (label, _) in enumerate(FUNNEL):
            alive -= drops[src][i]
            steps.append(alive)
        mine = [k for k in kept_any if k["source"] == src]
        out[src] = {"raw": raw_by_source[src], "stages": steps, **buckets(mine)}
    return out


def buckets(rows) -> dict:
    n = [r.get("n_files") for r in rows]
    return {"files_le10": sum(1 for x in n if x is not None and x <= 10),
            "files_le20": sum(1 for x in n if x is not None and x <= 20),
            "files_any": len(n), "files_unknown": sum(1 for x in n if x is None)}


def _table(header, rows) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def build(raw: str, work: str, out: str, *, cache_path: str = enrich_gh.DEFAULT_CACHE, log=print) -> dict:
    rows = _load(os.path.join(work, "rows.json"))
    leak = _load(os.path.join(work, "leak.json"))
    leak_repos, leak_pkgs = set(leak["repos"]), {tuple(p) for p in leak["packages"]}
    cache = enrich_gh.Cache(cache_path)
    rows = enrich_gh.apply(rows, cache)
    kw = dict(post_cutoff_repos=leak_repos, post_cutoff_packages=leak_pkgs)
    kept10, dropped10 = filters.keep(rows, max_files=10, **kw)
    kept20, _ = filters.keep(rows, max_files=20, **kw)
    kept_any, dropped_any = filters.keep(rows, max_files=None, **kw)
    kept_llm10, _ = filters.keep(rows, max_files=10, allow_llm_assisted=True, **kw)
    kept_llm_any, _ = filters.keep(rows, max_files=None, allow_llm_assisted=True, **kw)

    os.makedirs(out, exist_ok=True)
    _dump(os.path.join(out, "pairs.json"), kept10)
    slim = [{k: d.get(k) for k in DROPPED_FIELDS} for d in dropped10]
    _dump(os.path.join(out, "dropped.json"), slim)

    raw_by_source = Counter(r["source"] for r in rows)
    st: dict = {"funnel": funnel(raw_by_source, dropped_any, kept_any)}
    st["reasons_max10"] = dict(Counter(filters.reason_kind(d["reason"]) for d in dropped10).most_common())
    st["reasons_by_source_max10"] = {s: dict(c.most_common()) for s, c in sorted(
        _group(dropped10, lambda d: d["source"], lambda d: filters.reason_kind(d["reason"])).items())}
    st["other_language_by_source"] = {s: dict(c.most_common()) for s, c in sorted(
        _group([d for d in dropped_any if filters.reason_kind(d["reason"]) in ("language_unsupported", "language_unknown")],
               lambda d: d["source"], lambda d: d.get("language") or "unknown").items())}
    st["cwe_class"] = {name: dict(Counter(r["cwe_class"] for r in ks)) for name, ks in
                       (("files_le10", kept10), ("files_le20", kept20), ("files_any", kept_any))}
    st["cwe_class_raw"] = dict(Counter(r["cwe_class"] for r in rows))
    st["language"] = {name: dict(Counter(r["language"] for r in ks)) for name, ks in
                      (("files_le10", kept10), ("files_le20", kept20), ("files_any", kept_any))}
    st["language_x_cwe_class_le10"] = {f"{l}/{c}": n for (l, c), n in sorted(
        Counter((r["language"], r["cwe_class"]) for r in kept10).items())}
    st["distinct_repos"] = {name: len({r.get("repo_canonical") or r["repo"] for r in ks}) for name, ks in
                            (("files_le10", kept10), ("files_le20", kept20), ("files_any", kept_any))}
    passed_rows = sum(1 for d in dropped_any if filters.reason_kind(d["reason"]) in ("duplicate_alias", "duplicate_commit")) \
        + len(kept_any)
    st["dedupe"] = {"before": passed_rows, "after": len(kept_any),
                    "duplicate_alias": sum(1 for d in dropped_any if d["reason"].startswith("duplicate_alias")),
                    "duplicate_commit": sum(1 for d in dropped_any if d["reason"].startswith("duplicate_commit"))}
    st["multi_source_survivors"] = sum(1 for r in kept_any if len(r.get("sources") or []) > 1)
    st["missing"] = {k: st["reasons_max10"].get(k, 0) for k in
                     ("advisory_date_missing", "enrich_pending", "commit_missing", "enrich_error",
                      "fix_date_missing", "files_unknown")}
    st["leak"] = {"post_cutoff_repos": len(leak_repos), "post_cutoff_packages": len(leak_pkgs),
                  "post_cutoff_advisories": leak.get("n_advisories"),
                  "malware_only_repos_not_in_leak_set": len(leak.get("malware_repos") or []),
                  "post_cutoff_repos_with_pre_cutoff_fix_rows":
                      len(leak_repos & {r["repo"] for r in rows if r.get("repo") and r.get("fix_sha")
                                        and r.get("advisory_published") and r["advisory_published"] < sources.CUTOFF})}
    st["enrichment"] = {"cache_records": len(cache.records),
                        "cache_statuses": dict(Counter(r.get("status") for r in cache.records.values())),
                        "rows_by_enrich_status": dict(Counter(r.get("enrich_status") for r in rows)),
                        "language_from_fix_files": sum(1 for r in rows if r.get("language_basis") == "fix_files")}
    llm_rows = [r for r in rows if r.get("llm_assisted_labels")]
    st["llm_assisted"] = {"rows": len(llm_rows), "sources": dict(Counter(r["source"] for r in llm_rows)),
                          "extra_pairs_if_allowed_files_le10": len(kept_llm10) - len(kept10),
                          "extra_pairs_if_allowed_files_any": len(kept_llm_any) - len(kept_any),
                          "pairs_if_allowed_files_le10": len(kept_llm10)}
    fix_links = set(leak.get("repos_fix_links") or [])
    st["leak"]["rows_dropped_only_because_of_non_fix_link_repo_refs"] = sum(
        1 for d in dropped_any if d["reason"] == "post_cutoff_repo" and d["repo"] not in fix_links
        and (d.get("repo_canonical") or d["repo"]) not in fix_links)
    st["leak"]["post_cutoff_repos_from_fix_links_only"] = len(fix_links)
    st["sizes_bytes"] = {f: os.path.getsize(os.path.join(out, f)) for f in ("pairs.json", "dropped.json")}
    _dump(os.path.join(work, "build_stats.json"), st)
    with open(os.path.join(work, "tables.md"), "w") as f:
        f.write(tables(st))
    log(tables(st))
    return st


def _group(rows, key, val):
    g = defaultdict(Counter)
    for r in rows:
        g[key(r)][val(r)] += 1
    return g


def tables(st: dict) -> str:
    labels = ["raw"] + [label for label, _ in FUNNEL] + ["files ≤10", "files ≤20", "files any"]
    fun = st["funnel"]
    rows = []
    tot = [0] * (len(labels))
    for src, f in fun.items():
        vals = [f["raw"], *f["stages"], f["files_le10"], f["files_le20"], f["files_any"]]
        tot = [a + b for a, b in zip(tot, vals)]
        rows.append([src, *vals])
    rows.append(["**total**", *tot])
    parts = ["### Funnel per source (rows surviving each step)\n", _table(["source", *labels], rows), ""]
    cc = st["cwe_class"]
    parts += ["### Kept pairs by cwe_class\n",
              _table(["cwe_class", "files ≤10", "files ≤20", "files any"],
                     [[c, cc["files_le10"].get(c, 0), cc["files_le20"].get(c, 0), cc["files_any"].get(c, 0)]
                      for c in ("dataflow", "other", "unknown")]), ""]
    lg = st["language"]
    parts += ["### Kept pairs by language\n",
              _table(["language", "files ≤10", "files ≤20", "files any"],
                     [[l, lg["files_le10"].get(l, 0), lg["files_le20"].get(l, 0), lg["files_any"].get(l, 0)]
                      for l in ("js", "py", "java")]), ""]
    parts += ["### Distinct repos in kept pairs\n",
              _table(["files ≤10", "files ≤20", "files any"],
                     [[st["distinct_repos"]["files_le10"], st["distinct_repos"]["files_le20"],
                       st["distinct_repos"]["files_any"]]]), ""]
    parts += ["### Drop reasons (≤10-files run)\n",
              _table(["reason", "rows"], list(st["reasons_max10"].items())), ""]
    parts += ["### Dedupe\n", _table(["before", "after", "duplicate_alias", "duplicate_commit"],
                                     [[st["dedupe"]["before"], st["dedupe"]["after"],
                                       st["dedupe"]["duplicate_alias"], st["dedupe"]["duplicate_commit"]]]), ""]
    parts += ["### Other-language / unknown-language rows skipped, by source\n",
              _table(["source", "languages (rows)"],
                     [[s, ", ".join(f"{k} {v}" for k, v in c.items())] for s, c in st["other_language_by_source"].items()]), ""]
    parts += ["### Leak set\n", _table(["metric", "value"], list(st["leak"].items())), ""]
    parts += ["### Missing values (rows dropped because a value could not be obtained)\n",
              _table(["reason", "rows"], list(st["missing"].items())), ""]
    parts += ["### LLM-assisted-label rows (PyVul; excluded by default)\n",
              _table(["metric", "value"], list(st["llm_assisted"].items())), ""]
    parts += ["### Enrichment\n", "```\n" + json.dumps(st["enrichment"], indent=1) + "\n```", ""]
    return "\n".join(parts)


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Orion-LM training-pair miner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("collect", "build"):
        p = sub.add_parser(name)
        p.add_argument("--raw", default=DEFAULT_RAW)
        p.add_argument("--work", default=os.path.join(DEFAULT_RAW, "mined"))
        if name == "build":
            p.add_argument("--out", default="train/data")
            p.add_argument("--cache", default=enrich_gh.DEFAULT_CACHE)
    args = ap.parse_args(argv)
    log = lambda *a: print(*a, flush=True)  # noqa: E731
    if args.cmd == "collect":
        collect(args.raw, args.work, log=log)
    else:
        build(args.raw, args.work, args.out, cache_path=args.cache, log=log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
