# Orion-LM training pairs (Task D1): sources and measured counts

Built 2026-10-18 on branch `eval/orion-lm` (miner code: commit `2efa200`). Every number below
comes from actually running `train/mine.py build` on the data listed here. Nothing was
estimated or backfilled; a value that could not be obtained is `null` and is counted under a
"missing" reason. The OSV exports were downloaded 2026-10-18.

**Rules applied:**
- Training pairs are pre-cutoff: advisory published < 2026-05-31 AND fix commit < 2026-05-31.
  Both checks are strict.
- Every repo named by ANY advisory published on/after 2026-05-31 is dropped (the leak check),
  and so is every package named by one.
- Languages: JS/TS, Python and Java only.
- No frontier-model output and no LLM-made labels. PyVul is collected but tagged and excluded
  by default.
- Dedupe by CVE/GHSA alias, then by (repo, fix SHA). There is **no per-repo cap**.
- All CWEs are kept and tagged `dataflow` / `other` / `unknown`.
- The ≤10-files rule (non-test files) is a recorded drop reason. Counts are reported at ≤10,
  ≤20 and any. `train/data/pairs.json` is the ≤10 set.

## Sources

All downloads live in `~/Documents/OrionLutherLeo/orion-lm-research/raw/<source>/`, outside
the repo and one directory per source. They were parsed as data only: no setup.py, scripts or
notebooks from them were run, and the CVEfixes SQL dump was tokenised by hand rather than fed
to sqlite. Metadata-only files were fetched wherever a dataset offered them.

| source | official location | version | downloaded | status |
|---|---|---|---|---|
| OSV npm | storage.googleapis.com/osv-vulnerabilities/npm/all.zip | export of 2026-10-18 | 218,457,490 B | used (GHSA; 222,537 MAL-* and 399 withdrawn skipped) |
| OSV PyPI | …/PyPI/all.zip | export of 2026-10-18 | 36,437,960 B | used (GHSA + PYSEC; 11,848 MAL-* and 592 withdrawn skipped) |
| OSV Maven | …/Maven/all.zip | export of 2026-10-16 | 10,410,399 B | used (GHSA; 2 MAL-* and 113 withdrawn skipped) |
| CWE-Bench-Java v2 | github.com/iris-sast/iris branch `v2`, `data/` | `3a12f45` | 4 CSVs, 565,836 B | used (213 CVEs). The advisory JSONs (dates) for the original 120 come from github.com/iris-sast/cwe-bench-java `afe0ebd` (tarball 1,521,348 B). |
| OpenSSF CVE Benchmark | github.com/ossf-cve-benchmark/ossf-cve-benchmark | `91c59fd` | tarball 386,457 B | used (223 PUBLISHED CVE JSONs) |
| Vul4J | github.com/tuhh-softsec/vul4j `dataset/vul4j_dataset.csv` | `376411d` | 108,933 B | used (the repo itself is 2.6 GB and was not needed) |
| CVEfixes | zenodo.org/records/4476564 (v1.0.0, data to 2021-06-09) | v1.0.0 | 1,066,124,294 B | used. Dates and files come from the dump itself. |
| CrossVul | zenodo.org/records/4734050 `dataset.zip` | 2.0 | metadata.json 2,739,523 B + file_names.list 702,432 B (range-extracted from the 367,000,512 B zip) | used |
| SAP Project KB | github.com/SAP/project-kb branch `vulnerability-data` | `730d219` | tarball 62,619,506 B | used (1,297 statements, manually curated) |
| VulcaN | github.com/VulcaN-Study/Supplementary-Material `dataset/reviews/*.json` | `e72589b` | sparse clone, 957 reviews | used. Source→sink `locations` are kept per row. |
| SecBench.js | github.com/cristianstaicu/SecBench.js `<class>/*/package.json` | `5d36235` | sparse clone, 600 package.json | used (package, version, class, fix commit, sink). Exploits were not fetched or run. |
| JavaVulBench | zenodo.org/records/21353371 (concept 10.5281/zenodo.20110173) | 2026-07-14 | `benchmark.jsonl` 44,992,723 B (range-extracted from the 512,933,313 B core zip) | used (repo + fix SHA + CVE + CWE + NVD date). The method-level negatives are not used. |
| RepoPairBench (DREA) | github.com/huhusmang/DREA `data/repopairbench_100.jsonl` | `f858c49` | 358,751 B | used. **Its LICENSE is a placeholder** ("to be finalized before public release"). |
| PyVul | github.com/billquan/PyVul `dataset/` + `benchmark_curation/data_collection/` metadata | `1172bfd` | 5 metadata files, ~1.5 MB | **collected, tagged `llm_assisted_labels: true`, excluded by default** (see the PyVul section) |

**Not downloaded / not used:**

| source | location | size | why |
|---|---|---|---|
| MoreFixes | zenodo.org/records/20776007 `dump-2026-06-20.sql.gz` (+ `patch-files2026-06-20.zip`) | 3,472,298,400 B (+ 3,000,621,180 B) | Over the 3 GB per-source limit, so the user decides. The dump holds CVEs to 2026-06-02, so it would need date filtering. The patch-file names give (repo, sha) but no CVE, CWE or date, so they are unusable alone. |
| CVEfixes v1.0.8 | zenodo.org/records/13118970 | 12,708,711,268 B | over the limit (v1.0.0 used instead) |
| CVEfixes v1.0.7 | zenodo.org/records/7029359 | 3,858,462,238 B | over the limit |
| ReposVul | Google Drive links in github.com/Eshe0922/ReposVul README | unknown | Excluded on provenance: its "vulnerability untangling module" uses LLMs to pick the fix-related files (README). It could be handled like PyVul (tagged, excluded by default) if wanted. |
| JavaVulBench full tar | zenodo.org/records/21353371 `javavulbench-full.tar` | 38,777,763,840 B | not needed; the metadata is in the core zip |
| CWE-Bench-Java on Hugging Face | huggingface.co/datasets/iris-sast/CWE-Bench-Java | ~0.7 MB | Older and smaller than GitHub v2 (120 CVEs, predates the July 2025 SHA fixes) |
| IRIS `source_sink_detect.csv` | iris-sast/iris@v2 `data/` | 32,274 B | LLM detection results, so it was deleted after download and never used. The manual `fix_info_source_sink.csv` IS used. |

Total on disk: 1.4 GB. Free disk stayed above 80 GB.

## Headline (measured, final build 2026-10-18)

- **45,499 raw rows** across 14 sources. PyVul is collected but excluded.
- **4,344 unique pre-cutoff, leak-free pairs** survive every check except the size check. By
  fix size (non-test files):
  - ≤10 files: **4,058**
  - ≤20 files: **4,240**
  - any size: **4,344**
- Distinct repos: **2,466** (≤10), 2,542 (≤20), 2,585 (any).
- By cwe_class at ≤10 files: dataflow 1,784 · other 2,007 · unknown 267.
- By language at ≤10 files: JS/TS 1,790 · Python 516 · Java 1,752.
- `train/data/pairs.json` (the ≤10 set) is 5,515,175 B and `train/data/dropped.json` (41,441
  rows, each with a `reason`) is 16,618,559 B. Both are over 5 MB, so both are **gitignored**.
  They are in `train/data/` of this checkout. Full unfiltered rows are in
  `~/Documents/OrionLutherLeo/orion-lm-research/raw/mined/rows.json`.
- Pre-cutoff check: across the kept pairs, the latest advisory date is 2026-05-28 and the latest
  fix commit is 2026-05-26.

How to read the funnel: each column is the number of rows still alive after that check. The
checks run in order, and a row is counted at the first one it fails. "After dedupe" merges the
same vulnerability seen in several sources into one row; the survivor is the best-ranked source.
That is why per-source numbers fall sharply there: a CrossVul row that duplicates a CVEfixes or
OSV row is counted under the survivor's source. The kept set has 1,863 multi-source survivors.

### Funnel per source (rows surviving each step)

| source | raw | labels not LLM-assisted | has GitHub fix link | language JS/TS, Python, Java | advisory < cutoff | not a post-cutoff repo/package | fix commit found, < cutoff, touches language | after dedupe | files ≤10 | files ≤20 | files any |
|---|---|---|---|---|---|---|---|---|---|---|---|
| crossvul | 5203 | 5203 | 5199 | 738 | 738 | 521 | 504 | 44 | 42 | 42 | 44 |
| cvefixes | 5421 | 5421 | 5408 | 787 | 787 | 584 | 584 | 193 | 183 | 189 | 193 |
| cwe-bench-java | 213 | 213 | 205 | 205 | 205 | 125 | 115 | 113 | 105 | 111 | 113 |
| javavulbench | 1736 | 1736 | 1736 | 1736 | 1736 | 1114 | 1114 | 191 | 177 | 191 | 191 |
| openssf | 223 | 223 | 223 | 223 | 222 | 189 | 181 | 175 | 171 | 174 | 175 |
| osv-maven | 7077 | 7077 | 3654 | 3654 | 3333 | 1953 | 1551 | 1342 | 1231 | 1300 | 1342 |
| osv-npm | 7447 | 7447 | 4335 | 4335 | 3375 | 1872 | 1662 | 1215 | 1126 | 1182 | 1215 |
| osv-pypi | 13941 | 13941 | 8972 | 8972 | 5594 | 893 | 703 | 415 | 397 | 406 | 415 |
| pyvul | 1155 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| repopairbench | 100 | 100 | 100 | 100 | 99 | 47 | 46 | 29 | 29 | 29 | 29 |
| sap-kb | 1297 | 1297 | 1166 | 850 | 848 | 583 | 562 | 208 | 192 | 202 | 208 |
| secbench-js | 600 | 600 | 218 | 218 | 181 | 170 | 159 | 72 | 68 | 70 | 72 |
| vul4j | 129 | 129 | 127 | 127 | 74 | 57 | 56 | 51 | 51 | 51 | 51 |
| vulcan | 957 | 957 | 474 | 474 | 464 | 403 | 366 | 296 | 286 | 293 | 296 |
| **total** | 45499 | 44344 | 31817 | 22419 | 17656 | 8511 | 7603 | 4344 | 4058 | 4240 | 4344 |

### Funnel by cwe_class (steps by the row's own CWEs; dedupe/size columns by the merged survivor)

| cwe_class | raw | labels not LLM-assisted | has GitHub fix link | language JS/TS, Python, Java | advisory < cutoff | not a post-cutoff repo/package | fix commit found, < cutoff, touches language | after dedupe → files ≤10 | files ≤20 | files any |
|---|---|---|---|---|---|---|---|---|---|---|
| dataflow | 12523 | 12225 | 8282 | 6573 | 5792 | 3397 | 3014 | 1784 | 1867 | 1917 |
| other | 22699 | 21842 | 16685 | 9837 | 8468 | 3895 | 3500 | 2007 | 2091 | 2135 |
| unknown | 10277 | 10277 | 6850 | 6009 | 3396 | 1219 | 1089 | 267 | 282 | 292 |

### Repos losing the most rows to the leak check (post_cutoff_repo)

| repo | rows dropped |
|---|---|
| tensorflow/tensorflow | 1242 |
| openclaw/openclaw | 473 |
| jenkinsci/jenkins | 329 |
| xwiki/xwiki-platform | 284 |
| apache/tomcat | 227 |
| apache/airflow | 212 |
| keycloak/keycloak | 174 |
| django/django | 159 |
| fasterxml/jackson-databind | 146 |
| spring-projects/spring-framework | 112 |
| python-pillow/pillow | 94 |
| ansible/ansible | 91 |
| bcgit/bc-java | 86 |
| parse-community/parse-server | 83 |
| ikus060/rdiffweb | 83 |

### Kept pairs by cwe_class

| cwe_class | files ≤10 | files ≤20 | files any |
|---|---|---|---|
| dataflow | 1784 | 1867 | 1917 |
| other | 2007 | 2091 | 2135 |
| unknown | 267 | 282 | 292 |

### Kept pairs by language

| language | files ≤10 | files ≤20 | files any |
|---|---|---|---|
| js | 1790 | 1861 | 1903 |
| py | 516 | 527 | 537 |
| java | 1752 | 1852 | 1904 |

### Distinct repos in kept pairs

| files ≤10 | files ≤20 | files any |
|---|---|---|
| 2466 | 2542 | 2585 |

### Drop reasons (≤10-files run)

| reason | rows |
|---|---|
| no_fix_commit | 12436 |
| post_cutoff_repo | 8973 |
| language_unsupported | 8548 |
| advisory_after_cutoff | 4660 |
| duplicate_alias | 3018 |
| llm_assisted_labels | 1155 |
| language_unknown | 850 |
| no_source_files_in_language | 781 |
| too_many_files | 280 |
| duplicate_commit | 241 |
| post_cutoff_package | 172 |
| advisory_date_missing | 103 |
| non_github_repo | 91 |
| commit_missing | 69 |
| fix_pr_unresolved | 56 |
| files_unknown | 6 |
| fix_after_cutoff | 2 |

### Dedupe

| before | after | duplicate_alias | duplicate_commit |
|---|---|---|---|
| 7603 | 4344 | 3018 | 241 |

### Other-language / unknown-language rows skipped, by source

| source | languages (rows) |
|---|---|
| crossvul | c 2122, php 977, mixed 537, unknown 204, rb 159, cpp 119, go 80, cc 54, h 51, pm 32, cs 31, sh 12, cxx 11, pl 11, rs 8, scala 7, jsp 6, m 6, lua 6, swift 6, coffee 6, ex 3, hh 3, groovy 2, erl 2, vue 2, hs 1, pas 1, kt 1, sql 1 |
| cvefixes | c 2105, php 788, mixed 526, unknown 495, cc 164, cpp 147, rb 136, go 76, h 51, pm 29, cs 29, cxx 11, pl 9, swift 8, scala 7, rs 7, coffee 5, lua 5, sh 5, jsp 5, m 3, hh 3, erl 2, ex 2, kt 1, groovy 1, hs 1 |
| sap-kb | unknown 151, php 57, mixed 37, rb 30, cpp 18, go 10, c 8, cs 2, scala 1, coffee 1, m 1 |

### Leak set

| metric | value |
|---|---|
| post_cutoff_repos | 1559 |
| post_cutoff_packages | 1950 |
| post_cutoff_advisories | 7249 |
| malware_only_repos_not_in_leak_set | 23 |
| post_cutoff_repos_with_pre_cutoff_fix_rows | 821 |
| rows_dropped_only_because_of_non_fix_link_repo_refs | 560 |
| post_cutoff_repos_from_fix_links_only | 1074 |

### Missing values (rows dropped because a value could not be obtained)

| reason | rows |
|---|---|
| advisory_date_missing | 103 |
| fix_pr_unresolved | 56 |
| enrich_pending | 0 |
| commit_missing | 69 |
| enrich_error | 0 |
| fix_date_missing | 0 |
| files_unknown | 6 |

### LLM-assisted-label rows (PyVul; excluded by default)

| metric | value |
|---|---|
| rows | 1155 |
| sources | {'pyvul': 1155} |
| extra_pairs_if_allowed_files_le10 | 7 |
| extra_pairs_if_allowed_files_any | 7 |
| pairs_if_allowed_files_le10 | 4065 |

### Enrichment

```
{
 "cache_records": 6157,
 "cache_statuses": {
  "ok": 6089,
  "pr_missing": 7,
  "commit_missing": 61
 },
 "rows_by_enrich_status": {
  "pending": 31365,
  "ok": 14055,
  "commit_missing": 79
 },
 "language_from_fix_files": 533
}
```

### Kept pairs (≤10 files) by survivor source × cwe_class

| survivor source | dataflow | other | unknown | total |
|---|---|---|---|---|
| crossvul | 20 | 19 | 3 | 42 |
| cvefixes | 97 | 77 | 9 | 183 |
| cwe-bench-java | 88 | 17 | 0 | 105 |
| javavulbench | 83 | 88 | 6 | 177 |
| openssf | 120 | 51 | 0 | 171 |
| osv-maven | 444 | 759 | 28 | 1231 |
| osv-npm | 579 | 522 | 25 | 1126 |
| osv-pypi | 137 | 232 | 28 | 397 |
| repopairbench | 12 | 17 | 0 | 29 |
| sap-kb | 13 | 17 | 162 | 192 |
| secbench-js | 47 | 21 | 0 | 68 |
| vul4j | 17 | 29 | 5 | 51 |
| vulcan | 127 | 158 | 1 | 286 |
| **total** | 1784 | 2007 | 267 | 4058 |

### Kept pairs (≤10 files) by language × cwe_class

| language | dataflow | other | unknown |
|---|---|---|---|
| js | 962 | 794 | 34 |
| py | 177 | 293 | 46 |
| java | 645 | 920 | 187 |

The most common CWEs in the kept pairs (≤10 files) are CWE-79 (626), 22 (255), 20 (238),
400 (236), 1321 (211), 94 (184), 78 (152), 200 (149), 352 (114), 611 (111), 1333 (101) and
502 (97). A pair can carry several CWEs.

### Annotations carried by kept pairs (≤10 files)

| field | pairs | from |
|---|---|---|
| `locations` (source→sink, file/line/code) | 342 | VulcaN (paths relative to the npm tarball) |
| `source_sink` (manual) | 20 | CWE-Bench-Java v2 `fix_info_source_sink.csv` |
| `fix_methods` | 101 | CWE-Bench-Java `fix_info.csv` |
| `vuln_methods` (file/method/lines) | 977 | JavaVulBench |
| `weaknesses` (file/line) | 171 | OpenSSF |
| `sink_location` | 136 | SecBench.js (path relative to the npm package) |
| `fix_file` | 43 | RepoPairBench |

Other facts about the kept pairs:
- 235 fixes came from a PR link resolved to its merge commit.
- 507 pairs list more than one fix commit (`fix_shas`). `fix_sha` is the first; see decision 6.
- Advisory date basis: 3,180 from the row's own source, 769 from another source's record of
  the same alias, 109 from the CVE record (cveawg.mitre.org).
- Commit metadata: 3,875 from the GitHub API, 183 from the CVEfixes dump.

## Enrichment status: DONE

- The GitHub cache holds 6,157 records (6,089 ok, 61 commit missing, 7 PRs missing):
  `~/Documents/OrionLutherLeo/orion-lm-research/raw/gh-cache/github.jsonl`.
- 0 commits and 0 PRs are pending for the current candidate list.
- The last run took about 35 min and never hit the hourly quota floor.
- CVE-date cache (696 lookups: 693 ok, 3 unknown to the API):
  `~/Documents/OrionLutherLeo/orion-lm-research/raw/cve-cache/cve-records.jsonl`.

To rerun, or to continue after adding a source (both fetchers are resumable and skip cached keys):

```bash
./.venv/bin/python -I train/mine.py collect
./.venv/bin/python -I train/cve_dates.py --todo ~/Documents/OrionLutherLeo/orion-lm-research/raw/mined/cve_todo.json
./.venv/bin/python -I train/mine.py collect
./.venv/bin/python -I train/enrich_gh.py --candidates ~/Documents/OrionLutherLeo/orion-lm-research/raw/mined/candidates.json
./.venv/bin/python -I train/mine.py build --out train/data
```

## PyVul (LLM-assisted labels): counted separately, excluded by default

- PyVul's commit membership was filtered with GPT-4 ("LLM-VDC"; the paper reports 100%
  commit-level accuracy on a random sample).
- All 1,155 commit rows were collected and enriched, and each is tagged
  `llm_assisted_labels: true`.
- **If allowed, PyVul adds only 7 pairs** at ≤10 files (4,065 instead of 4,058), and 7 at any
  size. Nearly all of its commits are already covered by OSV/GHSA rows, or fail a check.

## Decisions Krish should check

1. **`cwe_class = "unknown"`** is used for rows with no CWE id at all, mostly SAP KB, which
   carries no CWE. The brief said dataflow/other; "unknown" keeps no-CWE rows from being
   silently called "other". 267 kept pairs are unknown.
2. **The leak set is conservative.** It holds every GitHub repo named by ANY URL in an advisory
   published on/after 2026-05-31: commit, PR, issue, repo and security-advisory links,
   withdrawn advisories included. That is 1,559 repos, against 1,074 named by fix links only.
   - Rows dropped only because of the extra (non-fix-link) repos: 560, before
     dedupe/enrichment.
   - Package-level leak drop: an OSV/SAP/VulcaN/SecBench row whose package appears in a
     post-cutoff advisory is dropped too (`post_cutoff_package`, 172 rows).
   - MAL-* malware reports are not treated as advisories; they would add 23 repos.
   - The leak set comes from the npm/PyPI/Maven OSV exports, plus any other source's row
     published after the cutoff (none found). Advisories in other ecosystems were not checked.
   - 821 of the 1,559 post-cutoff repos also have pre-cutoff fix rows (53%, compared with the
     ≈40% found in the planning research).
3. **`no_source_files_in_language`** (781 rows): the fix commit changes no non-test file in the
   row's language. Typical cases are a Maven advisory whose fix is a `pom.xml` bump or
   Kotlin/Scala code, or an npm package fixed in CoffeeScript. These pairs cannot teach the
   model anything at the fix site.
4. **`fix_commit_date = max(author_date, committer_date)`**, the conservative choice for a
   "before cutoff" rule. Two rows fail it.
5. **Language labels.**
   - npm → `js` (JS/TS family), PyPI → `py`, Maven → `java` (the ecosystem label); JavaVulBench,
     RepoPairBench and PyVul use their dataset label.
   - CrossVul, CVEfixes and SAP-without-purl take the language from their changed files. A fix
     touching two supported languages is `mixed` and is dropped (`language_unsupported:mixed`).
     CVEfixes breaks the tie with the repo's GitHub language.
6. **One row per advisory.**
   - `fix_sha` is the first fix commit: a GIT-range `fixed` event first, then a FIX-typed
     reference, then the listed order (CVEfixes: earliest commit date).
   - `fix_shas` keeps them all; 507 kept pairs have several. D2 should decide whether
     multi-commit fixes are used as-is or filtered.
7. **PR-only advisories** were resolved to merge commits (merged PRs only). GitHub returns a
   first-parent diff for merge commits; none of the 112 merge commits checked had an empty file
   list.
8. **Advisory dates are joined by alias.**
   - Each row takes the earliest real date of any record of the same CVE/GHSA.
   - Rows with no date anywhere get the CVE record's `datePublished`.
   - 103 rows stay `advisory_date_missing`: non-CVE ids, plus 3 CVEs the API does not know.
9. **The dedupe survivor unions CWEs** across duplicates (all from real records). This can
   change a row's cwe_class compared with any single source.
10. **SecBench.js has no CWE field.** Its cwe_class comes from its vulnerability-class folder
    (path traversal, command injection, code injection and prototype pollution → dataflow;
    ReDoS → other), recorded as `cwe_class_basis: "vuln_class"`. 11 kept pairs rely on it;
    the rest got CWE ids from a merged OSV/VulcaN duplicate.
11. **Licenses:**
    - RepoPairBench's LICENSE is a placeholder.
    - VulcaN, SecBench.js and PyVul have no license file.
    - CWE-Bench-Java and the OpenSSF benchmark are MIT, Vul4J is GPL-3.0 (with a separate data
      license), SAP KB is Apache-2.0, and JavaVulBench data is CC-BY-4.0.
12. **The test-file rule** is the eval's `_is_test`, reused for consistency with the test set's
    ≤10-files rule. It misses top-level `test_*.py` files and `__tests__/` directories.
13. **CWE-Bench-Java** comes from `iris-sast/iris@v2` (213 CVEs), not Hugging Face (120,
    older). In v2, `zip4j`'s `github_url` points to the fork `iris-sast/zip4j`.
14. **Splits are not frozen.** `train/data/splits.json` is not written, so more sources can be
    added first.
15. **ReposVul is excluded** (LLM untangling). It could be collected and tagged like PyVul if
    wanted.
16. **The MoreFixes dump (3.47 GB) was not downloaded** because it is over the per-source limit.
    It is the largest remaining source: 43,357 CVEs and 47,616 commits across all languages, to
    2026-06-02. Most of its JS/Py/Java overlap is probably already covered by OSV + CVEfixes,
    but that is unmeasured.
