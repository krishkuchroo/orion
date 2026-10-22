# Orion-LM test set (Task F0): post-cutoff CVEs, measured counts

Mined 2026-10-22 on branch `eval/orion-lm-finish` by `eval/dataset/mine.py`. Every number below
comes from that run (the tables at the end are the miner's own output, pasted unedited). Nothing was
estimated, padded or backfilled. A value OSV or GitHub did not give stays `null`.

Outputs:
- `eval/dataset/manifest.json`: manifest v2, 258 rows (208 dataflow, 50 access-control).
- `eval/dataset/testset_candidates.json`: all 885 candidates, each with its tier and reasons, for audit.

## Source

- **OSV exports dated 2026-10-18.** These are the same three zips that built the training leak
  set (`train.sources.post_cutoff`), so every repo a test advisory names was already kept out of
  training (controller ruling). The date basis is the zip file mtime (UTC); the latest advisory
  in the exports was published 2026-10-16. Advisories published after the export are not in the
  test set.
  - `osv-npm/all.zip`: 218,457,490 bytes, sha256 `a777c4de8c77e07f3b383e67e90d0ad4ec2b8b53c4826487f5dd477b1afbd773`
  - `osv-pypi/all.zip`: 36,437,960 bytes, sha256 `011f2b341876050dcdee59da6fe42dc794c2415b1d61fa2200573f8724858d0a`
  - `osv-maven/all.zip`: 10,410,399 bytes, sha256 `52ec189d363e84d6f4614c7d8c6ff1acea0140ef1d7e6c8461157dcd18353697`
- **GitHub.** Data comes from the REST API through `train/enrich_gh.py` and its cache
  (`orion-lm-research/raw/gh-cache/github.jsonl`). The first run fetched 744 fix commits and
  350 `.gitmodules` files and appended them to the cache.
  - A second run, served entirely from the cache, reproduced the manifest rows and all 885
    audit rows exactly.
  - Fix round 1 (same day) added only 17 compare fetches, one per merge-commit fix (rule 9).
    The tables below come from that regenerated run.
  - The appended records change nothing the training build reads: the raw→canonical repo map is
    identical before and after (0 names changed, 0 added).
  - `train/data/*` is unchanged.

## Rules, in check order (a row's first failing rule is its reason)

1. **Candidate.** An OSV advisory published strictly after 2026-05-31, with a GitHub fix-commit
   link and a CWE in either set:
   - dataflow: `sources.DATAFLOW_CWES`;
   - access-control: CWE-284/285/862/863.

   If an advisory lists CWEs from both sets, it counts as dataflow (10 such advisories).
   - Each row's `cwe` is the ONE CWE that qualified it for its kind: the first CWE of that kind,
     in the advisory's own order.
   - `cwes` keeps every CWE the advisory lists, in that order.
   - `cwe_basis` is `only_qualifying` or `first_of_<n>_qualifying`.
   - The L2 matcher credits a finding whose CWE is in the family of ANY of `cwes`
     (`eval/match.py::l2`).

   Advisories
   that link only a PR are left out (392 published after the cutoff). Reason: a rebase-merged PR's
   merge commit does not have the pre-fix tree as its parent.
2. **training_repo / training_pair.** The repo (raw or canonical name) is a training/dev/oldcve
   repo (`manifest.split_repos()`, 3,074 names), or the advisory id/alias is a training pair id.
   Result: 0 rows dropped by either.
3. **multi_commit_fix.** The advisory links more than one distinct fix commit (a short sha and
   the full sha of the same commit count once). One commit pair per row:
   `vulnerable_commit` = the fix's first parent, `patched_commit` = the fix.
4. **bundled_fix.** Another advisory (any date, any CWE) links the same fix commit. Short and
   full shas are matched by prefix, and records of the same CVE are not counted against each other.
5. **commit_missing / commit_fetch_error.** GitHub does not return the fix commit.
6. **files_truncated / n_files.** GitHub paginated the commit's file list (>300 files), or more
   than 10 non-test files changed (`eval.dataset.enrich._is_test`).
7. **unsupported language.** The fix's non-test files are not all JS/TS, Python or Java
   (`sources.language_from_files`). "mixed" and "no code files" are excluded too.
8. **submodule.** The fix touches a submodule path listed in `.gitmodules` at the fix commit,
   read through the contents API. Only rows that passed every other rule were checked.
9. **control.** `fix_commit_date` is on or before 2026-05-31, or the advisory was public on or
   before it through its NVD record (`nvd_published_at`) or another OSV advisory for the same
   CVE (`advisory_first_public`).
   - `fix_commit_date` is the EARLIER of the fix commit's author and committer dates.
   - For a merge-commit fix it is instead the EARLIEST author or committer date among the commits
     the merge brings in: GitHub compare `parents[0]...merge`, which includes the merge itself.
     The merge's own date is kept as `fix_commit_date_merge`.
   - If the compare fails or is truncated, the date is left missing, so the row is never
     headline.
10. **headline.** The row passes everything above. LOC is not measured (it needs clones), so no
    row is put in the scale tier here; Task F2's build pre-check decides that.
11. **Per-repo cap.** At most 2 headline rows per (canonical repo, kind): the earliest-published
    advisories, ties broken by id. Manifest rows are ordered by advisory date.

### Choices made in F0 (flagged for review)

- **Cap after the tier rules, not on raw candidates.** The cap keeps the two earliest *usable*
  advisories per repo, so a slot never goes to a multi-commit or bundled fix. It is applied per
  kind, because dataflow and access-control are reported separately.
  - The rule was fixed before the GitHub run.
  - Sensitivity: the brief's literal reading (cap the raw candidates per raw repo, then apply the
    rules) gives 179 dataflow and 37 access-control headline rows, against 208 and 50 here.
- **bundled_fix (rule 4) is new in F0.** It puts the 09-17 inclusion rule 4 ("one
  vulnerability; bundled/multi-issue fixes are excluded") and CLAUDE.md's "one bug" into code.
  - It drops 149 dataflow and 34 access-control advisories.
  - The 09-17 exception ("unless the advisory names the exact function") needs a human, so it is
    not applied. Those rows are in the audit file with reason `bundled_fix`.
- **The earlier-public date (rule 9) is new in F0.** 9 candidates had an NVD or alias date on or
  before the cutoff. None was headline anyway: 7 were already control on the fix date, 1 was
  commit_missing and 1 an unsupported language. So this rule changed no count in this run.
- **One submodule hit.** `uhop/stream-json` (CVE-2026-104183) is excluded under the rule as
  written. Its fix also bumps a `wiki` submodule, but the code change itself is in `src/`, so a
  human may want to restore it.
- **9 manifest rows have a merge commit as the fix** (2 parents): 7 dataflow and 2
  access-control. `vulnerable_commit` is the merge's first parent, as the ruling says.
  - All 17 merge-commit fixes among the candidates were compared (rule 9). 9 got an earlier fix
    date; 0 compares failed or were truncated.
  - No tier changed: the 9 manifest merge rows' earliest merged commits all fall after the
    cutoff. The earliest is pyod CVE-2026-15529, moved from 2026-07-20 to 2026-06-10.
  - For all 17, the compare's non-test files equal the commit's own non-test file list, so
    GitHub's merge-commit `files` is the vulnerable->patched diff.
- **7 manifest rows are renamed repos.** `repo` is the canonical name and `repo_raw` keeps the
  advisory's name.

## Result

- **208 dataflow rows pass the tier rules and are in the manifest** (165 repos), against the
  ≈60 target. There are also **50 access-control rows** (38 repos).
- Before the per-repo cap: 276 dataflow and 73 access-control headline rows.
- `manifest.validate(data, split_repos=manifest.split_repos())`: **0 errors** against 3,074
  training repos.
- **The test set is larger than planned.** At 208 dataflow rows (two commits each, five arms,
  R = 3), the run is about 3.5× the N = 60 at the upper end of the spec's rough 4–8-day
  estimate (N ≈ 29–60).
  Cutting it to ≈60 needs a selection rule set before the tag, such as a seeded random sample
  stratified by language, or one row per repo. F0 does not choose one; that is Krish's call.

## Fix round 1 (2026-10-22): before -> after

Changes:
- the single qualifying `cwe`, plus `cwes` and `cwe_basis`;
- `multi_commit_fix` counts distinct commits;
- merge-commit fix dates come from the compare;
- `validate` checks `cwe`/`cwes` and `repo_raw`.

| | before | after |
|---|---|---|
| dataflow manifest rows | 208 | 208 (same ids) |
| access-control manifest rows | 50 | 50 (same ids) |
| tier changes (any candidate) | | 0 |
| access-control first reason `multi_commit_fix` / `n_files` | 35 / 9 | 34 / 10 |
| manifest rows whose `cwe` `eval.cwe.parse` can read | 159 / 258 | 258 / 258 |
| merge-commit fixes with an earlier fix date | | 9 of 17 (no tier change) |
| `validate` errors | 0 | 0 |

- The `n_files` / `multi_commit_fix` change is one row: CVE-2026-106462 (backstage). It listed a
  short sha and the full sha of one commit; its fix touches 55 non-test files.
- 99 manifest rows list several CWEs: 75 dataflow and 24 access-control.
  - 17 rows have two CWEs of their kind (`first_of_2_qualifying`); L2's any-of rule covers them.
  - The "manifest by cwe" lines below now count the qualifying CWE, so they sum to the row
    counts.

## Still pending (nothing below is filled in)

- **Path fields** (`fix_sites`, `sink_or_protected_operation`, `accepted_entry_points`,
  `entry_evidence`, `graph_missed`): E5 (`eval/pathgt.py`) on real builds of both commits.
- **Scale tier:** F2's graph-build pre-check on every test commit (both sides). Rows whose
  build fails move to scale for all arms, before the tag. `loc_first_party` stays `null`.
- **Labels:** `labelers`, `guard`, `agreement` (Krish + second labeler), plus the protected
  operation for access-control rows.
- **The 09-17 rule 3 write-up check:** no public write-up of the bug before the cutoff (issue
  and PR creation dates). It is not automated here; the fix-date and earlier-public rules are the
  automated part. Check the 9 manifest merge-commit rows' PR creation dates explicitly.
- **The ≈60 vs 208 decision** above.

## Rerun

```bash
./.venv/bin/python -I eval/dataset/mine.py 2> mine.log > tables.md   # resumable; GitHub reads are cached
```

## Measured tables (`mine.py` output, unedited)

The "by cwe" lines count each row's qualifying `cwe` (one per row).

| Funnel stage | Count |
|---|---|
| OSV advisories in the three exports (non-withdrawn, non-malware, unique) | 28295 |
| published after the cutoff | 6992 |
| ... with a GitHub fix commit link | 4256 (PR link only: 392; no GitHub fix link: 2344) |
| ... in a dataflow CWE | 705 |
| ... in an access-control CWE (284/285/862/863) | 180 |
| ... other CWE / no CWE | 1077 / 2294 |
| same CVE in several advisory records (merged) | 0 |

**dataflow** — 705 candidates

| Tier | First reason | Dropped |
|---|---|---|
| excluded | multi_commit_fix | 154 |
| excluded | bundled_fix | 149 |
| excluded | commit_missing | 1 |
| excluded | files_truncated | 1 |
| excluded | n_files | 24 |
| excluded | unsupported language | 20 |
| excluded | submodule | 1 |
| control | fix_commit_date | 79 |
| **headline** | passes every rule | **276** |
| headline beyond the per-repo cap | (2 per repo and kind) | 68 |
| **manifest rows** | in 165 repos | **208** |

manifest by cwe: CWE-22 54, CWE-79 39, CWE-918 30, CWE-1321 24, CWE-78 15, CWE-94 14, CWE-89 8, CWE-502 6, CWE-73 4, CWE-1336 3, CWE-611 2, CWE-77 2, CWE-943 2, CWE-113 1, CWE-23 1, CWE-36 1, CWE-90 1, CWE-917 1
manifest by cwe basis: only_qualifying 192, first_of_2_qualifying 16
manifest by language: js 118, py 70, java 20
headline by language: js 153, py 102, java 21
manifest rows whose advisory lists several CWEs: 75
manifest rows whose fix is a merge commit: 7

**access_control** — 180 candidates

| Tier | First reason | Dropped |
|---|---|---|
| excluded | multi_commit_fix | 34 |
| excluded | bundled_fix | 34 |
| excluded | n_files | 10 |
| excluded | unsupported language | 4 |
| control | fix_commit_date | 25 |
| **headline** | passes every rule | **73** |
| headline beyond the per-repo cap | (2 per repo and kind) | 23 |
| **manifest rows** | in 38 repos | **50** |

manifest by cwe: CWE-862 25, CWE-863 15, CWE-284 5, CWE-285 5
manifest by cwe basis: only_qualifying 49, first_of_2_qualifying 1
manifest by language: js 24, py 19, java 7
headline by language: py 34, js 32, java 7
manifest rows whose advisory lists several CWEs: 24
manifest rows whose fix is a merge commit: 2

merge-commit fix check: {'merge_fixes': 17, 'date_moved_earlier': 9, 'errors': 0, 'truncated': 0, 'files_match': 17}
submodule check: {'checked': 350, 'with_gitmodules': 33, 'fix_touches_submodule': 1, 'errors': 0}

validate: 0 errors against 3074 training repos

