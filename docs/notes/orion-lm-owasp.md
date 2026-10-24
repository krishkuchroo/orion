# Orion-LM OWASP false-alarm set and scale-tier pre-check (Task F2)

Built 2026-10-22 on branch `eval/orion-lm-finish`. Every number below was measured in this session.
Nothing was estimated or backfilled. Code: `eval/owasp.py`, `eval/precheck.py`,
`eval/arms/prompt.py` (`CASE_PROMPT`), and the OWASP paths in `eval/run.py`, `eval/arms/plain.py`
and `eval/arms/lm.py`. Run input: `eval/dataset/owasp_sample.json`.

## Benchmarks and pinned commits

The bare mirrors were cloned 2026-10-22 with `eval/repo.py::mirror` into
`~/Documents/OrionLutherLeo/orion-lm-research/raw/owasp-benchmark/` (outside the repo).

| id | repo | version | pinned sha | commit date |
|---|---|---|---|---|
| `owasp-java` | https://github.com/OWASP-Benchmark/BenchmarkJava | 1.2 | `a0f07b8451902de4e3ff37aa03e40f4aeb3b4dbe` | 2026-10-20 (`master` HEAD) |
| `owasp-python` | https://github.com/OWASP-Benchmark/BenchmarkPython | 0.1 | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | 2026-05-19 (`main` HEAD) |

**Why these commits.** Each is the default-branch HEAD on the clone date, and the expected-results
CSV at that HEAD is byte-identical to the CSV we hold (next section).
- Java: `expectedresults-1.2.csv` last changed in `7be342d` (2016-06-05, the 1.2 release). Later
  commits change test cases without changing the CSV: `e6e9c2e` (2026-02-02) "Eliminate some
  unintended vulns in the test cases"; `f190e05` (2025-01-24) deletes the per-case `.xml` metadata
  files.
- Python: `expectedresults-0.1.csv` last changed in `4369cab` (2026-01-09). Two later commits fix
  test cases to match the CSV: `9f0d349` (path-traversal cases echoing an XSS) and `f129148`
  (a header value).
- So each pinned HEAD is the latest code for the answer key we hold.

## The expected-results CSVs: the repo's own vs ours

`owasp.sample` reads the CSV inside the exported tree at the pinned commit. That is the only source
of the answers. Compared with `orion-lm-research/owasp/{java,py}.csv`:

| | repo CSV at the pin | ours | sha256 (both) | case rows |
|---|---|---|---|---|
| Java | `expectedresults-1.2.csv` | `java.csv` | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` | 2740 |
| Python | `expectedresults-0.1.csv` | `py.csv` | `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c` | 1230 |

- Both pairs are byte-identical (`cmp`), so there are no differences to record.
- All 120 sampled cases also agree with our CSVs on category, real/false and CWE (0 disagree).
- The brief's "2741 / 1231 cases" are line counts. Each file has one `#` header line, so the case
  rows are 2740 and 1230.
- The header versions are `Benchmark version: 1.2, 2016-06-1` and `0.1, 2026-01-9`.
  `build_sample` refuses a CSV whose header version is not the study's.

## Layout: `file` and `entry`

Both were read from the pinned trees, not assumed.
- **Java v1.2.** Cases are `src/main/java/org/owasp/benchmark/testcode/BenchmarkTestNNNNN.java`
  (2740 files). Each has exactly one `@WebServlet(value = "/<cat>-NN/<id>")`, one `doGet` and one
  `doPost`. In 2524 files `doGet` calls `doPost(request, response)`; the rest serve a form.
  `entry` = `POST /<cat>-NN/<id> -> <id>.doPost`.
- **Python v0.1.** Cases are `testcode/BenchmarkTestNNNNN.py` (1230 files). Each defines one GET
  route and one POST route: `@app.route('/benchmark/<cat>-NN/<id>', methods=['POST'])` on
  `def <id>_post`. `entry` = `POST /benchmark/<cat>-NN/<id> -> <id>_post`.
- Same-named `.html` templates are not source files and are ignored. A case with no source file, or
  with no servlet/route, raises an error rather than being guessed.

## The sample (`eval/dataset/owasp_sample.json`)

Seed 0, 60 per language. Rules:
- The cases are spread evenly over the categories. Each category gets 60 // C cases; the
  remainder goes to categories drawn with the seed.
- Real and trap are at most 1 apart in every category. Each odd quota's extra case alternates
  between real and trap, in a seeded order.
- The result is deterministic: rebuilding with the same seed gave an identical file.

Rebuild command:

```
./.venv/bin/python -m eval.owasp \
  --java-mirror ~/Documents/OrionLutherLeo/orion-lm-research/raw/owasp-benchmark/BenchmarkJava.git \
  --java-sha a0f07b8451902de4e3ff37aa03e40f4aeb3b4dbe \
  --python-mirror ~/Documents/OrionLutherLeo/orion-lm-research/raw/owasp-benchmark/BenchmarkPython.git \
  --python-sha f1291485808b66e20ddb6b01b10dc71b3df8c8ba --seed 0 --n-per-lang 60
```

Totals: Java 30 real / 30 trap; Python 30 real / 30 trap. No case id is in both samples. The
validator allows it anyway, because the run key is (repo, commit, case_id).

| Java v1.2 (11 categories) | real | trap | | Python v0.1 (14 categories) | real | trap |
|---|---|---|---|---|---|---|
| cmdi | 3 | 3 | | cmdi | 3 | 2 |
| crypto | 3 | 2 | | codeinj | 2 | 2 |
| hash | 3 | 2 | | deserialization | 2 | 2 |
| ldapi | 2 | 3 | | hash | 2 | 2 |
| pathtraver | 3 | 3 | | ldapi | 2 | 2 |
| securecookie | 2 | 3 | | pathtraver | 2 | 2 |
| sqli | 3 | 3 | | redirect | 2 | 3 |
| trustbound | 3 | 3 | | securecookie | 2 | 2 |
| weakrand | 2 | 3 | | sqli | 2 | 2 |
| xpathi | 3 | 2 | | trustbound | 2 | 2 |
| xss | 3 | 3 | | weakrand | 2 | 2 |
| | | | | xpathi | 2 | 2 |
| | | | | xss | 2 | 3 |
| | | | | xxe | 3 | 2 |

## Answer stripping (`owasp.strip_answers`)

`run.build_launcher` calls it right after `export_tree`, for every arm, on OWASP items only. It
removes:
- every `expectedresults*.csv`, at any depth;
- every per-case `BenchmarkTestNNNNN.xml` metadata file (category plus real/false; Java shipped
  these before `f190e05`);
- everything under the top-level `results/` (tool results) and `scorecard/` (per-case TP/FP
  scorecards).

It never removes a build file: `pom.xml`, `web.xml`, `build.xml`, gradle files, `setup.py`,
`setup.cfg`, `pyproject.toml`, `requirements.txt`, `Pipfile`, `package.json`, `go.mod`.

**On the real exported trees** (`git archive` of each pin, then `strip_answers`):

| | files before → after | removed | what |
|---|---|---|---|
| Java | 5725 → 5629 | 96 | `expectedresults-1.2.csv`; 11 `results/Benchmark_1.2-*.xml` (ZAP, FindBugs, FindSecBugs, PMD, Sonar, VCG results); 84 under `scorecard/` (30 html, 29 png, 11 csv, plus css/js/fonts) |
| Python | 2540 → 2536 | 4 | `expectedresults-0.1.csv`; `results/.placeholder`, `results/Benchmark-Bearer-v1.51.1.json`, `results/BenchmarkPython-Bandit.sarif` |

- Neither pinned tree has `BenchmarkTest*.xml` files left.
- `pom.xml` and `requirements.txt` are kept.
- Orion's language detection is unchanged: `pom.xml → javasrc` and `requirements.txt → pythonsrc`,
  both before and after.

**Leak grep of the stripped trees.**
- Patterns: `<vulnerability>`, `real vulnerability`, `expectedresults`, `true positive` /
  `false positive`, `fake vulnerability`, `not vulnerable`, `<category>`. Also any line that names a
  case id next to true/false/vulnerable/safe, outside the case's own source file.
- Java: no hit.
- Python: 4 hits, none of them an answer.
  - `scoringconfigfile.yaml` contains `expectedresults: expectedresults-0.1.csv`, the scorecard
    config naming the deleted file.
  - Three tool-runner scripts (`scripts/run{Bandit,CodeQL,Fortify}.sh`) have a TODO comment about
    "expectedresults file name".
  - Nothing per-case.
- Per-case form defaults are not answer markers:
  - `SafeText` and `name: safe data` default input values, and `class="safe"` on form inputs.
  - They follow the input type and category, not the label. `class="safe"` is on 425 real / 402
    trap Java pages (base rate 1415 / 1325) and on 161 / 202 Python pages (base 452 / 778).
  - The crawler file `data/benchmark-crawler-http.xml` carries only URL, `tcName`,
    `tcType="SERVLET"` and input values.

**CONCERN (left in place, for Krish).** Java test-case comments hint at the answer. They are part
of OWASP's published test code, and removing them would edit the code under test, so they were not
stripped. They do not change behaviour, but every arm reads them.

| comment | real | trap (all 2740 cases) |
|---|---|---|
| `// condition 'B', which is safe` | 18 | 131 |
| `// get the last 'safe' value` | 25 | 147 |
| `// get safe value back out` | 26 | 124 |
| `// This is static so this whole flow is 'safe'` | 23 | 122 |
| `// append some safe content` | 72 | 145 |
| `// remove the 1st safe value` | 147 | 176 |

- In the 60 sampled Java cases, 17 of the 30 traps carry at least one such comment, against 2 of
  the 30 real cases.
- Python test cases carry no such comment (the only comments are `# "// we tried..."` and
  `# all features are disabled by default`).
- If the comments stay, OWASP Youden J is optimistic for any arm that reads comments: all three
  plain arms, and orion-lm through its code snippets.
- Stripping comments from the case files would be a pre-registration decision.

## Run wiring

- `./.venv/bin/python -m eval.run --owasp eval/dataset/owasp_sample.json` adds OWASP items to the
  queue.
  - Each item is `(pinned_sha, "owasp", case_id)` under repo `owasp-java` / `owasp-python`, with
    `tier="owasp"` and `commit_kind="owasp"`.
  - Each benchmark is mirrored once into `<mirror-root>/<id>`.
  - `--owasp-runs` defaults to 1 (spec 5.4: R = 1); `--runs` still applies to manifest rows.
  - `--manifest ''` runs OWASP items alone.
  - The sample is validated before anything is mirrored: case ids unique per benchmark, full 40-hex
    pinned shas, known categories, typed fields, no benchmark id equal to a manifest row id.
- **Plain arms** get `CASE_PROMPT`:
  - It is filled from the case's file, entry and plain category description
    (`prompt.OWASP_CATEGORIES`; the names follow OWASP's own titles).
  - It uses the same findings shape as `TASK_PROMPT`, including `path`. The shape text is cut from
    `TASK_PROMPT`, whose sha256 a test pins.
  - The case's `real` never reaches the prompt.
- **orion-lm arms** (two modes; fix round 1):
  - After the build, `owasp.case_flows` keeps the scan's CandidateFlows with any path node in the
    case's file. A path node's file is `CpgCall.file_path`, repo-relative, compared by the L1
    same-file rule.
  - Mode `flows`: when there are such flows, they go to `discover_lm(..., flows=...)`.
  - Mode `entry_only`: when there are none, the case is judged code-only instead of being an empty
    "nothing flagged" by construction.
    - `owasp.entry_slice` builds a one-node `flow_slice`-shaped dict at the handler's declaration
      line: `F0`, rank 0, `sink_category` / `source_uid` / `sink_uid` None, as in
      `cases.case_from_function`. The line comes from `void doPost(` / `def <id>_post(` in the case
      file.
    - The real `discover_lm` path turns it into a CodeCase: `cases.case_from_flow`, then
      `RepoIndex.enclosing`. Its target snippet is the handler, plus callers and callees.
    - Checked on the real trees: the target snippet is the case's handler for 60 of 60 Java and
      60 of 60 Python sampled cases.
  - Every run writes `case_meta.json` (`{case_id, n_flows, mode}`) in its run dir, so the analysis
    can split flow-backed from code-only judgements.
  - A failed flow read, or a handler the case file does not declare, is "crashed". The F3 checks
    still apply (an entry-only batch that fails is crashed).
  - Entry-only cases carry no category (`sink_category=None`); flow cases carry pathfind's sink
    category. The plain arms are told the OWASP category in `CASE_PROMPT`. Keep this asymmetry in
    mind when comparing arms.
  - Orion's `RepoIndex` resolves callers and callees by bare name across the repo. In all 60 Java
    entry-only cases the context snippets include code from other files, e.g. the `doGet` of
    *other* `BenchmarkTest` cases, which call `doPost` too. This is `orion/lm/codeindex.py`
    behaviour, unchanged here, and it can carry other cases' hint comments (below).
- **Scoring**: `owasp.score(findings, case)` counts a case as flagged when any normalized finding
  is in the case's file (after `./` and tree-root stripping). `owasp.youden(rows)` = TPR − FPR, and
  is `None` without real cases or without trap cases.

**CONCERN: CandidateFlow cap.**
- `graph/pathfind._MAX_FLOWS = 300` caps the CandidateFlows a build persists for the whole app. The
  cap is applied after ranking by severity, centrality and path length.
- On Java (2740 cases in one app) many sampled cases will probably have no flow in the top 300.
  Those cases now run as `entry_only`: judged, but without a graph path.
- The split is measured per run in `case_meta.json`, and per build in the scan record's
  `counts.precompute.pathfind.sinks` vs `flows`.
- A per-file pathfind (a change in `orion/`) would give those cases a path. That is out of scope.

## Scale-tier pre-check (`eval/precheck.py`)

`precheck.buildable(repo_url, sha, *, mirror_root, builder)` returns
`{ok, seconds, nodes, error, stage}`:
- It mirrors once per repo (`<mirror_root>/<owner>__<name>`) and exports to a fresh temp dir
  outside any repo (`run._leak_guard`).
- It runs and times `builder(tree)`. `seconds` is the build only; on a failure it is the time
  until the failure.
- It always deletes the tree.

**What counts as a build failure (fix round 1).**
- Only the commit failing: Joern or the normalizer raising, persist failing on the data, or the
  build's pathfind step failing.
  - The pathfind check is `eval.arms.lm._pathfind_error(scan_id)`, the check the arm itself makes.
  - A commit whose pathfind failed is `stage "build"`, not ok, with the error recorded. Its node
    count is still kept, because the graph exists.
- The machine failing is never a build failure. These are stage `"setup"`, so the result is
  `not_checked` and the row is never moved:
  - neo4j `ServiceUnavailable`, `SessionExpired` or `AuthError` anywhere in the exception chain
    (Neo4j unreachable, a dropped bolt connection, bad credentials);
  - a missing Joern binary (`joern-parse` / `joern` under `JOERN_HOME`).
- A mirror or export failure is also `not_checked`.

The default builder `lm_graph_build`:
- runs the orion-lm arm's own build (`eval.arms.lm._build_graph`: lm sink profile, streaming,
  OrionScan record), with `orion.config.JOERN_HEAP_GB = 8` for the call and no model;
- keeps Joern's temp files (cpg.bin, the stream work dir) next to the tree, so they are deleted too;
- returns the node count Neo4j wrote (the sum of the record's `counts.nodes`), or `None`;
- deletes the scan's Neo4j partition afterwards.

CLI (run from the repo root):

```
./.venv/bin/python -m eval.precheck --manifest eval/dataset/manifest.json [--write] [--id CVE-...] [--report PATH]
```

- **Preflight.** Before the first row it checks that Neo4j answers `RETURN 1` with Orion's
  credentials and that the Joern binaries exist. If either fails, it exits 1 and writes nothing
  (no report, no manifest).
- It checks both commits of every row (or only the `--id` rows). Each record is
  `{result, joern_heap_gb, orion_commit, checked_at, vulnerable: {sha, ok, seconds, nodes, error,
  stage}, patched: {...}}`.
- `result` is one of:
  - `ok`;
  - `build_failed`: the build failed on either commit;
  - `not_checked`: a machine, mirror or export failure.
- **Records always go to the report file.** The default is `precheck_report.json` next to the
  manifest, overridable with `--report`. It is merged by row id and saved after each row.
- **The manifest is only written with `--write`** (a run without it is a true dry run). With
  `--write`:
  - each checked row's `precheck` is updated;
  - every `build_failed` row moves to tier `scale`, with the old tier kept in
    `precheck.tier_before`;
  - a `not_checked` row is never moved, and neither is a row outside `--id`.
- **Re-runs keep the past.** A new record carries the earlier ones in `history` (oldest first), and
  keeps the original `tier_before`. A later `ok` build never hides or undoes a move: the row stays
  `scale`, with the failing record visible in `history`. Moving a row back is a human decision.
- It is not `python -I -m eval.precheck` as the task said. Isolated mode drops the working directory
  from `sys.path`, and the venv's editable install points at `../orion`, so `eval` does not import
  and `orion` would resolve to the other checkout. The untrusted trees are never the working
  directory or on `sys.path`; they are only exported, parsed by Joern and deleted.

**Smoke: not run.**
- At 2026-10-22T22:20Z, `docker ps` showed Docker up but Orion's Neo4j container `orion-neo4j`
  stopped ("Exited (137) 45 hours ago"). Nothing answered on bolt port 7688 (`nc -z localhost 7688`
  failed).
- The default builder persists to Neo4j, so it cannot run without it. Per the ruling, the container
  was not started.
- No build seconds or node counts exist yet.
- The fix-round preflight was checked on this machine, against a scratch copy of the manifest with
  `--write`:
  - It printed `Neo4j at bolt://localhost:7688 is not usable: ServiceUnavailable ... Connection
    refused` and exited 1.
  - The manifest copy was byte-identical afterwards (sha256 check OK), and no report file was
    created.
  - No Joern problem was reported: the binaries under `~/joern/joern-cli` are present.
- The full pre-check (2 × 258 = 516 Joern builds) is Krish's next step. Run one `--id` first as the
  smoke.

## Old-CVE check

There is no second sampler. The `oldcve` split in `train/data/splits.json` (`oldcve_frac` 0.2;
28 pairs on 2026-10-22) is the held-out 20%. F4 lists its ids in the pre-registration.
