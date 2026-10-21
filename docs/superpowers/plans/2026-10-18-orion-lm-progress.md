# Orion-LM build progress (snapshot 2026-10-18)

Plan: `docs/superpowers/plans/2026-10-18-orion-lm.md` (rev 2). Branch: `eval/orion-lm`.
Paused by Krish after Task E3. This file is a committed copy of the working ledger
(`.superpowers/sdd/2026-10-18-orion-lm/progress.md`, gitignored) so the record survives on GitHub.

## Done (each task implemented, reviewed, fixed until the review was clean)

- Part A (eval harness fixes): A1–A6. 121 eval tests at the end of Part A.
- Part B (in-process model path): B1–B6. C1 (LM sink hints).
- Scoring: E1 (normalize), E2 (matcher), E3 (report). Eval suite: 190 passed.
- Orion suite: 259 passed, 1 expected failure (`tests/test_persist_indexes.py` needs Neo4j running).

## Not done yet

E4, E5, D1–D6, C2, F0, F1, F3, F2, then the final whole-branch review. F4 and F5 need Krish.

## Krish to check before the pre-registration tag

- Credentials: the A6 smoke test copied the Claude OAuth block (from the macOS keychain) and
  `~/.codex/auth.json` into gitignored `eval/.config/`. Plaintext on disk; never committed.
- Comparability: the plain Claude arms now get only 7 tools (no subagents, no Skill). State this in
  PREREGISTRATION.md.
- `eval/cwe.py` CWE_PARENTS was written from memory and is unverified. The sibling rule puts
  CWE-94 and CWE-502 in one family.
- Codex runs with `--sandbox workspace-write` and network off (read-only blocked the findings
  write, measured), not the plan's read-only.
- Not captured yet: the usage-limit fixtures (`"captured": false`). Placeholders: the system prompt
  and the training templates (Krish writes these).
- Day-1 measurements not run (need Neo4j / the fixture): FLOWS_TO parity at 217, and the NodeGoat
  CandidateFlow count with `with_lm_sinks(EXPRESS)` (the prototype-pollution hints
  merge/extend/assign are broad).
- Not implemented: the sign-flip and McNemar sensitivity checks (spec §6).
- For training (D5): cut examples only from commit 121b0d8 onward; apply `merge_consecutive_roles`.
- For the bake-off (C2): A/B the token splice against canonical tokenisation.

## Full ledger


Spec: docs/superpowers/specs/2026-10-18-orion-lm-design.md (read). Branch: eval/orion-lm (feature branch; main checkout — Krish works here, untracked scratch files present, so no new worktree).
Baselines before Task A1: `./.venv/bin/pytest eval/tests -q` → 44 passed. Orion's Neo4j container is NOT running (only grc-* containers up) → `tests/test_persist_indexes.py` is the one expected failure in `pytest -m "not slow"`.
Plan commit: b25534c.

## Preflight conflict scan (2026-10-18)

| Pair / task | Produces vs consumes | Finding → Ruling |
|---|---|---|
| A2 ↔ A4 ↔ A5 ↔ F3 (eval/run.py) | A2 rewrites build_launcher (tree export); A4 changes run_one to ArmResult; A5 adds classify_exit + resume loop; F3 adds lm dispatch | Sequential edits to one file; ordering A2→A4→A5→A6→F3 keeps each diff coherent. OK. |
| A4 test ↔ A6 | A4's test calls `plain_arm(..., effort="xhigh")` with no `ollama_url`; A6 is where `_build_cmd(arm, repo_dir, model_tag, effort)` and Ollama removal are specified | Ruling: A4 already drops `ollama_url` from `plain_arm`/launcher and adds `effort` passthrough (a 4th positional arg to `_build_cmd`, unused until A6). A6 then fills the flags and removes env.py/preflight Ollama bits. Cost if wrong: a one-line signature shuffle. |
| A2 test_run_wiring ↔ A4 `_orion` removal | A2 extends test_run_wiring with `_export`/`_plain` injection while `_orion` still exists | A4 deletes the `_orion` seam and its tests in the same task. OK. |
| B3 ↔ B4 (orion/lm/model.py) | B3 creates `GenResult` in model.py; B4 adds wrappers | Both state lazy MLX imports. OK. |
| B3 run_session → (leads, steps) ↔ B5 `_session` stub returns tuple | consistent | OK. |
| B6 ↔ C1 | B6 needs `profiles.with_lm_sinks` + `graph_build.build(profile=)` | Order C1 before B6. |
| C1 test `test_build_accepts_explicit_profile` | names a seam `_build_with_profile` that doesn't exist | Ruling: implementer chooses the seam (e.g. patch `select_profile` in graph_build and assert it is NOT called when `profile=` is given, and the given profile reaches `pathfind`). Cost if wrong: test shape only. |
| D4 ↔ E2 | D4 `trace.pair_test` imports `eval.match.l1` | Order E2 before D4. `eval/__init__.py` and `train/__init__.py` stay empty so eval↔train module imports don't cycle (E5 imports train.fixmap; D4 imports eval.match). |
| D5 ↔ B3 | D5 adds `format.dumps_action` to B3's format.py | OK; D5 after B3. |
| E3 `_tokens` ↔ A1 steps schema | reads `steps.prompt_tokens/completion_tokens` for lm arms, `agent_calls` otherwise | OK. |
| F2 ↔ F3 (eval/arms/lm.py) | F2 says it modifies lm.py for case mode; F3 creates it and already takes `case=` | Ruling: F3 creates lm.py with a `case_flows_fn` hook (default None); F2 wires `owasp.case_flows` into the launcher. Order F1→F3→F2 (F2 also needs queue items). Cost if wrong: one kwarg rename. |
| B4 / C2 / D1 / D2 / F0 "run the real thing" steps | need model weights (GB downloads), OSV export re-download, cloud GPU, Krish's text | Ruling: build + unit-test all code now; the measurement runs (bake-off, OSV mining counts, Joern timings, LoRA, test run) are listed as next steps for Krish, not faked. No number is recorded that wasn't measured. |
| A3 / A5 / A6 fixture captures | need one real `codex exec --json`, one real `claude -p`, limit messages, network smoke | Ruling: implementers run the tiny real CLI calls (cents of subscription usage); limit fixtures use the plan's `"captured": false` fallback if they can't be triggered. |
| Each task self-consistency | tests vs code vs files | A1–F3 checked: file lists include every test named; no task's test references an interface another task defines differently. |

Execution order: A1 A2 A3 A4 A5 A6 B1 B2 B3 B4 B5 C1 B6 E1 E2 E3 E4 D1 D2 D3 E5 D4 D5 D6 C2 F0 F1 F3 F2. F4/F5 are human-gated (left as next steps).
Models: implementers sonnet (fable for multi-file integration tasks A2/A4/B5/B6/F3), reviewers sonnet, final review opus.

## Task log
Task A1: impl c8f296a (48 tests). Review: 2 Important (non-atomic migration; thin v1 migration tests), 4 minor. minor (deferred): runs DDL + failures view duplicated in db.py; UNIQUE detection is substring heuristic; NULL vs '' commit_sha on legacy rows (documented); next_attempt read-then-insert (sequential runs only).
Task A1: fix round 1/5 (2 addressed, 0 open; commits c8f296a..86b7ebb)
Task A1: complete (commits b25534c..86b7ebb, review clean)
Task A2: impl 9c2b468 (53 tests). Review: 3 Important (relative paths vs cwd; tree inside Orion checkout exposes CLAUDE.md/.git; mirror failure aborts queue / partial clone). Ruling: tree exported OUTSIDE the repo (`--tree-root`, default <tmpdir>/orion-eval-trees; artifacts stay in eval/runs) + ancestor CLAUDE.md/.git guard — spec "no agent can see the answer" overrides the plan's `<run_dir>/tree`. Cost if wrong: path plumbing only. minor (deferred): KeyError on manifest row without any commit field; `.get("commit_sha","")` in run_one; stale dest in export_tree; brittle nested-dirname in test; root-commit `FIX^` untested. ⚠️ to check later (F3): cached scan_id vs file_path tied to a deleted tree path (graph file_paths may be absolute).
Task A2: fix round 1/5 (3 addressed, 0 open; commits 9c2b468..f7b527d). minor (deferred): leak guard uses abspath not realpath; main skip-and-continue untested; empty tree parent dirs left behind.
Task A2: complete (commits 86b7ebb..f7b527d, review clean)
Task A3: impl 9f7b167 (65 tests). Real fixtures captured (codex 0.155.1: usage nested under `usage`, reasoning ⊂ output → total() does not add reasoning; claude 2.1.302: result has modelUsage + usage). Review pending. Note: fixtures force-added (.gitignore ignores fixtures/).
Task A3: fix round 1/5 (1 addressed, 0 open; commits 9f7b167..ad7c78c). minor (deferred): mixed dict/non-dict modelUsage entries silently dropped (CLI-controlled format; untested); double-count inference from one sample (recorded in module comment).
Task A3: complete (commits f7b527d..ad7c78c, review clean)
Task A4: dispatched (BASE ad7c78c, fable). Rulings carried: delete launch.orion_arm + _orion seam + ollama_url plumbing; orion-* in launcher raises NotImplementedError until F3 (`_lm=` seam placeholder); plain_arm(arm, repo_dir, model_tag, effort, ...) -> ArmResult; copies tree/findings.json → json_out, validates via prompt.validate_findings, missing/invalid = findings_path None (a miss); usage = list of normalized blocks; run_one logs agent_calls + resources(phase="run"); skip convert.confirmed_verdicts persistence (belonged to the deleted subprocess path).
Task A4: impl 49369d1 (87 tests). Review pending. Implementer concerns: plain-gemma4 still in ARMS (A6 removes); EFFORT table added early (A6 owns values); README stale (A6 updates arm table).
Task A4: review: 2 Important (silent drop of malformed usage events; post-launcher logging outside try leaves run `running`), 1 routed to A6 (stale ARMS: plain-gemma4 + orion-* must be removed; README rewrite). minor (deferred): agent_calls.exit_reason/session_id always None for plain arms (raw result has subtype/session_id — follow-up); copy2/normalize_usage could still raise on odd shapes; wall_seconds has two definitions.
Task A4: fix round 1/5 (2 addressed, 0 open; commits 49369d1..ae7354c). minor (deferred): empty/missing usage log is silent (non-ok status flags it); DB failure inside the except path leaves run `running`.
Task A4: complete (commits ad7c78c..ae7354c, review clean)
Task A5: dispatched (BASE ae7354c, sonnet). Ruling carried: main plans BOTH commits per repo (vulnerable + patched) when the manifest row has the pair; limit fixtures may be `"captured": false` with a module comment (replace with the first real one in Phase 0).
Task A5: impl 421ad71 (101 tests). Limit fixtures UNCAPTURED (`"captured": false`). Review pending. Implementer concerns: limit signatures are guesses (substring over lines may over-match); resume loop unbounded by design; `source` unused in classify_exit.
Task A5: review: 1 Important (raw-text limit match over-broad, `source` unused → real failures become never-scored retries). minor (deferred): main-with-run_one integration untested; commit_sha-only row forced kind "vulnerable"; wait printed to stdout only (no events row); legacy NULL commit_sha rows exempt from UNIQUE.
Task A5: fix round 1/5 (1 addressed, 0 open; commits 421ad71..fd9f74a). minor (deferred): `_source_for` is a hard-coded arm→source dict (A6/F3 must extend; unknown → "lm", safe); `_RAW_RE` unbounded gap; `_log_resource` in the KeyboardInterrupt path could mask the interrupt.
Task A5: complete (commits ae7354c..fd9f74a, review clean)
Task A6: dispatched (BASE fd9f74a, fable). Rulings carried: claude_settings.json sandbox shape is a hypothesis decided by the real smoke test; if Bash still reaches the network, report DONE_WITH_CONCERNS (the no-Bash fallback needs Krish's sign-off, not applied unilaterally); smoke test copies ONLY credential files into the clean config dirs and records which.
Task A6: impl 61d5e50 (119 tests), DONE_WITH_CONCERNS. Measured: Claude Bash curl blocked under clean config + sandbox settings (403 deny network-outbound); Codex shell curl blocked (DNS fails) under workspace-write + network_access=false. Rulings: (1) Codex `--sandbox workspace-write` + `network_access=false` replaces the plan's `read-only` — read-only rejected the findings.json write (measured); the constraint (no network) still holds. Cost if wrong: Codex could write inside the tree only — acceptable, tree is discarded. (2) empty allowlist + strictAllowlist accepted (claude process itself is outside the sandbox). (3) extra Codex isolation flags (--disable apps/plugins/remote_plugin, web_search=disabled) accepted — they close measured leaks (Codex ran real web searches before). (4) SURFACE TO KRISH: the smoke test exported the Claude OAuth block from the macOS keychain into eval/.config/claude/.credentials.json and copied ~/.codex/auth.json into eval/.config/codex/ (both under gitignored eval/.config; the claude dir is empty again at review time). Review pending.
Task A6: review: 1 Important (non-Bash Claude tools — RemoteTrigger/DesignSync/Task/Cron/etc. — not disallowed; untested lookup channel). minor (deferred): shared config homes keep session transcripts across runs; no preflight check for credential files; reads unrestricted outside the tree (manifest/other arms' outputs readable if on disk — tree lives in tmp, eval/runs in repo); stale "ollama" label test_queue.py:102; Opus transcript elided. ⚠️ flagged for Krish: OAuth block copied from keychain into a plaintext gitignored file; refresh-token rotation could invalidate the primary login (unverified).
Task A6: fix round 1 impl 437d04e (121 tests): `--tools Bash,Read,Edit,Write,Grep,Glob,NotebookEdit` allowlist + extended --disallowedTools; smoke re-run shows init tools == those 7; --no-session-persistence; preflight login checks. Ruling: the plain arms lose Task/Agent subagents vs the 09-17 setup — a capability change that must be stated in PREREGISTRATION.md (F4). Re-review pending.
Task A6: fix round 1/5 (1 addressed, 0 open; commits 61d5e50..437d04e). minor (deferred): README should state the subagent/Skill removal as a pre-registration comparability note (carry into F4).
Task A6: complete (commits fd9f74a..437d04e, review clean). PART A DONE — 121 eval tests.
Task B1: dispatched (BASE 437d04e, sonnet).
Task B1: impl 4142443 (160 passed/17 skipped/1 expected Neo4j fail). Rule interpretation: a label-less property-less node joined by a relationship to a scoped node is allowed (edges carry scan_id on both endpoints) — standalone (n)/() rejected. Review pending.
Task B1: review: 3 Important (comment/backtick `(` swallows the rest of the query — scope bypass; unbalanced paren silently `continue`s instead of failing closed; scope check is a substring search accepting nested maps / expressions). Ruling: relationship-adjacent label-less node accepted — sound only because every edge carries scan_id on both endpoints (B2 fix, CLAUDE.md); assumption to be written in a code comment. minor (deferred): read_code ValueError on NUL/non-int; start>end returns empty; negative lines clamp silently; binary files return replacement chars; leading label-less node rejected (conservative).
Task B1: fix round 1 impl 57d0f3d (176 passed; one-pass blanker strips strings/comments/backticks, fail-closed on unbalanced parens; top-level scan_id:$scan_id entry required; 15 new probe tests). Re-review pending.
Task B1: fix round 1/5 (3 addressed, 0 open; commits 4142443..57d0f3d). Out-of-scope "label-less node with props uncovered" probed by controller: `MATCH (x {uid:"a"})` IS rejected — not a hole. minor (deferred): edge-scan_id assumption documented, not enforced.
Task B1: complete (commits 437d04e..57d0f3d, review clean)
Task B2: dispatched (BASE 57d0f3d, sonnet).
Task B2: impl c5e6ca8 (181 passed). Review pending. Implementer notes: slice query errors raise RuntimeError; function = method_full_name.
Task B2: complete (commits 57d0f3d..c5e6ca8, review clean). minor (deferred): dead file/function fallbacks for stub rows; _KEEP_STARTS/_HEADS not drift-guarded (no EntryPoint/CpgMethod assertion); unparseable path_uids → [] silently; negative max_flows unvalidated. CARRY TO B5: slice raises RuntimeError on query errors — engine must catch per batch (error event + zero leads).
Task B3: dispatched (BASE c5e6ca8, sonnet).
Ruling for B6 (pre-noted): cli.py has no _build_parser — main() builds the parser inline (cli.py:211). B6 extracts _build_parser() and has main() call it so the brief's test holds. Cost if wrong: a pure refactor. Also: profile is only selected when args.repo is given (cli.py:~75-78) — with --scan-id the lm engine gets profile=None (brief already says warn).
Task B3: impl 8a1f4d5 (205 passed). Review pending. CARRY TO D5: tool errors are tool_result_message(action, {error}) → ERROR: turns; error_message() only for parse failures; ACTION_SCHEMA is flat (no oneOf) for Outlines.
Task B3: review: 1 Important (read_code/flow code rendered undelimited — prompt-injection surface; fix before D5 cuts training data). minor (deferred): consecutive user turns at forced final (CARRY TO B4: check the chat template tolerates it; if merged, change format.py so training matches); tool exceptions not caught in prompter (B1 returns error dicts; slice RuntimeError is B5's); context-cap action still runs its tool before the forced final (compliant, untested).
Task B3: fix round 1 impl 8ce855f (210 passed): <<<CODE>>>/<<<END CODE>>> markers around read_code + flow code; data-not-instruction rule in ACTION_RULES + placeholder prompt. CARRY TO D5: cut training examples only from 8ce855f onward. Re-review pending.
Task B3: fix round 1/5 (1 partially addressed — marker forgery via literal <<<END CODE>>> in repo text left open; commits 8a1f4d5..8ce855f). Fix round 2 dispatched.
Task B3: fix round 2 impl 82eb09c (212 passed): _neutralise breaks every run of 3+ < or > with backslashes in both code helpers. Note for Krish's prompt: a line explaining <\<\< means a literal <<<. Re-review pending.
Task B3: fix round 2/5 (block fix ADDRESSED + exhaustively probed; residual: file/function names rendered raw outside the block; commits 8ce855f..82eb09c). Fix round 3 dispatched.
Task B3: fix round 3 impl 121b0d8 (213 passed): _s() neutralises every repo-controlled string at render time (file/function/uids/rows/error text). CARRY TO D5: cut training examples from 121b0d8 onward. Re-review pending.
Task B3: fix round 3/5 (1 addressed, 0 open; commits 82eb09c..121b0d8). minor (deferred): action `name` in RESULT:/ERROR: prefix not neutralised (model-controlled, not repo); no unit test for _s(None)/_s(int).
Task B3: complete (commits c5e6ca8..121b0d8, review clean)
Task B4: dispatched (BASE 121b0d8, fable).
Pre-note for C1: pathfind._SINK_SEVERITY already has ssrf(4)/template(4)/path(3)/deserialize(5) — only xxe + prototype_pollution are missing; graph_build.build selects the profile at graph_build.py:117 and uses it for BOTH the taint sources (stream_build/export_repo) and pathfind — build(profile=) overrides that one line.
Task B4: impl fb206ee (220 passed; slow 6/6 on mlx-community/gemma-3-1b-it-4bit, 736 MiB). MEASURED: load 3.9 s, ~808 MiB RSS after load (MLX peak 1371 MiB after 2.7k prompt), 127 tok/s gen, ~1950 tok/s prefill; Outlines keeps KV cache (cached_tokens [0,773,809]) → constrain every turn (default). Gemma template rejects consecutive same-role turns → merge_consecutive_roles applied before every template call. CARRY TO D5: apply merge_consecutive_roles identically. CARRY TO B5/F3: wrapper raises ContextOverflow above context_cap — prompter cap must sit below the wrapper's by a turn + reply. CARRY TO C2: record .sampling per model (test model had no generation_config.json → defaults temp 1.0/top_p 0.95). Review pending.
Task B4: review: 4 Important (ContextOverflow crashes run_session on the forced-final path; no cache invalidation on mid-generation failure / offset unchecked; splice creates a train/runtime tokenisation gap; seed only at load). Ruling: prompter catches ContextOverflow → step kind "context_overflow", leads []; F3 sets prompter cap ≥1 turn+reply below the wrapper cap; `GenResult.spliced` flag added; CARRY TO C2: A/B splice vs canonical tokenisation before trusting bake-off numbers; CARRY TO D5: merge_consecutive_roles mandatory, canonical tokenisation noted. minor (deferred): load() silent GGUF fallback (→ .backend + warning); outlines_core/numba/huggingface_hub unpinned; Outlines/mlx_lm internals used; decode lossy on non-ASCII tokens; DEFAULT_TOP_K=0 vs Gemma's 64; model.py 521 lines / 4 responsibilities; llama-cpp extra undeclared.
Task B4: fix round 1 impl 1cb110d (225 passed, slow 6/6). Re-review pending.
Task B4: fix round 1/5 (4 addressed, 0 open; commits fb206ee..1cb110d). minor (deferred): unknown model family keeps top_k 0 with only a code comment; malformed config.json raises.
Task B4: complete (commits 121b0d8..1cb110d, review clean)
Task B5: dispatched (BASE 1cb110d, fable).
Task B5: impl 61ed924 (239 passed; eval 121). Notes: _dedup copied (discover imports claude_cli at top); Shape literal gains 'LM'; one accidental live slow test run (~1 Claude call). Review pending.
Task B5: review: 1 Important (steps of a batch that raises mid-session never reach on_step). Ruling: plan-level gap — keep `(leads, steps)` return, add `on_step=` streaming callback to run_session; engine forwards it and stops replaying returned steps. Cost if wrong: duplicate step rows (guarded by test). minor (deferred): lead events carried pre-dedup indices; no cap floor; stopped-early not stated in done; single-node role untested.
Task B5: fix round 1 impl 7644e66 (243 passed). Re-review pending.
Task B5: fix round 1/5 (1 addressed, 0 open; commits 61ed924..7644e66).
Task B5: complete (commits 1cb110d..7644e66, review clean)
Task C1: dispatched (BASE 7644e66, sonnet).
Pre-notes: B6 test seam = cli.main([...]) with graph_build/discover/verify monkeypatched (see tests/test_cli_repo_guard.py); --scan-id skips the build. E1: eval/arms/prompt.py has FINDINGS_SCHEMA (findings.schema.json), 7-field shape incl. line_start/line_end, validate_findings(obj)->list[str]; scripts/run_nodegoat_eval.py has CLASS_KEYWORDS, _text_blob, _file_blob, match_verdicts.
Task C1: impl 3868d30 (249 passed). NOT RUN (Krish, Day 1): test_stream_flows_parity (217) and NodeGoat build with with_lm_sinks(EXPRESS) → FLOWS_TO + CandidateFlow count. Review pending.
Task C1: complete (commits 7644e66..3868d30, review clean). minor (deferred, FLAG FOR DAY-1 MEASUREMENT): bare `merge`/`extend`/`assign` prototype_pollution hints (severity 4) are substring-matched over name+code and may crowd out severity-3 path flows — qualify (Object.assign(, _.merge, $.extend() if the NodeGoat CandidateFlow count balloons; `open(` matches fopen/popen; no stream=True test for build(profile=).
Task B6: dispatched (BASE 3868d30, fable).
Task B6: impl 3ee11ee (256 passed). Review pending.
Task B6: review: 1 Important (lm + --scan-id without repo → read_code sandboxed to CWD = Orion checkout). Ruling: --engine lm REQUIRES the repo path even with --scan-id (exit 2 otherwise). Cost if wrong: one extra CLI arg for lm users. minor (deferred): --watch loads MLX in a worker thread (MLX streams thread-local — needs a live smoke); two consecutive discover/start events; new tests not stubbing GraphDB/ensure_exploit_index.
Task B6: fix round 1 impl f0833a8 (259 passed). Re-review pending.
Task B6: fix round 1/5 (1 addressed, 0 open; commits 3ee11ee..f0833a8).
Task B6: complete (commits 3868d30..f0833a8, review clean). PART B + C1 DONE — orion tests 259 passed / 1 expected Neo4j fail.
Task E1: dispatched (BASE f0833a8, sonnet).
Task E1: impl fc250fa (eval 135 passed). CARRY TO F3: orion-lm findings.json on disk = JSON list of asdict(Verdict) dicts. Review pending.
Task E1: review: 2 Important (library names like Express.js extracted as the file; `lines 42-50` → None). minor (deferred): CWE searched in text only; `:digits` fallback can catch ports; `function` never extracted from prose; findings.schema.json optional `path` would break a strict structured-output mode that requires all properties (none used today).
Task E1: fix round 1 impl 3b3c043 (eval 139 passed). Re-review pending.
Task E1: fix round 1/5 (2 addressed, 0 open; commits fc250fa..3b3c043). minor (deferred): a root-level file literally named react.js is dropped by the stoplist (known tradeoff); `path: null` rejected by validate_findings (decision made in E1 — plain arms must omit or send a list).
Task E1: complete (commits f0833a8..3b3c043, review clean)
Task E2: dispatched (BASE 3b3c043, sonnet).
Pre-note E2: eval/cwe.py CWE_PARENTS table is from model knowledge, marked unverified — KRISH CHECK against cwe.mitre.org before the tag.
Ruling for E3 (pre-noted): venv has numpy 2.5.2 + scipy 1.18.0, NO matplotlib → report.py may use numpy for the bootstrap (seeded RNG) and writes the Pareto plot as a hand-built SVG + markdown table (no new plotting dependency). Cost if wrong: a less pretty plot.
Task E2: impl 792040b (eval 158 passed). KRISH CHECK: sibling rule makes CWE-94 and CWE-502 (both parent 913) one family — review before the tag. Review pending.
Task E2: review: 1 Important (missing/inverted line_end disabled the line window). CARRY TO E3: read matches via match.read_matches (cwe_family comes back as a real bool; raw TEXT column holds "1"/"0"). minor (deferred): entry_hit file_ok True when the entry point has no file; duplicate/missing key ids not checked; only leading ./ normalised (no backslashes); garbled test comment.
Task E2: fix round 1 impl 084e613 (eval 161). Ruling: path_levels.fix_traversal stays line-only (spec: file + line±10; function-name match would credit any path through the fix function) — documented in the docstring. Re-review pending.
Task E2: fix round 1/5 (1 addressed, 0 open; commits 792040b..084e613). CARRY TO E3: read_matches returns path_level as the stored JSON string (json.loads it), cwe_family as bool.
Task E2: complete (commits 3b3c043..084e613, review clean)
Task E3: dispatched (BASE 084e613, fable).
Ruling for E4 (pre-noted): train/ does not exist until D1 — the 'train does not import eval.judge' subprocess test imports the modules that exist (eval.match, eval.normalize, eval.report, and train.* when present via importlib + try/except ImportError) and asserts eval.judge not in sys.modules; D6 extends it to train.rounds/train.trace.
Pre-note D1: OSV export = zip of GHSA-*.json; fields used by the research miner: published[:10], database_specific.github_reviewed, database_specific.cwe_ids, references[].url matched by https?://github.com/<owner/repo>/commit/<sha> (type FIX flag), withdrawn; eval/dataset/check.py classify(row, *, cutoff) -> (tier, reasons) reads advisory_published / fix_commit_date.
Task E3: impl 61d0b10 (eval 186). Notes: token-less scored runs excluded from both E sums + counted in n_no_token_data; sign-flip/McNemar sensitivity checks NOT implemented (spec §6 lists them — carry to final review as a gap to decide). Review pending.
Task E3: review: 3 Important (bootstrap used union of repos → unpaired contributions; pair_correct keyed by (repo, run_no) conflates CVEs in one repo; attempt_no unfiltered). Rulings: bootstrap pairs on the INTERSECTION of repos with scored vulnerable runs in both arms (+ n_unmatched_repos reported); pair_correct(conn, arm, pairs) takes the manifest's (vuln_id, vulnerable_sha, patched_sha) list and is None when not supplied; score only the highest attempt_no per key. minor (deferred): FAR-denominator docstrings; per-row Holm CI level label; main must open the DB read-only; surface n_no_token_data / n_vulns_under_k_runs; sign-flip + McNemar sensitivity checks NOT implemented (spec §6 lists them as sensitivity, not confirmatory — carried to final review / F4 decision); Pareto axes use slightly different populations.
Task E3: fix round 1 impl 7c18016 (eval 190). Re-review pending.
Task E3: fix round 1/5 (3 addressed, 0 open; commits 61d0b10..7c18016). minor (deferred): repos with no token data in BOTH arms appear in neither the Coverage table's unmatched list nor unmatched_repos (their runs are still counted in n_no_token_data); latest-attempt-aborted-over-scored-earlier is documented but not directly tested.
Task E3: complete (commits 084e613..7c18016, review clean)
PAUSED BY KRISH (2026-10-18) after Task E3. Branch pushed to krish/eval/orion-lm at 7c18016 + progress snapshot. RESUME HERE: E4 E5 D1 D2 D3 D4 D5 D6 C2 F0 F1 F3 F2, then the final whole-branch review. F4/F5 human-gated.
