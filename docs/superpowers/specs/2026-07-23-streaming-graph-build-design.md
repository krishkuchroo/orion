# Orion Streaming Build — per-function segments + summary-stitch interprocedural taint

**Status:** design (2026-07-23). Supersedes the whole-graph export step of
`2026-07-12-orion-design.md`; everything downstream of the graph (MCP tools, discovery, verify)
is unchanged.

## 1. Problem

`orion scan` builds the graph by asking Joern to `joern-export --repr=all --format=graphson` the
**entire** CPG into one pretty-printed JSON blob, then `json.loads`-ing that whole blob in Python
(`joern_adapter.export_repo` → `_run_export` → `project_graphson`). Two whole-graph blobs back to
back. On a 427-file C# repo (sharpemu) on a 16 GB Mac this OOMs — first the JVM (`OutOfMemoryError`
in spray-json `PrettyPrinter`), and even past that the Python parse would OOM next.

Measured on NodeGoat: the binary CPG is **634 KB**, the pretty-JSON export is **54.3 MB** — an
**~85× inflation**. The graph itself is small; flattening it into pretty JSON is what explodes.
Memory today scales with `85 × repo size`, not with repo size.

## 2. Goal & non-goals

**Goal.** Replace the whole-graph export+consume with a **streaming, per-function pipeline** whose
peak memory is bounded by a small, fixed number of functions in flight — independent of repo size —
while producing a graph **identical** to today's, taint edges included.

**Hard parity gate (pass/fail).** The streaming build must reproduce NodeGoat's current graph
exactly: **217 FLOWS_TO edges**, byte-for-byte node/edge parity, and the existing 14/15 recall.
Second gate: PyGoat parity (the existing non-NodeGoat validation repo). Nothing replaces the legacy
path until both pass.

**Non-goals (this stage).** The discovery/verify agents are unchanged — they keep querying the
finished Neo4j graph. The streaming *queue is designed so a later stage can let agents drain it
per-function in parallel*, but that stage is not built here (see §10).

## 3. Why exact taint can't be a pure per-function property (measured)

`collapse_flows` is a **global interprocedural reachability**, not a per-function computation. A
tainted value flows across a call boundary into a callee's parameter (`stitch_target` →
`callee`/`mparams`) and can chain deeper, and some flows need caller-side context too. Spike
results on NodeGoat (`scratchpad/spike_partition.py`, `spike_closure.py`):

| Slice strategy | FLOWS_TO recovered | Missing |
|---|---|---|
| Whole graph (oracle) | 217 | — |
| One function alone | 185 | 32 |
| Function + full transitive callee closure | 190 | 27 |

Always a clean subset (0 invented, 0 provenance flips), but never exact. So B does **not** try to
slice the graph and re-run `collapse_flows` on slices. Instead it factors `collapse_flows` into a
bounded **per-function summary** plus a cheap **global stitch** that together reproduce it exactly.

## 4. Architecture

```
joern-parse (UNCHANGED)                 builds cpg.bin once; already fits in RAM
        │  cpg.bin
        ▼
┌─────────────────────────────┐  PRODUCER (Joern script, one JVM)
│ iterate cpg.method          │  emits ONE compact record per function →
└─────────────────────────────┘
        │  segments.jsonl  (durable, numbered: line N = function N)   ← "the queue"
        ▼
┌─────────────────────────────┐  CONSUMER (Python), ≤ queue-size functions live at once
│ per function:               │
│   • project structural nodes/edges  (FILE/METHOD/CALL/PARAM/RETURN + AST/CALL/SOURCE_FILE)
│   • compute FUNCTION SUMMARY        (intra-function taint reachability, §6)
│   • persist structural graph to Neo4j incrementally
│   • keep the compact summary        (small; not the function's full graph)
└─────────────────────────────┘
        │  {summaries[F]}  +  call graph
        ▼
┌─────────────────────────────┐  GLOBAL STITCH (Python, after the stream drains)
│ worklist over summaries →   │  reproduces collapse_flows' FLOWS_TO edges exactly, then
│ persist FLOWS_TO edges       │  writes them to Neo4j
└─────────────────────────────┘
```

- **Queue = a durable, numbered JSONL stream on disk.** The producer emits one function then moves
  on (never building the 85× blob); the consumer reads ≤ `queue-size` records at a time. Disk holds
  the backlog, so producer speed never inflates RAM.
- **Bounded window:** `--queue-size`, default **64** functions (~13 MB in flight at NodeGoat's
  ~200 KB/function; stays flat regardless of repo size). Backpressure: consumer pace gates the
  window; the producer streams to disk ahead of it.
- **Resumable:** the stream is numbered and the consumer persists a cursor (`last_segment`), so a
  crash resumes at segment N instead of restarting.

## 5. The segment

One line of `segments.jsonl` = one function's self-contained record:

- `seg`: integer segment number (ordering / resume cursor).
- `method`: the METHOD vertex (id + props Orion maps).
- `vertices`: every vertex owned by this method (AST-descendants: CALL, IDENTIFIER, LITERAL,
  BLOCK, FIELD_IDENTIFIER, METHOD_PARAMETER_IN, METHOD_RETURN, ANNOTATION …).
- `edges`: every edge **wholly inside** this method (AST, REACHING_DEF, ARGUMENT).
- `callsites`: for each real CALL in the method — `(call_id, arg_index → callee_full_name)` so the
  stitch can resolve call → callee param without a cross-segment graph walk.

Ownership = Joern AST ancestry to the nearest enclosing METHOD (the same climb `_call_file_map`
already does for B3). **Cross-function edges** — CALL (call→callee METHOD), SOURCE_FILE
(method→file) — are *not* in any segment; they are reconstructed at persist time from
`method_full_name` (exactly as `normalize` already binds calls to methods today).

## 6. Summary-stitch taint algorithm (the heart)

Factor `collapse_flows` (`joern_adapter.py:96`) into intra-function summaries + a global fixpoint.
Notation follows the current code: `rd` = REACHING_DEF adjacency, `enclosing_real_arg(n)` = the
`(real_call, arg_index)` whose argument subtree contains `n`, `callee(rc)` = first-party method a
real call resolves to, `mparams[M][idx]` = M's formal parameter at index `idx`.

**Per-function summary (intra-function only, bounded).** For function F, for each *taint entry*
`e ∈ realcalls(F) ∪ params(F) ∪ internal_sources(F)`, precompute by an intra-F `rd` walk (identical
to the current walk but never leaving F — i.e. omit the `stitch_target` hop):

```
direct_F(e) = { (rc, idx) : rc ∈ realcalls(F), the intra-F rd walk seeded from rd[e]
                            reaches arg idx of rc }   # walk starts at e's reaching-defs, as today
```

Also record per F: its formal params, its `internal_sources` (request-object fieldAccess whose base
∈ `request_source_names`, plus annotated `source_params`, plus — for the GENERIC profile —
entry-point params), and each call site's `callee_full_name` per arg index.

**Global stitch (worklist over summaries + call graph).** Reproduce the two edge families:

- `best` (call→call): for every real call `s` in function `F_s`, do a search whose frontier is
  `(entry, function, crossed)`. Seed `(s, F_s, crossed=False)`. Expanding an entry `e` in `F`:
  for each `(rc, idx) ∈ direct_F(e)` with `rc != s` emit `s → rc` with
  `best[(s,rc,idx)] ← AND(existing, crossed)`;
  if `rc` resolves to first-party callee `M`, push `(mparams[M][idx], M, crossed=True)`. Dedup on
  `(entry, function, crossed)` (mirrors the current `seen` set). Provenance = `proven` iff some path
  reached the edge with `crossed=False`, else `inferred` — identical to
  `best.get(key, True) and crossed`.
- `param_flows` (sink self-loops, always `inferred`): same search seeded from each
  `internal_source`, emitting self-loop `(rc, rc, idx)` for every reached `(rc, idx)`.

Because every step is either an intra-F relation lookup (`direct_F`) or a call-graph hop, the
fixpoint touches only compact summaries and the call graph — never the full node graph. Memory is
`O(Σ summary sizes + call graph)`, and summaries are built one function at a time from the stream.

**This is an equivalence claim, and it is *tested*, not asserted.** The oracle is the current
whole-graph `collapse_flows`; the property `union of summary-stitch == collapse_flows(whole)` is
checked on NodeGoat (must be exactly 217, same edges, same provenance) and PyGoat before cutover.
The spike scripts become the first tests.

## 7. Rollout (safe, incremental, reversible)

1. Land the summary-stitch analysis **behind the existing whole-graph path** (a pure refactor of
   `collapse_flows`, validated by the oracle test — no pipeline change yet). This de-risks the
   hardest part first with the whole graph still in hand.
2. Add the Joern per-function producer script + the streaming consumer behind `--stream` (legacy
   path stays default). `--queue-size` defaults to 64.
3. Parity gate: `--stream` build of NodeGoat == legacy build (217 FLOWS_TO, node/edge parity) AND
   PyGoat parity AND NodeGoat 14/15 recall unchanged. Only then flip `--stream` to default and keep
   `--no-stream` as the escape hatch.
4. sharpemu smoke test: builds within 16 GB without swapping to death.

## 8. Memory & resumability model

- Producer JVM: holds `cpg.bin` (small) + one function's serialization buffer. Never the 85× blob.
- Consumer: ≤ `queue-size` function records + the accumulating summaries (small relations) + the
  Neo4j driver. Flat in repo size.
- Global stitch: summaries + call graph only.
- Resume: numbered stream + persisted `last_segment` cursor; re-running continues mid-repo.

## 9. Testing

- **Oracle parity (unit):** `union(summary-stitch) == collapse_flows(whole)` on NodeGoat (==217,
  exact edges+provenance) and PyGoat. Derived from `scratchpad/spike_partition.py`.
- **Structural parity:** `--stream` persisted node/edge set == legacy persisted set on NodeGoat.
- **Recall:** NodeGoat 14/15 unchanged (existing eval).
- **Scale smoke:** sharpemu `--stream` build completes under 16 GB (peak-RSS assertion).
- **Resume:** kill mid-stream, resume, result == uninterrupted result.
- **Property:** random function orderings in the stream yield identical graphs (order-independence).

## 10. Stage two (documented, NOT built here)

The same `segments.jsonl` is the natural work queue for the discovery agents: a later stage can have
N agents pull functions (plus their 1-hop neighbors) from the stream and reason one function at a
time, in parallel, with the fast producer never idle. The summaries computed here are exactly the
per-function taint facts such agents would want. Out of scope for this spec; the queue is built to
make it a drop-in later.

## 11. Open questions / risks

- **Provenance edge cases** in the `best.get(key, True) and crossed` AND-over-paths semantics under
  the worklist — the oracle test is the guard; if any edge's provenance differs, the summary search
  ordering/dedup key is refined until exact.
- **Recursive / cyclic call graphs** — the `(entry, function, crossed)` dedup must terminate on
  cycles (it does: finite entry×function×{T,F} state space), matching the current `seen` guard.
- **GENERIC-profile entry-point sources** must be threaded into `internal_sources` so non-Express
  repos (PyGoat, sharpemu) keep today's behavior.
- **Producer/consumer coupling to Joern's method AST** — the spike proves the Python-side
  decomposition; the Joern script must emit the same per-method vertex/edge sets. Validated by
  diffing the script's segments against the Python partition of the whole export on NodeGoat.
