# Orion Streaming Build, per-function segments + summary-stitch interprocedural taint

**Status:** design (2026-07-23). Supersedes the whole-graph export step of
`2026-07-12-orion-design.md`; everything downstream of the graph (MCP tools, discovery, verify)
is unchanged.

## 1. Problem

`orion scan` builds the graph by asking Joern to `joern-export --repr=all --format=graphson` the
**entire** CPG into one pretty-printed JSON blob, then `json.loads`-ing that whole blob in Python
(`joern_adapter.export_repo` → `_run_export` → `project_graphson`). Two whole-graph blobs back to
back. On a 427-file C# repo (sharpemu) on a 16 GB Mac this OOMs, first the JVM (`OutOfMemoryError`
in spray-json `PrettyPrinter`), and even past that the Python parse would OOM next.

Measured on NodeGoat: the binary CPG is **634 KB**, the pretty-JSON export is **54.3 MB**, an
**~85× inflation**. The graph itself is small; flattening it into pretty JSON is what explodes.
Memory today scales with `85 × repo size`, not with repo size.

## 2. Goal & non-goals

**Goal.** Replace the whole-graph export+consume with a **streaming, per-function pipeline** that never
builds or parses the 85x pretty-JSON blob, while producing a graph **identical** to today's, taint edges
included. The delivered memory guarantee is "does not build the 85x blob," not "constant memory": the
producer is genuinely bounded (it holds `cpg.bin` plus one function's buffer, never the blob), and the
consumer runs a bounded window but keeps O(repo) accumulators plus, under the batch-at-end persist (§8),
one normalized batch. Peak is `O(window + compact accumulators + normalized batch)`, roughly one graph
size, about 85x below the blob that OOMs today. See §8 for the honest term-by-term model.

**Hard parity gate (pass/fail).** The streaming build must reproduce NodeGoat's current graph
exactly: **217 FLOWS_TO edges**, byte-for-byte node/edge parity, and the existing 14/15 recall.
Second gate: PyGoat parity (the existing non-NodeGoat validation repo). Nothing replaces the legacy
path until both pass.

**Non-goals (this stage).** The discovery/verify agents are unchanged, they keep querying the
finished Neo4j graph. The streaming *queue is designed so a later stage can let agents drain it
per-function in parallel*, but that stage is not built here (see §10).

## 3. Why exact taint can't be a pure per-function property (measured)

`collapse_flows` is a **global interprocedural reachability**, not a per-function computation. A
tainted value flows across a call boundary into a callee's parameter (`stitch_target` →
`callee`/`mparams`) and can chain deeper, and some flows need caller-side context too. Spike
results on NodeGoat (`scratchpad/spike_partition.py`, `spike_closure.py`):

| Slice strategy | FLOWS_TO recovered | Missing |
|---|---|---|
| Whole graph (oracle) | 217 |, |
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
│   • append to the normalized batch  (persisted ONCE at the end; batch-at-end, see §8)
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

`segments.jsonl` carries **one preamble record** (line 0) then **one record per function**. Each
per-function record is self-contained: everything `build_summary` and the structural projection need
for that method rides in its own line, so the consumer never correlates two segments to build one
method's inputs.

**Preamble (`seg = -1`).** The unowned FILE nodes, emitted once from `cpg.file`. FILE nodes are AST
roots (no enclosing METHOD owns them), so a method-only stream would drop every CpgFile node and every
DEFINED_IN edge. The preamble carries them, and preserves Joern's FILE ids for any id-level parity
assertion.

```json
{"seg": -1,
 "files": [{"id": <int>, "label": "FILE", "properties": {"NAME": "<path>", ...}}]}
```

**Per-function record.**

```json
{
  "seg": <int>,                       // ordering / resume cursor
  "method_id": <int>,                 // the METHOD vertex id (a scalar key only)
  "vertices": [                       // ALL owned vertices, INCLUDING the METHOD vertex itself
     {"id": <int>, "label": "<L>", "properties": { <full property set> }}
  ],
  "edges": [                          // every edge WHOLLY inside this method, WITH endpoint labels
     {"label": "AST|REACHING_DEF|ARGUMENT|CONTAINS",
      "outV": <int>, "inV": <int>, "outVLabel": "<L>", "inVLabel": "<L>"}
  ],
  "source_file": {"file_id": <int>},  // this method's SOURCE_FILE target FILE id (to DEFINED_IN)
  "callsites": [                      // one per real CALL in the method
     {"call_id": <int>, "callee_id": <int|null>, "callee_full_name": "<str>",
      "args": {"<idx>": <arg_node_id>}}
  ],
  "cross_rd": [[<src_id>, <dst_id>], ...],   // closure SOURCE side (see below)
  "closure_targets": [<dst_id>, ...],        // closure TARGET side (see below)
  "is_entry": <bool>                  // entry-point membership; this build reconstructs it in the
                                      //   consumer's pass 1 instead of trusting a producer stamp (§6)
}
```

Field rules (frozen):

- **The METHOD vertex is inside `vertices`.** This matches `partition`'s per-method slice and the
  Task-5 equivalence test as written. `method_id` is a scalar key, not a second copy of the vertex, so
  the consumer's `_seg_to_graphson` must NOT re-prepend it; it returns
  `{"vertices": seg["vertices"], "edges": seg["edges"]}`. Re-prepending double-counts the METHOD node.
- **Full property dump.** `properties` carries each node's entire property set. This is the simplest
  form that provably covers the union `_NODE_PROPS` plus `{ARGUMENT_INDEX, INDEX, IDENTIFIER.NAME,
  ANNOTATION.FULL_NAME, ANNOTATION.NAME}`. `IDENTIFIER.NAME` is load-bearing (without it
  `_base_root_name` returns None, request-object sources vanish, and NodeGoat drops below 217);
  `ANNOTATION.FULL_NAME`/`ANNOTATION.NAME` are NodeGoat-invisible but carry annotated-source taint on
  other repos. Segment size is dominated by edges, not properties.
- **Endpoint labels on every edge.** Each edge carries `outVLabel`/`inVLabel` so `project_graphson`'s
  `(outVLabel, inVLabel)` filter keeps CONTAINS_CALL and any other label-filtered family. Without them
  every structural edge, including the in-slice CONTAINS_CALL, is dropped.
- **CONTAINS is in the wholly-inside edge set.** Emit the intra METHOD-to-CALL CONTAINS edge (2052 on
  NodeGoat, which becomes CONTAINS_CALL). The old §5 listed only AST/REACHING_DEF/ARGUMENT and lost it.
- **`callsites[].callee_id` comes direct from the CALL out-neighbor.** The producer emits the resolved
  callee METHOD id straight from the CALL edge's target; the consumer builds
  `callee_edges = {call_id: callee_id}` and `callgraph[mid] |= {callee_id}` with NO string
  re-resolution. `callee_full_name` is retained for debugging only. Colliding first-party full_names (JS
  arrow-closures and overloads) make name resolution non-unique, so re-resolving `callee_full_name` to
  an id in the consumer would silently mis-wire the stitch; carrying `callee_id` removes that failure
  mode (and the order-dependence in §9). A callee METHOD may be `IS_EXTERNAL`, which is still a valid id
  (`stitch_target` returns None for it, since external methods have no mapped params), so the producer
  must also visit external `cpg.method` stubs so RESOLVES_TO parity includes external callees.

**Reconstruction at consume time (replaces the old false claim).** The previous §5 said cross-function
edges are "reconstructed at persist time from `method_full_name`, exactly as `normalize` already binds
calls to methods." That is false: `normalize` maps CALL to RESOLVES_TO and SOURCE_FILE to DEFINED_IN
only from envelope edges present by node id (`joern_adapter.py:454-469`); it synthesizes nothing from
`method_full_name`. The real reconstruction rules are:

- **CALL to RESOLVES_TO** is rebuilt from `callsites[].callee_id` (CALL id to callee METHOD id).
- **SOURCE_FILE to DEFINED_IN** is rebuilt from the FILE preamble plus each method's
  `source_file.file_id`.
- **Cross-method REACHING_DEF closure edges are a THIRD cross-edge family**, carried in the segment
  (distributed to both endpoint methods), and are NOT reconstructable from any name. Without them the
  stitch reproduces 190, not 217.

**Closure carriage (the third cross-edge family).** A cross-method REACHING_DEF edge (a nested-lambda
closure capture: an outer variable used inside an inner function) has its two endpoints owned by
different methods, so `partition` drops it from every slice (1396 such edges on NodeGoat). The producer
holds the whole `cpg.bin` once and distributes each such edge into BOTH endpoints' segments, computing
each side purely from owned-id-set membership. Let `ids_M` be the AST node ids owned by method `M` and
`owned` the union over all methods.

- **`cross_rd` (SOURCE side, lands in owner(src)'s segment):** for each REACHING_DEF edge `o -> i` with
  `o ∈ ids_M`, `i ∈ owned`, `i ∉ ids_M`. The `i ∈ owned` filter DROPS method-less targets, reproducing
  `_closure_edges`' `if mi is None: continue` (`taint_summary.py:336`). Feeds `cross_rd[o].append(i)`.
- **`closure_targets` (TARGET side, lands in owner(dst)'s segment):** for each REACHING_DEF edge
  `o -> i` with `i ∈ ids_M`, `o ∉ ids_M` (no `owned` filter on `o`, i.e. KEEP method-less sources,
  matching `targets_by_method`, which retains `mo=None`). Feeds `targets_by_method[M].add(i)`.

The asymmetry (drop method-less targets, keep method-less sources) is deliberate. A method-less TARGET
must be dropped: `method_of[t]` is built only from summaries' `direct` keys (`taint_summary.py:256-257`)
and dereferenced as a dict in `stitch` (`:290/:307`), so a method-less target would KeyError. A
method-less SOURCE must be kept: its targets are still real closure entries. Carrying both sides in
their own owner's segment is what makes each segment self-contained, so `build_summary(M)` consumes
`M`'s complete `cross_rd`/`closure_targets` with no cross-segment correlation even when the two owning
methods arrive in different windows.

This carriage reproduces the CONSULTED part of `_closure_edges.cross_rd` plus all of
`targets_by_method`, which is exactly what drives the stitch to 217. It does not reproduce
`_closure_edges`' raw `cross_rd` dict byte-for-byte (that dict also holds method-less-source keys, which
are provably inert because a method-less source is never a walked node). That is a proof obligation,
discharged by the closure-edge parity test in §9 and plan Task 5, not an assumption.

## 6. Summary-stitch taint algorithm (the heart)

Factor `collapse_flows` (`joern_adapter.py:96`) into intra-function summaries + a global fixpoint.
Notation follows the current code: `rd` = REACHING_DEF adjacency, `enclosing_real_arg(n)` = the
`(real_call, arg_index)` whose argument subtree contains `n`, `callee(rc)` = first-party method a
real call resolves to, `mparams[M][idx]` = M's formal parameter at index `idx`.

**Per-function summary (intra-function only, bounded).** For function F, for each *taint entry*
`e ∈ realcalls(F) ∪ params(F) ∪ internal_sources(F)`, precompute by an intra-F `rd` walk (identical
to the current walk but never leaving F, i.e. omit the `stitch_target` hop):

```
direct_F(e) = { (rc, idx) : rc ∈ realcalls(F), the intra-F rd walk seeded from rd[e]
                            reaches arg idx of rc }   # walk starts at e's reaching-defs, as today
```

Also record per F: its formal params, its `internal_sources` (request-object fieldAccess whose base
∈ `request_source_names`, plus annotated `source_params`, plus, for the GENERIC profile, entry-point
params), and each call site's `callee_full_name` per arg index.

**The third family: `closure_out_F(e)` (cross-method REACHING_DEF).** `collapse_flows` walks the whole
graph `rd` relation, so it steps transparently across closure-capture edges (an outer variable used
inside a nested lambda) whose two endpoints live in different functions. `partition` drops those edges,
so the summary must record them explicitly. `_reach_full` collects, at every transparent node reached
inside F, the cross-method REACHING_DEF successors of that node (from F's `cross_rd` slice) into
`closure_out_F(e)` = the set of target nodes the whole-graph walk would step into. In addition, every
`closure_target` owned by F (a node another function's flow reaches by closure capture) becomes an
extra self-checked entry of F: it is tested for an enclosing real call in F and, if it is one, seeds a
`direct` result. This is exactly the `cross_rd`/`closure_targets` seam `build_summary` already
implements (`taint_summary.py:203-248`); `closure_out` is stored on the `Summary`.

**Global stitch (worklist over summaries + call graph).** Reproduce the three edge families:

- `best` (call→call): for every real call `s` in function `F_s`, do a search whose frontier is
  `(entry, function, crossed)`. Seed `(s, F_s, crossed=False)`. Expanding an entry `e` in `F`:
  for each `(rc, idx) ∈ direct_F(e)` with `rc != s` emit `s → rc` with
  `best[(s,rc,idx)] ← AND(existing, crossed)`;
  if `rc` resolves to first-party callee `M`, push `(mparams[M][idx], M, crossed=True)`. Dedup on
  `(entry, function, crossed)` (mirrors the current `seen` set). Provenance = `proven` iff some path
  reached the edge with `crossed=False`, else `inferred`, identical to
  `best.get(key, True) and crossed`.
- `param_flows` (sink self-loops, always `inferred`): same search seeded from each
  `internal_source`, emitting self-loop `(rc, rc, idx)` for every reached `(rc, idx)`.
- `closure_out` (cross-method REACHING_DEF crossing): a third frontier expansion used inside BOTH the
  `best` and `param_flows` searches. When an entry `e` in `F` is popped, for each
  `t ∈ closure_out_F(e)` push `(t, method_of[t], crossed)` with `crossed` **preserved** (contrast the
  call-to-param hop, which forces `crossed=True`). Dedup on `(node, crossed)`, keyed exactly like the
  current `seen` set (`taint_summary.py:287-290, 305-308`). This is what re-joins a flow that
  `collapse_flows` follows through a nested-lambda capture; it emits no FLOWS_TO edge of its own, it
  only continues the walk in the target function.

Because every step is either an intra-F relation lookup (`direct_F`), a call-graph hop, or a
cross-method REACHING_DEF relation lookup (`closure_out`, sourced in Phase 2 from the per-segment
producer slices in §5), the fixpoint touches only compact summaries and the call graph, never the full
node graph. Memory is `O(Σ summary sizes + call graph)` (the closure state folds into summary size).
This is the analysis' own working set; it is not the whole streaming build's peak memory, which §8
states honestly.

**Phase-2 note.** In Phase 2 the consumer threads
`build_summary(mid, sub, src_names, entry_taint, cross_rd=<segment cross_rd as dict>,
closure_targets=<segment closure_targets>)`, the same 5th and 6th args `flows_via_summaries` passes at
`taint_summary.py:347-349`. The only difference from Phase 1 is where `cross_rd`/`closure_targets` come
from: a per-segment producer slice instead of `_closure_edges` over the whole graph. `build_summary`,
`_reach_full`, and `stitch` stay byte-for-byte the Phase-1 code; do NOT call `build_summary(mid, ...,
None)`, which omits the closure seam and yields 190, not 217.

**This is an equivalence claim, and it is *tested*, not asserted.** The oracle is the current
whole-graph `collapse_flows`; the property `union of summary-stitch == collapse_flows(whole)` is
checked on NodeGoat (must be exactly 217, same edges, same provenance) and PyGoat before cutover.
The spike scripts become the first tests.

## 7. Rollout (safe, incremental, reversible)

1. Land the summary-stitch analysis **behind the existing whole-graph path** (a pure refactor of
   `collapse_flows`, validated by the oracle test, no pipeline change yet). This de-risks the
   hardest part first with the whole graph still in hand.
2. Add the Joern per-function producer script + the streaming consumer behind `--stream` (legacy
   path stays default). `--queue-size` defaults to 64.
3. Parity gate: `--stream` build of NodeGoat == legacy build (217 FLOWS_TO, node/edge parity) AND
   PyGoat parity AND NodeGoat 14/15 recall unchanged. Only then flip `--stream` to default and keep
   `--no-stream` as the escape hatch.
4. sharpemu smoke test: builds within 16 GB without swapping to death.

## 8. Memory & resumability model

The honest model. The producer is genuinely bounded; the consumer is bounded-window but O(repo) in its
accumulators and its final batch. "Flat in repo size" would be false. What the pipeline actually
delivers is that it never builds or parses the 85x blob:

`peak = O(queue_size subgraphs) + O(Σ compact summaries + callgraph + callee_edges + tables) + O(normalized batch at persist)`

- **Producer JVM (bounded):** holds `cpg.bin` (small) plus one function's serialization buffer. Never
  the 85x blob.
- **Consumer window (transient, O(queue_size)):** the up-to-`queue_size` decoded segment records plus
  their per-segment `project_graphson` output. This is the big term per step, and it is dropped after
  each batch.
- **Consumer accumulators (resident, O(repo) but compact):** `summaries` (ids and ints only, never
  re-embedding subgraph vertices), `callgraph`, `callee_edges`, the `method_id`-to-`full_name` table,
  the FILE table, and the entry-point facts. Each is about one graph size, all far below the blob.
- **Normalized batch (resident, O(repo), the largest term):** under the batch-at-end persist (the first
  cutover, Option 2), pass 1 accumulates the full normalized node/edge batch and the stitch appends
  FLOWS_TO, then a single `persist.persist(batch)` call runs as today. This clears the 85x OOM with
  minimal change; the batch is small (NodeGoat's CPG is 634 KB, sharpemu fits comfortably under 6 GB).
  It does NOT deliver bounded-in-repo-size resident memory. A true incremental persist (clear-once, MERGE
  structural nodes/edges per batch, defer cross-function and FLOWS_TO edge binding to a final pass that
  holds the global tables) is documented as a FUTURE follow-on, not built now.
- **Global stitch (cheap):** touches only summaries and the call graph.
- **Resume:** the numbered, durable `segments.jsonl` (the expensive producer step is never re-run) plus
  a persisted `last_segment` cursor and the persisted pass-1 tables/summaries; re-running continues
  mid-repo. Under batch-at-end persist a crash before the final `persist.persist` loses the DB write but
  not the segments, so resume replays cheaply.

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
  the worklist, the oracle test is the guard; if any edge's provenance differs, the summary search
  ordering/dedup key is refined until exact.
- **Recursive / cyclic call graphs**, the `(entry, function, crossed)` dedup must terminate on
  cycles (it does: finite entry×function×{T,F} state space), matching the current `seen` guard.
- **GENERIC-profile entry-point sources** must be threaded into `internal_sources` so non-Express
  repos (PyGoat, sharpemu) keep today's behavior.
- **Producer/consumer coupling to Joern's method AST**, the spike proves the Python-side
  decomposition; the Joern script must emit the same per-method vertex/edge sets. Validated by
  diffing the script's segments against the Python partition of the whole export on NodeGoat.
