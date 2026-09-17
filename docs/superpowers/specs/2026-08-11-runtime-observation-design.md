# Runtime observation: enriching Orion's graph from a live fuzz run

**Status:** design (2026-08-11). Adds an **opt-in** stage that runs *after* the static build and
persist. It does **not** touch `normalize`, the taint seam, `FLOWS_TO` construction, `schema.NODE_KEY`,
or the 217/1075 parity tripwires — it writes only additive props and one new edge type onto the
already-persisted graph, through its own driver, with its own idempotent clear.

## 1. Problem

Orion's graph is built entirely from a static Joern CPG, and that graph lies by omission. CLAUDE.md
records the case the PoC paid for: *"calls nested in arrow-functions assigned to object properties get
no `CONTAINS_CALL` edge."* Three parts of the code already bend around that hole — `strategies.py:34`
warns every discovery agent, `reachability.py:16` downgrades its own `reachable_from_entry` output to
"a soft signal, never a hard filter," and `embed.py:8` uses a fixed 40-line window because `CpgMethod`
carries no end line.

Each is a question that **running the code settles and static analysis only guesses.** Reverified on
the live NodeGoat scan: **1658 of 2052 `CpgCall` nodes (81%) carry `reachable_from_entry:false`** — a
large pool the conservative static BFS is unsure about. Every one that runtime actually executes is a
guess overturned with ground truth.

## 2. Goal & non-goals

**Goal.** Execute the target under a coverage/profile tracer, correlate what ran back onto existing
graph nodes, and write the result into the same Neo4j partition the agents query — so discovery and
verification reason over static *and* dynamic evidence through one interface, needing no new MCP tool.

**Non-goals (this stage).**
- **Dynamic taint** (`OBSERVED_FLOW`). §10 documents it; v1 emits coverage-derived linkages only.
- **Stripped third-party binaries.** No source CPG to enrich → nothing to correlate to. The exe path
  requires the exe be *built from the scanned source* with coverage instrumentation.
- **Real fuzzers** (AFL++/Jazzer/Atheris). A pluggable engine seam is built; only Orion's own loop
  ships behind it.
- **Container isolation of the target.** v1 runs on the host, opt-in. A container is stage-2 hardening.
- **Languages beyond JS and Go.** The seam admits Python/Java/Rust tracers later; none ship now.

## 3. Coverage is not a call graph (the precision that shapes v1)

V8 coverage (`NODE_V8_COVERAGE`) and `go build -cover` report *which lines ran*, not *who called
whom*. So the tracer yields **two independent signals** and the design never conflates them:

| Signal | Source | Writes | Availability |
|---|---|---|---|
| coverage | `NODE_V8_COVERAGE`, `go tool covdata` | `executed` / `hit_count` props | cheap, every language |
| call tree | `--cpu-prof`, Go pprof | `OBSERVED_CALL` edges | only where a profiler gives parent→child frames |

Where a language has no call-tree source, v1 emits props only and **no** edges for it — never an edge
fabricated from mere co-execution.

## 4. Architecture

```
orion scan <repo> --runtime
        │
        ▼   (unchanged) build → persist static graph            ← PURE up to persist; byte-for-byte identical
        │
        ▼   runtime.enrich(scan_id, repo, profile, on_event)     ← the whole new stage, gated on --runtime
   ┌────┴─────────────────────────────────────────────────┐
   │ targets.select(repo, profile) → (Driver, Tracer)|None │      ← PURE selection; the NEW framework seam
   │  Driver.start(repo, work) ──► RunningTarget            │      ← IMPURE: boots app / builds+preps exe
   │  Driver.seeds(db, scan_id) → [Input]                   │      ← reads the graph (route query)
   │  engine.run(driver, tracer, target, seeds, budget):    │      ← PURE loop; feedback = coverage delta
   │     mutate → Driver.send(input); Tracer.collect(work)  │      ← IMPURE only in send / collect
   │  Driver.stop(target)                                   │
   └────┬──────────────────────────────────────────────────┘
        ▼   RuntimeTrace{ coverage:[Hit], calls:[ObservedCall] } ← normalized, language-agnostic
        ▼   correlate(trace, methods, calls_index) → WritePlan   ← PURE: file:line → graph nodes
        ▼   writeback(scan_id, plan)                             ← IMPURE: one additive writer, own driver
        ▼   metric: OBSERVED_CALL edges w/ no static path; executed-but-unreachable count
```

Pure/impure seam is the spine: everything except `Driver.start/send/stop`, `Tracer.collect`, and
`writeback` is a pure function over data, tested without executing or booting anything.

## 5. The trace→node correlation algorithm (the heart)

The tracer normalizes every language to `RuntimeTrace{coverage: list[Hit], calls: list[ObservedCall]}`
with `Hit = (file_path, line, hit_count)` (file **repo-relative**) and `ObservedCall = (caller_file,
caller_line, callee_file, callee_line)`.

**Byte offsets → lines (JS only).** V8 keys ranges by byte offset. The tracer reads each source once,
builds a prefix array of line-start offsets, and binary-searches each offset to a 1-based line.

**Props.** `CpgCall`: correlate by `(file_path, line)`; a call whose Joern `line` is `0` never
correlates (documented loss, never a guess). `CpgMethod` has a declaration `line` but **no end line**,
so containment is resolved structurally: within a file, a covered line `L` belongs to the method with
the **greatest declaration line ≤ L**. Methods without both `file_path` and an int `line` are skipped.

**`OBSERVED_CALL` edges.** Resolve both endpoints via the same containment resolver; emit
`(:CpgMethod{full_name:caller})-[:OBSERVED_CALL{scan_id,hits}]->(:CpgMethod{full_name:callee})` only
when both resolve. A frame resolving to no method is dropped. New relationship types need zero persist
registration (`persist.py:114`); endpoint labels are already `NODE_KEY`-indexed.

## 6. Persist ordering, and why parity cannot move

The static build is seconds; a fuzz run is minutes and needs the target booted/rebuilt. Running it
inline before `persist` would hold a fast pure pipeline hostage and force runtime data through
`persist`'s destructive `_clear` (`persist.py:228`). So the stage runs **after** build+persist as its
own writer, like `embed.py`: own `neo4j` driver, additive `SET`/`CREATE`, own idempotent clear
(`MATCH ...-[r:OBSERVED_CALL]->() DELETE r`; `REMOVE n.executed, n.hit_count`). **No new node label,
no `NODE_KEY` change** — so `persist._clear` (label-scoped to `NODE_KEY.keys()`) never wipes it and the
static graph stays byte-for-byte identical. That is the mechanical reason 217/1075 `FLOWS_TO` cannot
move.

## 7. The two seams

**Runtime target = a NEW seam, parallel to `Profile`.** `Profile` answers static questions
(source/sink/entry vocabulary); how to boot/build/drive is orthogonal (an EXPRESS repo is an HTTP
target, a GENERIC Go repo is an exe target). `targets.select(repo, profile) → (Driver,Tracer)|None`;
`None` → stage skipped, graph unchanged. Two instances ship: **HttpDriver + V8Tracer** and
**ProcessDriver + GoCoverTracer**. HTTP uses stdlib `urllib`/`http.client` — **no new dependency**.

## 8. Reproducibility & degradation

The stage is best-effort: a missing toolchain (`go`), an unbootable app, or any driver failure emits a
`runtime/error` event and returns without touching the graph — exactly as the semantic index degrades
when the model is absent (`cli.py:95`). Off by default; `--runtime` opts in. Runtime evidence varies
run to run, so any committed snapshot under `examples/runtime/` is labeled non-reproducible-to-the-edge.

## 9. Testing

Token-free (`pytest -m "not slow"`), literal fixtures, no boot/network/`go`:

1. **`test_byte_to_line`** — V8 offset → 1-based line; offset 0 and last line.
2. **`test_containing_method`** — greatest-decl-line-≤-L; multiple methods/file; line above first → none; non-int/absent line skipped.
3. **`test_coverage_to_props`** — `Hit`s → props plan; `line=0` correlates to nothing; `hit_count` summed.
4. **`test_observed_call_edges`** — `ObservedCall`s → `(caller,callee)` plan; unresolved frame dropped.
5. **`test_novel_edge_count`** — static adjacency + observed calls → count of edges with no static `method→call→method` path (the value metric).
6. **`test_v8_parse`** — literal `NODE_V8_COVERAGE` JSON → `RuntimeTrace`; malformed entry skipped+counted, never crash.
7. **`test_go_covdata_parse`** — literal `covdata textfmt` → `RuntimeTrace`.
8. **`test_engine_deterministic`** — seeded loop + fake driver/tracer → fixed corpus.
9. **`test_http_seeds_from_graph`** — route-recovery rows → seed request list.
10. **`test_runtime_off_by_default`** — no `--runtime` → no `runtime/*` events, no driver called.
11. **`test_writeback_plan_preserves_static`** — a write plan touches no `NODE_KEY` node/edge identity (the 217-stays-217 guard as a pure-plan assertion).

`@slow` + skip-guarded (literal command in the module docstring): `test_nodegoat_http_enrich` (docker
NodeGoat, seeded login, ≥1 executed authed-route call + ≥1 novel `OBSERVED_CALL`), `test_go_exe_enrich`
(tiny Go fixture, `go build -cover`, argv drive).

## 10. Stage two (documented, NOT built)

**Dynamic taint (`OBSERVED_FLOW`).** Tag the fuzzer's input and observe where it surfaces (JS Proxy
hooks / `sys.settrace` / native taint), emitting `(:CpgCall)-[:OBSERVED_FLOW]->(:CpgCall)` on a
**strictly separate** edge type so it can never perturb the `FLOWS_TO` parity tripwires. **Container
isolation** of the target. **Real fuzzers** behind the same engine seam. **More languages** behind the
same tracer seam.

## 11. Deliverables & done-when

| Path | Contents |
|---|---|
| `orion/runtime/{__init__,base,correlate,engine,writeback,targets,enrich}.py` | The stage. |
| `orion/runtime/{http_driver,v8_tracer,process_driver,go_tracer}.py` | Two concrete instances. |
| `tests/test_runtime_*.py` | The §9 suite. |
| `orion/cli.py`, `orion/strategies.py`, `orion/verify.py`, `pyproject.toml` | Wiring + prompt vocab + package list. |
| `examples/runtime/` | A NodeGoat metric snapshot (non-reproducible-to-the-edge). |

**Done when** `orion scan fixtures/NodeGoat --runtime` boots NodeGoat, logs in, drives it, and the
enriched graph has ≥1 `CpgCall {executed:true}` on a previously `reachable_from_entry:false` node and
≥1 `OBSERVED_CALL` edge with no static path; the token-free suite is green; the 217 tripwire is
unchanged; and the measured `J`/`U` back the go/no-go call.

## 12. Risks (against this feature's own interest)

- **OBSERVED_CALL may add few edges** (sampled, incomplete). The `executed`/U half is the reliable win
  — hence the go/no-go gate is `J≈0 AND U≈0`, not `J` alone.
- **Authed fuzzing needs per-app knowledge**; NodeGoat only works because seeded creds exist. A real
  ceiling on "point Orion at any repo."
- **The exe path needs the target's toolchain**; CGO / custom builds / missing `go` → stage skips.
- **Executing target code on the host is a genuine new risk surface**; opt-in mitigates, does not
  eliminate. A malicious repo's build/start script runs as the user.
- **Non-determinism** makes committed output a snapshot, not bit-reproducible.
