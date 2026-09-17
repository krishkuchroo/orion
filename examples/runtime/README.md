# `runtime/` — the opt-in runtime-enrichment stage, measured on NodeGoat

`orion scan <repo> --runtime` executes the target after the static build and folds observed coverage
back into the graph as `executed`/`hit_count` props and `OBSERVED_CALL` edges. See the design at
`docs/superpowers/specs/2026-08-11-runtime-observation-design.md`.

`nodegoat-metric.json` is one real run against `fixtures/NodeGoat` (host-run: `node server.js` with a
seeded mongo on `localhost:27017`, driven by the built-in coverage-guided HTTP loop under
`NODE_V8_COVERAGE` + `--cpu-prof`). The headline numbers:

- **123 executed nodes were marked `reachable_from_entry = false`** by the static BFS (the **U**
  metric) — attacker-reachability the conservative static graph was unsure about, confirmed with
  ground truth that the code actually ran.
- **2 of 4 `OBSERVED_CALL` edges had no static call path** (the **J** metric) — real caller→callee
  links the CPG lacked, the arrow-function `CONTAINS_CALL` gap filled by observation.

Both J and U are positive, which is the go/no-go bar the design set for shipping the feature.

**Not bit-reproducible.** Unlike the static graph, runtime evidence varies run to run (different
boots exercise slightly different code), so re-running reproduces the *shape* of this result, not the
exact integers. That is called out in the JSON and is the honest limit of dynamic evidence.
