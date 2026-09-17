# Deterministic-scanner baseline: Semgrep on NodeGoat, scored through Orion's own matcher

**Status:** design (2026-08-11). Implements agenda item 1. Touches nothing in the scan pipeline —
this adds a second, independent scorer that reuses `scripts/run_nodegoat_eval.py:match_verdicts`
unmodified. No Claude tokens, no Neo4j, no Joern.

## 1. Problem

Orion's value proposition is stated in the first paragraph of the README:

> The goal is recall on an arbitrary codebase that a fixed rule catalog cannot reach, without the
> false-positive flood.

"a fixed rule catalog cannot reach" is currently **asserted, not measured**. The README is already
honest about this — it explicitly says the baseline is not committed and declines to claim a number.
That honesty is the right holding position, but it is not the finish line: until a deterministic
scanner has been run on the *same* checkout and scored by the *same* matcher, a skeptical reviewer
has no reason to believe the central claim, and the 14/15 figure floats without a reference point.

A number is only worth having if it is hard to attack. The three ways this kind of comparison
usually gets dismissed, and what this design does about each:

| Attack | Mitigation |
|---|---|
| "You ran it on different code." | Pin NodeGoat at the fixture SHA `c5cb68a`; record it in the output. |
| "You scored the two tools differently." | Reuse `match_verdicts` **unmodified**. Only presentation differs. |
| "You gave Semgrep a weak ruleset." | Generous union of five registry packs; disclose the resolved list and version. |

## 2. Goal & non-goals

**Goal.** A committed, clone-surviving Semgrep run on the pinned NodeGoat checkout, scored through
`match_verdicts`, with the measured number in the README and a single documented command that
reproduces it.

**Explicit non-goal: making Orion look good.** The number goes in the README as measured. If Semgrep
scores higher than expected, that is the result, and the README's comparison language gets weakened
to match rather than the methodology getting adjusted until it doesn't.

**Non-goals (this stage).**
- CodeQL. The structure does not preclude a second tool, but nothing is built for it here and no
  tool-agnostic abstraction is invented on spec. (YAGNI: one tool, one adapter.)
- Changing `match_verdicts`, `GROUND_TRUTH`, or `CLASS_KEYWORDS`. The scorer is the fixed reference;
  editing it while adding a competitor to it would invalidate both numbers at once.
- Re-running Orion's own eval. That is agenda item 2, gated on tokens + Neo4j; this item is
  independent of it and does not wait on it.

## 3. What "the same matcher" means, precisely

`scripts/run_nodegoat_eval.py` contains two separable things:

- **`match_verdicts(confirmed) -> (found, unmatched)`** — the scoring logic. A pure function over
  objects exposing `.lead.text` and `.lead.evidence`. This is shared, imported, and unmodified.
- **`render(confirmed, found, unmatched) -> str`** — presentation. It prints
  `PASS ✅ / BELOW BAR ❌` against `RECALL_BAR = 13`, Orion's own recall bar.

`render` is **not** reused. `RECALL_BAR` is the bar Orion set for itself against the prior PoC;
printing "BELOW BAR ❌" next to a Semgrep score would be a category error dressed up as a result —
Semgrep was never trying to clear Orion's bar. The baseline gets its own renderer that reports a
number and a per-vuln table with no pass/fail verdict attached.

Sharing the scorer and not the renderer is the whole point: identical scoring, honest presentation.

## 4. Architecture

```
fixtures/NodeGoat @ c5cb68a
        │
        ▼
  semgrep --json --config p/javascript --config p/owasp-top-ten ...
        │  raw findings JSON  ──────────────────────────────► examples/baseline/semgrep.json
        ▼                                                      (committed; the primary artifact)
  adapt_findings(json, mode)          ← PURE, no I/O, no network, no semgrep import
        │  list[Verdict]  (real orion.contracts types, decision="CONFIRM")
        ▼
  match_verdicts(verdicts)            ← SHARED, imported from run_nodegoat_eval, UNMODIFIED
        │  (found, unmatched)
        ▼
  path_exact_crosscheck(...)          ← §6: catches substring-collision credits
        │
        ▼
  render_baseline(...)  ──────────────► examples/baseline/REPORT.md + scored.json
```

Two modules, matching the repo's existing layout (`scripts/` for harnesses, `tests/` for the
token-free suite):

- **`scripts/run_semgrep_baseline.py`** — the harness. Subprocess-invokes semgrep, or ingests an
  existing JSON via `--results` so the committed run can be **re-scored without re-running semgrep**
  (and therefore without network, a semgrep install, or version drift). Owns the renderer.
- **`tests/test_semgrep_baseline.py`** — token-free, network-free, and importantly **does not
  require semgrep to be installed**, because the adapter is pure and the tests feed it literal JSON.

The split is deliberate: everything that can be tested without semgrep is in the pure function, and
the impure part (one `subprocess.run`) is thin enough to eyeball.

## 5. The adapter: Semgrep JSON → `Lead` / `Verdict`

### 5.1 Emit the real contracts, not shims

`orion/contracts.py` defines `Lead` and `Verdict` as the frozen integration spine, and
`tests/test_eval_matcher.py` already constructs them directly to test the matcher. The adapter does
the same. A shim exposing duck-typed `.lead.text` would work, but reusing the real dataclasses
guarantees the matcher sees exactly the type it sees in production, and any future field rename
breaks the baseline loudly instead of silently.

Semgrep's relevant JSON shape:

```json
{ "version": "1.x.y",
  "results": [
    { "check_id": "javascript.express.security.audit.express-open-redirect",
      "path": "app/routes/index.js",
      "start": { "line": 51 },
      "extra": {
        "message": "Untrusted input in res.redirect() ...",
        "severity": "WARNING",
        "lines": "res.redirect(req.query.url)",
        "metadata": { "cwe": ["CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"],
                      "owasp": ["A10:2013 - Unvalidated Redirects and Forwards"] } } } ],
  "errors": [], "paths": { "scanned": [...] } }
```

Note `metadata.cwe` and `metadata.owasp` are **sometimes a string, sometimes a list of strings**.
The adapter normalizes both to a flat list; a bare `str` must not be iterated character-by-character.

### 5.2 Field mapping

| `Lead` field | Value | Rationale |
|---|---|---|
| `text` | **mode-dependent** (§5.3) — the "claim" | The only blob `_text_blob` reads for class tokens |
| `evidence` | `f"{path}:{line}"` | `_file_blob` reads text+evidence; path is the file signal |
| `index` | enumeration order | Stable ordering for the report |
| `shape` | `"D"` | See below |
| `confidence` | `ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW` | Semgrep's own severity, not a judgment of ours |
| `source_uid`/`sink_uid` | `None` | Graph anchors; Semgrep has none |

`Verdict`: `decision="CONFIRM"` for every finding, `reason="semgrep"`, `sink_centrality=0.0`.
Every Semgrep finding is treated as a confirmed claim — Semgrep has no verifier stage, and
pre-filtering its output by our own judgment would be exactly the thumb-on-the-scale this design
exists to avoid.

On `shape="D"`: `Shape` is `Literal["A","B","C","D"]`, Orion's discovery-lens taxonomy, which does
not apply to a pattern matcher. `"D"` (pattern/deps) is the closest honest fit, it keeps the value
inside the declared Literal, and **nothing in the baseline scores on `shape`** — the field is
display-only here. This is documented at the assignment so a reader does not mistake it for a claim
that Semgrep runs Orion's shape-D lens.

### 5.3 The two blob modes

The class-token blob choice materially moves the score, so it is measured both ways and both are
reported. The headline is the generous one.

| mode | `lead.text` composition |
|---|---|
| `generous` (headline) | `check_id` + `extra.message` + `metadata.cwe` + `metadata.owasp` |
| `strict` (sensitivity) | `extra.message` only |

Worked example, on a real open-redirect finding:

```
GENEROUS → "javascript.express.security.audit.express-open-redirect
            Untrusted input in res.redirect() ...
            CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
            A10:2013 - Unvalidated Redirects and Forwards"
   tokens hit: "redirect", "unvalidated"            → A10 credited

STRICT   → "Untrusted input in res.redirect() ..."
   tokens hit: "redirect"                           → A10 credited
```

Reporting both pre-empts the two symmetric accusations at once — "you hobbled Semgrep by ignoring
its rule ids" and "you inflated Semgrep by keyword-stuffing its metadata." If the two numbers agree,
the result is robust to the choice. **If they diverge by more than one vuln, that divergence is
itself the finding** and gets called out in the report rather than buried under the headline.

`extra.lines` (the matched source text) is deliberately **excluded** from both modes. NodeGoat source
lines contain words like `password`, `redirect`, and `session` independently of what the rule
detected, so including them would credit rules for vuln classes they never reasoned about. That is
inflation, not generosity.

## 6. Known matcher looseness, and the path-exact cross-check

Reading `_matches` closely surfaced a real trap that only bites the Semgrep path:

```python
if not any(f.lower() in file_blob for f in gt.files):
```

This is a bare substring test, and the ReDoS ground truth is
`GroundTruth("ReDoS", ..., files=("profile.js", "app"), ...)`. The token **`"app"` matches any blob
containing "application", "happens", "appears"** — or a Semgrep rule id like
`javascript.express.security.audit...`, or a CWE string, or the path `app/routes/anything.js`.

For Orion this is mostly harmless: LLM prose rarely pairs a stray "app" with a distinctive ReDoS
token like `"catastrophic"` or `"backtracking"`. For Semgrep it is a live hazard, because Semgrep
ships a ReDoS rule whose message *does* say "catastrophic backtracking", and nearly every path in
NodeGoat starts with `app/`. A ReDoS rule firing on any file whatsoever would be credited as the
`profile.js` ReDoS.

**This is not fixed by editing the matcher.** `GROUND_TRUTH` and `match_verdicts` are the fixed
reference that Orion's own committed 14/15 was scored against; changing them here would silently
invalidate that number and make the two sides incomparable — the exact failure this whole item
exists to prevent.

Instead the baseline adds a **cross-check that reports rather than rewrites**: for every credited
`(ground_truth, finding)` pair, re-test the ground truth's file tokens against the finding's
structured `path` field alone, not the prose blob. Semgrep gives an exact path, so this is
available for free and is strictly more precise than a prose scan.

- Credit survives both → solid.
- Credit survives the shared matcher but **fails** path-exact → flagged in the report as
  `[substring-collision]`, with both numbers shown.

The report therefore carries a headline (shared matcher, comparable by construction) and a
footnote-grade stricter reading. A reviewer who distrusts the substring matcher can read the second
number without having to re-derive anything. The same looseness is noted as affecting Orion's own
score in principle, so the disclosure is symmetric rather than an asymmetric handicap applied only
to the competitor.

## 7. Unmatched findings are not false positives

`match_verdicts` returns `unmatched`, and `run_nodegoat_eval.render` labels it
`"CONFIRMED verdicts matching NO ground truth (candidate false positives)"`. That label is fair for
Orion, which claims to report *only* confirmed exploitable vulnerabilities — an unmatched Orion
finding is a candidate FP by Orion's own standard.

Applying that label to Semgrep would be **false**, and would manufacture the "false-positive flood"
the README claims. Semgrep's unmatched findings are largely real, useful, lint-grade results that
simply are not among the 15 vulns in this specific ground truth — missing `Object.freeze`, a weak
random source in a test file, a hardcoded credential in a fixture. The ground truth enumerates 15
specific vulnerabilities, not every defect in NodeGoat.

So the baseline renderer and `examples/baseline/REPORT.md` use this wording, and never the word
"false positive" for this bucket:

> N findings did not map to any of the 15 ground-truth vulnerabilities. This is **not** a
> false-positive count — the ground truth enumerates 15 specific vulns, not every issue in NodeGoat,
> and many unmatched findings are legitimate results outside its scope. Establishing a true FP rate
> for Semgrep would require triaging all N by hand, which this baseline does not do and does not
> claim to have done.

If the README later wants to say anything about false-positive rates, it needs that hand triage
first. This design does not do it, and the README wording will be constrained to what is measured:
recall against the 15, for both tools, under one matcher.

## 8. Ruleset, pinning, reproducibility

**Not `--config auto`.** It resolves server-side against a registry that changes over time, prefers
logged-in Pro rules, and sends metrics — so it is neither reproducible nor disclosable. A number
produced by `auto` cannot be re-derived by a reviewer six months from now.

Explicit packs, generous by intent:

```
p/javascript  p/owasp-top-ten  p/nodejsscan  p/expressjs  p/secrets
```

Recorded in the output header, alongside: `semgrep --version`, the resolved rule count, the NodeGoat
SHA (`c5cb68a`), and the literal command line. Packs are fetched from the registry on first run and
cached; the **committed `semgrep.json` is the artifact of record**, so re-scoring needs neither
network nor a semgrep install.

Scope: repository root, semgrep's default ignores (which skip `node_modules`, and here also
`package-lock.json` / `artifacts/` noise). Not narrowed to `app/` — narrowing could only *hide*
findings, and every scoping decision here breaks toward Semgrep.

`semgrep` is added to the `dev` extra in `pyproject.toml`. It is a real dependency of a real script
in this repo; leaving it as an ambient tool a maintainer is assumed to have is how a "reproducible"
command stops reproducing.

## 9. Testing

`tests/test_semgrep_baseline.py`, token-free and semgrep-free, feeding literal JSON to the pure
adapter:

1. **Generous credits a known vuln.** Open-redirect finding → `A10` credited.
2. **Strict is a strict subset.** Every generous credit that strict also makes is identical; strict
   never credits something generous misses. (A property, not an example — guards a future edit that
   accidentally makes strict the more permissive mode.)
3. **`extra.lines` never inflates.** A finding whose matched source line contains `password` but
   whose rule is about something else must not credit `A2-2`. Pins the §5.3 exclusion.
4. **`cwe`/`owasp` as bare string vs. list.** Both normalize; a `str` is not iterated per-character.
5. **Path-exact cross-check fires.** A ReDoS-flavoured finding on an unrelated path whose blob
   contains "app" is credited by the shared matcher but flagged `[substring-collision]`. This is the
   §6 hazard, pinned as a test so the disclosure cannot silently stop working.
6. **Malformed input is not a silent zero.** Missing `results`, absent `extra`, absent `path` → the
   finding is skipped and *counted* as skipped, never fabricated into a credit and never crashing
   the run. (Matches the repo's standing rule that a failure is never a clean success.)
7. **Shared-matcher identity.** The adapter's output is fed to the imported `match_verdicts`, not a
   local copy — asserted by importing from `scripts.run_nodegoat_eval`, mirroring how
   `test_eval_matcher.py` already imports it.

Runs under `pytest -m "not slow"` with the existing suite (75 passing). Nothing here is `@slow`: the
live semgrep invocation is a script, not a test, so CI never depends on the registry being up.

## 10. Deliverables & done-when

| Path | Contents |
|---|---|
| `scripts/run_semgrep_baseline.py` | Harness + pure `adapt_findings` + `--results` re-score path |
| `tests/test_semgrep_baseline.py` | The seven tests above |
| `examples/baseline/semgrep.json` | Raw, unedited semgrep output — the artifact of record |
| `examples/baseline/scored.json` | Machine-readable scoring: both modes, cross-check flags |
| `examples/baseline/REPORT.md` | Human-readable table + full methodology header |
| `examples/README.md` | New section, mirroring the `apex/` entry |
| `README.md` | Measured number replacing the "not committed yet" note |
| `pyproject.toml` | `semgrep` added to the `dev` extra |
| `agenda.md` | Item 1 struck; items 2–3 renumbered |

**Done when** `examples/baseline/` holds a committed Semgrep run on NodeGoat `c5cb68a`, scored
through `ground_truth_nodegoat.py` via the shared `match_verdicts`, the README cites that measured
number instead of a qualitative claim, and this reproduces it:

```bash
./.venv/bin/python scripts/run_semgrep_baseline.py --results examples/baseline/semgrep.json
```

## 11. Risks and honest expectations

**Expected shape of the result.** Semgrep should find the shape-A data-flow vulns (A1-1 `eval`,
A1-2 `$where`, A10 open redirect, SSRF) and structurally miss the shape-B absent-control ones
(A5 Helmet removed, A7 admin middleware never attached, A8 no CSRF middleware) — a pattern matcher
cannot match code that **is not there**. Shape-C reverted-fix vulns (A3 autoescape off, A6
encryption disabled) are borderline. If that holds, the shape-B/C gap is the substance of Orion's
case, and it is a *mechanistic* argument, not a scoreboard.

**The result may not hold, and that is fine.** `p/nodejsscan` and `p/owasp-top-ten` are tuned for
exactly this benchmark class; NodeGoat is a teaching repo that rule authors have seen. A high
Semgrep score is a plausible outcome. If it lands, the README says so and the differentiator
narrows to the honest one: shape-B/C coverage and per-finding verification, on arbitrary code rather
than on a benchmark whose vulns are in the rule catalogs.

**Benchmark-familiarity caveat.** Whatever the number, NodeGoat is a public teaching benchmark and a
deterministic scanner's score on it is an *upper* bound on its real-world performance in a way
Orion's is not. The report will state this rather than let a low Semgrep number be read as more
damning than it is — the caveat cuts against the conclusion this repo would prefer, which is
precisely why it belongs in the report.

**Scope discipline.** The temptation is to hand-tune packs after seeing the first number. The packs
are fixed in §8 *before* the run; changing them afterward requires disclosing both numbers in the
report.
