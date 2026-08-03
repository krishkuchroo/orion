# Orion — agenda

Forward-looking work, roughly in priority order. Each item states *why*, the *concrete steps*, and
what "done" means (so a reviewer can tell when the claim is actually backed).

## 1. Deterministic-scanner baseline (Semgrep / CodeQL head-to-head)

**Why.** The value proposition — "Orion reaches bugs a fixed rule catalog cannot, without the
false-positive flood" — is currently asserted, not measured. Until there is a committed baseline run
scored through Orion's *own* matcher, a skeptical reviewer has no reason to believe the comparison.
The README has been made honest about this (it names the baseline as uncommitted); this item is how
we make the claim real.

**Steps.**
1. Pin the exact NodeGoat checkout Orion is scored on (same commit as the eval fixture) so both tools
   see identical source.
2. Run a deterministic scanner on it:
   - Semgrep: `semgrep --config auto` (and note the ruleset/version), OR
   - CodeQL: the standard `javascript-security-and-quality` suite.
3. Map that tool's raw findings onto the 15-vuln ground truth using the **same matcher** Orion uses
   (`tests/ground_truth_nodegoat.py`) — do NOT eyeball it. If the matcher needs a small adapter to
   ingest SARIF/Semgrep JSON, write that adapter; the scoring logic stays shared.
4. Commit the raw tool output + the scored table under `examples/baseline/` so it survives a clone,
   the same way `examples/apex/` does.
5. Update the README with the measured baseline number (whatever it actually is) and a one-line
   methodology note.

**Done when.** `examples/baseline/` contains a committed Semgrep-or-CodeQL run on the pinned NodeGoat
checkout, scored through `ground_truth_nodegoat.py`, and the README cites that number instead of a
qualitative claim. Reproducible via a single documented command.

**Risks / notes.** Keep it apples-to-apples — same checkout, same matcher, disclosed tool versions and
rulesets. A baseline that quietly uses a weaker ruleset is worse than no baseline. Report the number
honestly even if it is less flattering than expected.

## 2. Capture the NodeGoat eval output as committed evidence

**Why.** The headline 14/15 result has no committed artifact — only the script and the ground truth.
`examples/README.md` is currently honest that it is reproducible-but-not-captured.

**Steps.** Run `scripts/run_nodegoat_eval.py` against the NodeGoat fixture (needs the fixture with a
prebuilt `cpg.bin`, a running Neo4j, and Claude tokens) and commit the output to `examples/nodegoat/`.

**Done when.** `examples/nodegoat/eval.log` (and the verdict JSON) is committed and the README points
at it, so the 14/15 number is backed by a clone-surviving run, not just a claim. Pairs naturally with
item 1 (same checkout → run both at once).

## 3. A9 gap — components with known vulnerabilities

**Why.** The one NodeGoat vuln Orion misses (15th) is "components with known vulnerabilities"; the
graph carries `Dependency` nodes but no CVE data, so there is nothing to match against.

**Steps.** Wire a CVE/advisory feed (e.g. OSV) to the `Dependency` nodes so Shape D can flag known-
vulnerable versions. Scope: a lookup keyed on `(name, version)`, cached locally, no mid-scan network
dependency in the hot path.

**Done when.** A NodeGoat run confirms 15/15 with the known-vuln dependency surfaced and verified, at
still-zero false positives.
