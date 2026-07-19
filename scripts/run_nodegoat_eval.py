#!/usr/bin/env python
"""NodeGoat recall harness — scores Orion's full pipeline against the 15 ground-truth vulns.

Runs (or reuses) a scan, discovers + verifies, then matches every CONFIRMED verdict to
`tests.ground_truth_nodegoat.GROUND_TRUTH` by **file overlap + vulnerability class**, and prints:

    - N/15 recall (and N/14 over the checkable subset; A9/deps is a known data-gap),
    - which ground-truth vulns were MISSED,
    - which CONFIRMED verdicts matched no ground truth (candidate false positives).

Usage:
    ./.venv/bin/python scripts/run_nodegoat_eval.py [REPO] [--scan-id ID] [--json OUT] [--quiet]

REPO defaults to fixtures/NodeGoat. Pass --scan-id to reuse an already built+indexed scan
(skips build/index — the integration path builds once, then evals without rebuilding).

The matching logic (`match_verdicts`) is a pure function so it can be unit-tested without tokens.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.ground_truth_nodegoat import GROUND_TRUTH, RECALL_BAR, TOTAL, CHECKABLE, GroundTruth

# DISTINCTIVE per-vuln tokens. Two hard lessons from the first run drove this design:
#   1. Match the LEAD'S OWN CLAIM, not the verifier's verbose reason/evidence — the verifier
#      cross-references other files/vulns ("unlike the open redirect in index.js…"), which leaked
#      matches across ground truths. `_verdict_blob` below uses lead.text + lead.evidence only.
#   2. Use tokens UNIQUE to each vuln, never generic words. "access control" collided A4/A7;
#      "package" spuriously credited A9. Each token here identifies exactly its vuln class, so
#      vulns that share a file (server.js hosts A2-1/A3/A5; session.js hosts A1-3/A2-1/A2-2) don't
#      cross-match. A verdict matches iff it names the file AND hits one distinctive token.
CLASS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "A1-1": ("eval", "ssjs", "server-side js", "server side js"),
    "A1-2": ("$where", "nosql"),
    "A1-3": ("log injection", "log forging", "log/crlf", "crlf"),
    "A2-1": ("session cookie", "httponly", "session hardening", "session secret",
             "session management", "cookie name", "secure flag"),
    "A2-2": ("password policy", "password-policy", "enumeration", "weak password", "weak-password",
             "plaintext password", "password hashing", "password comparison", "comparepassword", "bcrypt"),
    "A3": ("autoescape", "auto-escap", "auto escap", "escaping disabled", "swig", "xss"),
    "A4": ("idor", "direct object", "req.params"),
    "A5": ("helmet", "x-frame", "clickjack", "hsts", "x-powered-by", "security header",
           "security response header", "security-misconfiguration"),
    "A6": ("encrypt", "ssn", "sensitive-data", "sensitive data", "pii"),
    "A7": ("isadmin", "function-level", "function level", "never attached",
           "admin-authorization", "admin authorization", "admin middleware"),
    "A8": ("csrf", "forgery"),
    # A9 is the known data-gap (0 Dependency nodes / no CVE data). Only a genuine dependency-CVE
    # signal counts — a finding that merely mentions "package.json" is NOT a dependency finding.
    "A9": ("cve-", "known vulnerabilit", "vulnerable version", "outdated version", "npm audit", "retire.js"),
    "A10": ("redirect", "forward", "unvalidated"),
    "SSRF": ("ssrf", "server-side request", "server side request", "needle.get"),
    "ReDoS": ("redos", "backtracking", "nested quantifier", "catastrophic", "([0-9]+)+"),
}


def _text_blob(v) -> str:
    """The LEAD's focused CLAIM (`lead.text`) only, lowercased. The vuln-CLASS token must come from
    here -- never from `lead.evidence`, which is the discoverer's raw query result (often a broad
    `MATCH (c:CpgCall) RETURN c.code, c.file_path` dump whose incidental class-words would otherwise
    cross-credit unrelated ground truths and inflate recall)."""
    return (getattr(v.lead, "text", "") or "").lower()


def _file_blob(v) -> str:
    """Text + the discoverer's cited evidence, lowercased -- used ONLY for the file match. The file
    is legitimately cited in either place (many leads name the vuln in `text` but the file in the
    query in `evidence`), so allowing evidence here recovers real finds; the class token stays
    text-only so this cannot inflate."""
    lead = v.lead
    return " ".join(p for p in (getattr(lead, "text", ""), getattr(lead, "evidence", "")) if p).lower()


def _matches(gt: GroundTruth, text_blob: str, file_blob: str) -> bool:
    """A lead matches a ground truth iff (file cited anywhere in the claim/evidence) AND (a
    distinctive class token appears in the focused CLAIM). Asymmetric on purpose: file from
    text+evidence recovers real finds; token from text-only prevents a broad evidence dump from
    crediting several ground truths at once."""
    if not any(f.lower() in file_blob for f in gt.files):
        return False
    kws = CLASS_KEYWORDS.get(gt.id, ())
    if kws and not any(k in text_blob for k in kws):
        return False
    return True


def match_verdicts(confirmed) -> tuple[dict[str, list[int]], list[int]]:
    """Pure matcher. Given the list of CONFIRM verdicts, return
    (found: {gt_id -> [verdict indices that matched it]}, unmatched: [verdict indices matching no gt]).
    A verdict may support more than one ground truth only if it genuinely overlaps both file+class."""
    text_blobs = [_text_blob(v) for v in confirmed]
    file_blobs = [_file_blob(v) for v in confirmed]
    found: dict[str, list[int]] = {}
    matched_any: set[int] = set()
    for gt in GROUND_TRUTH:
        hits = [i for i in range(len(confirmed)) if _matches(gt, text_blobs[i], file_blobs[i])]
        if hits:
            found[gt.id] = hits
            matched_any.update(hits)
    unmatched = [i for i in range(len(confirmed)) if i not in matched_any]
    return found, unmatched


def _run_pipeline(repo: str, scan_id: str | None, quiet: bool):
    """Build/index (unless scan_id given) then discover + verify. Returns (scan_id, verdicts)."""
    from orion import graph_build, embed, discover, verify
    from orion.graph import profiles

    # Measure the SAME discovery path `orion scan` ships: profile-injected prompt (cli.py passes it).
    profile = profiles.select_profile(repo)

    def on_event(ev: dict) -> None:
        if quiet:
            return
        phase = ev.get("phase", ev.get("event", "?"))
        detail = ev.get("detail", "")
        if isinstance(detail, str) and len(detail) > 100:
            detail = detail[:100] + "…"
        print(f"  [{phase}] {ev.get('event','')} {detail}".rstrip(), file=sys.stderr)

    if scan_id is None:
        print(f"[eval] building graph for {repo} …", file=sys.stderr)
        scan_id = graph_build.build(repo)
        print(f"[eval] scan_id = {scan_id}", file=sys.stderr)
        try:
            print("[eval] indexing (semantic) …", file=sys.stderr)
            embed.index(repo, scan_id)
        except Exception as e:  # embedding is best-effort; graph-only path still works
            print(f"[eval] WARN: embed.index failed ({e!r}); continuing graph-only", file=sys.stderr)
    else:
        print(f"[eval] reusing scan_id = {scan_id} (skipping build/index)", file=sys.stderr)

    print(f"[eval] discovery … (profile: {profile.name})", file=sys.stderr)
    leads = discover.discover(scan_id, on_event, profile)
    print(f"[eval] {len(leads)} leads", file=sys.stderr)

    print("[eval] verification …", file=sys.stderr)
    verdicts = verify.verify_all(scan_id, leads, repo, on_event)
    return scan_id, verdicts


def render(confirmed, found, unmatched) -> str:
    n_found = len(found)
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"NodeGoat recall: {n_found}/{TOTAL}  (checkable {n_found}/{CHECKABLE}; bar = {RECALL_BAR})")
    verdict = "PASS ✅" if n_found >= RECALL_BAR else "BELOW BAR ❌"
    lines.append(f"  {verdict}   false-positive candidates: {len(unmatched)}")
    lines.append("=" * 72)
    lines.append("")
    lines.append("Ground truth:")
    for gt in GROUND_TRUTH:
        if gt.id in found:
            tag = "FOUND  ✅"
            by = " (verdict " + ",".join(f"#{i}" for i in found[gt.id]) + ")"
        else:
            tag = "MISS   ✗ " if not gt.known_gap else "MISS   – "
            by = "  [known data-gap]" if gt.known_gap else ""
        lines.append(f"  {tag} {gt.id:<6} {gt.name}{by}")
    lines.append("")
    if unmatched:
        lines.append("CONFIRMED verdicts matching NO ground truth (candidate false positives):")
        for i in unmatched:
            v = confirmed[i]
            lines.append(f"  #{i} [{v.lead.shape}/{v.lead.confidence}] {v.lead.text[:90]}")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NodeGoat recall harness for Orion")
    ap.add_argument("repo", nargs="?", default="fixtures/NodeGoat", help="target repo (default fixtures/NodeGoat)")
    ap.add_argument("--scan-id", default=None, help="reuse an already built+indexed scan (skip build/index)")
    ap.add_argument("--json", dest="json_out", default=None, help="also write a JSON result to this path")
    ap.add_argument("--quiet", action="store_true", help="suppress per-event progress on stderr")
    args = ap.parse_args(argv)

    scan_id, verdicts = _run_pipeline(args.repo, args.scan_id, args.quiet)
    confirmed = [v for v in verdicts if v.decision == "CONFIRM"]
    found, unmatched = match_verdicts(confirmed)

    text = render(confirmed, found, unmatched)
    print("\n" + text)

    if args.json_out:
        payload = {
            "scan_id": scan_id,
            "recall": len(found),
            "total": TOTAL,
            "checkable": CHECKABLE,
            "bar": RECALL_BAR,
            "pass": len(found) >= RECALL_BAR,
            "found": {gt_id: idxs for gt_id, idxs in found.items()},
            "missed": [gt.id for gt in GROUND_TRUTH if gt.id not in found],
            "false_positive_candidates": len(unmatched),
            "verdicts": [dataclasses.asdict(v) for v in verdicts],
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2))
        print(f"[eval] wrote {args.json_out}", file=sys.stderr)

    return 0 if len(found) >= RECALL_BAR else 1


if __name__ == "__main__":
    raise SystemExit(main())
