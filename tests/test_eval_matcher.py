"""Regression tests for the NodeGoat eval matcher (scripts/run_nodegoat_eval.py).

The first live run exposed two ways the matcher LIED — it reported 15/15 when the hand-verified
truth was 13/15:
  1. A9 (a known data-gap: 0 Dependency nodes) was credited to a CSRF and a helmet finding whose
     text merely mentioned "package.json" + the generic word "package".
  2. A7 was credited to the IDOR finding because both shared the generic phrase "access control".
These tests pin the fix: match the LEAD's own claim (not the verifier's cross-referencing prose)
with DISTINCTIVE per-vuln tokens. Token-free, no pipeline, no DB.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orion.contracts import Lead, Verdict
from scripts import run_nodegoat_eval as ev


def _confirm(shape: str, text: str, evidence: str = "", reason: str = "", vev: str = "") -> Verdict:
    lead = Lead(index=0, shape=shape, text=text, evidence=evidence, confidence="HIGH")
    return Verdict(lead=lead, decision="CONFIRM", reason=reason, evidence=vev)


def test_distinctive_tokens_credit_the_right_vuln():
    confirmed = [
        _confirm("A", "Server-side JS injection (RCE) in app/routes/contributions.js via eval(req.body.preTax)"),
        _confirm("A", "Insecure Direct Object Reference in app/routes/allocations.js: userId from req.params.userId"),
        _confirm("A", "Open redirect in app/routes/index.js: /learn passes req.query.url into res.redirect"),
    ]
    found, unmatched = ev.match_verdicts(confirmed)
    assert "A1-1" in found and "A4" in found and "A10" in found
    assert unmatched == []


def test_a9_not_credited_without_a_real_dependency_signal():
    """A CSRF finding that mentions package.json (verifier read the manifest to confirm csurf isn't
    installed) must NOT be credited as A9 — A9 needs a genuine CVE/vulnerable-version signal."""
    csrf = _confirm(
        "B",
        "No CSRF protection on the state-changing POST routes in app/routes/index.js; "
        "csurf is not listed in package.json.",
        evidence="MATCH ... no csrf middleware",
    )
    found, _ = ev.match_verdicts([csrf])
    assert "A8" in found          # it IS the CSRF vuln
    assert "A9" not in found      # but NOT a dependency-CVE finding


def test_a7_not_credited_to_idor_via_shared_phrase():
    """An IDOR finding whose verifier reason says 'access control' must not leak into A7 (missing
    function-level access control) — matching is on the lead claim, not the verifier's prose."""
    idor = _confirm(
        "A",
        "Insecure Direct Object Reference in app/routes/allocations.js: req.params.userId trusted",
        reason="This is a broken access control issue; the admin middleware is elsewhere.",
    )
    found, _ = ev.match_verdicts([idor])
    assert "A4" in found
    assert "A7" not in found


def test_a7_credited_only_by_its_own_distinctive_claim():
    a7 = _confirm(
        "B",
        "isAdminUserMiddleware is defined but never attached to any route in app/routes/index.js",
    )
    found, _ = ev.match_verdicts([a7])
    assert "A7" in found


def test_broad_evidence_dump_does_not_inflate_recall():
    """A CONFIRMED lead's `evidence` is the discoverer's raw query result -- often a broad
    `MATCH (c:CpgCall) RETURN c.code, c.file_path` dump that names many files. Matching must NOT
    credit unrelated ground truths from that dump: one A6 lead whose evidence happens to mention
    server.js/'security header' and index.js/'redirect' must credit ONLY A6, never A5/A10."""
    a6 = _confirm(
        "C",
        "Sensitive-data encryption disabled in app/data/profile-dao.js: ssn/dob stored plaintext",
        evidence=(
            "MATCH (c:CpgCall) RETURN c.code, c.file_path -> rows include "
            "server.js 'security header helmet', index.js 'res.redirect(req.query.url)', "
            "profile-dao.js 'ssn'"
        ),
    )
    found, _ = ev.match_verdicts([a6])
    assert "A6" in found
    assert "A5" not in found and "A10" not in found
