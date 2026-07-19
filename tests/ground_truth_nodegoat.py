"""NodeGoat ground truth: the 15 distinct exploitable vulnerabilities Orion is scored against.

Reconstructed from NodeGoat's own `/tutorial` (OWASP Top-10 2013 + SSRF + ReDoS bonus classes)
and reconciled with the 23 `// Fix for A...` source markers, matching the recall bar the prior
PoC hit (6/15 shape-A-only, 13/15 multi-shape, 0 false positives).

`run_nodegoat_eval.py` matches Orion's CONFIRMED findings to these by OWASP id + file overlap.
`shape` = the discovery lens most likely to surface it (A data-flow, B absent-control,
C disabled/reverted, D pattern/deps). `known_gap=True` marks items not derivable from this scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GroundTruth:
    id: str          # OWASP-style id
    name: str
    files: tuple[str, ...]   # substrings that should appear in a correct finding's evidence
    shape: str               # A | B | C | D
    known_gap: bool = False  # true = not checkable from the CPG (e.g. dependency data absent)


GROUND_TRUTH: list[GroundTruth] = [
    GroundTruth("A1-1", "Server-Side JS Injection via eval()", ("contributions.js",), "A"),
    GroundTruth("A1-2", "NoSQL Injection via $where operator", ("allocations-dao.js",), "A"),
    GroundTruth("A1-3", "Log Injection (CRLF forging)", ("session.js",), "A"),
    GroundTruth("A2-1", "Broken Auth — insecure session management", ("server.js", "session.js"), "B"),
    GroundTruth("A2-2", "Broken Auth — weak password policy + user enumeration",
                ("session.js", "user-dao.js"), "C"),
    GroundTruth("A3", "Cross-Site Scripting (auto-escaping disabled)", ("server.js",), "C"),
    GroundTruth("A4", "Insecure Direct Object Reference", ("allocations.js",), "A"),
    GroundTruth("A5", "Security Misconfiguration (Helmet headers removed)", ("server.js",), "B"),
    GroundTruth("A6", "Sensitive Data Exposure (SSN/DOB encryption disabled)", ("profile-dao.js",), "C"),
    GroundTruth("A7", "Missing Function-Level Access Control", ("index.js",), "B"),
    GroundTruth("A8", "Cross-Site Request Forgery (missing CSRF middleware)",
                ("contributions.js", "app.js", "index.js"), "B"),
    # Dependency nodes ARE now populated (graph/deps.py parses package.json), but confirming a
    # component is *known-vulnerable* needs a CVE feed the graph doesn't carry — so still a gap.
    GroundTruth("A9", "Using Components with Known Vulnerabilities",
                ("package.json",), "D", known_gap=True),
    GroundTruth("A10", "Unvalidated Redirects and Forwards", ("index.js",), "A"),
    GroundTruth("SSRF", "Server-Side Request Forgery", ("research.js",), "A"),
    GroundTruth("ReDoS", "Regex Denial of Service (nested quantifier)", ("profile.js", "app"), "D"),
]

TOTAL = len(GROUND_TRUTH)          # 15
CHECKABLE = sum(1 for g in GROUND_TRUTH if not g.known_gap)  # 14 (A9 needs a CVE feed, not in scan)
RECALL_BAR = 13                    # the bar to match or beat
