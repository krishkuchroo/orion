"""Render the run: candidate leads with their independent verdicts, confirmed ones first.

Everything here is a LEAD plus a verdict, never a "trusted finding". That honesty is the point:
Orion surfaces evidence-backed candidates, and the verifier's decision is shown alongside each,
with BOTH the lead's own cited evidence and the verifier's independently-queried evidence in view.

Only needs `contracts` + stdlib (no discover/verify/embed/graph_build imports), so it can be
tested and used without any of the heavy/live pieces being up.
"""
from __future__ import annotations

from .contracts import Verdict

# CONFIRM first (the payload), then INCONCLUSIVE (needs a human look), then REJECT (checked out
# clean), then ERROR (the verifier itself failed -- worth a look, but not a finding).
_ORDER = {"CONFIRM": 0, "INCONCLUSIVE": 1, "REJECT": 2, "ERROR": 3}


def render(verdicts: list[Verdict]) -> str:
    """A ranked, evidence-cited text report. Confirmed leads sort first; within a decision,
    leads keep their original index order. Each entry shows the lead's shape tag, confidence,
    the verifier's decision and reason, and both pieces of evidence -- the lead's own citation
    and whatever the verifier itself queried or read.
    """
    ranked = sorted(verdicts, key=lambda v: (_ORDER.get(v.decision, 9), v.lead.index))

    counts: dict[str, int] = {}
    for v in ranked:
        counts[v.decision] = counts.get(v.decision, 0) + 1
    summary = ", ".join(
        f"{counts[d]} {d}" for d in ("CONFIRM", "INCONCLUSIVE", "REJECT", "ERROR") if d in counts
    )

    lines: list[str] = [f"Orion: {len(ranked)} candidate leads ({summary})", ""]

    for v in ranked:
        lead = v.lead
        lines.append(f"[{v.decision}] lead {lead.index} - shape {lead.shape} - confidence {lead.confidence}")
        lines.append(f"  claim:             {lead.text}")
        lines.append(f"  lead evidence:     {lead.evidence}")
        lines.append(f"  verdict reason:    {v.reason}")
        lines.append(f"  verifier evidence: {v.evidence}")
        lines.append("")

    return "\n".join(lines)
