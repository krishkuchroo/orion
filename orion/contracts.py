"""Frozen data contracts shared across every Orion component.

This module is the integration spine. Discovery, verification, reporting, and the monitor all
speak in these types, so the parallel build streams agree on these shapes without seeing each
other's code. Do not rename a field here without updating every consumer — that is the whole
point of freezing it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

Shape = Literal["A", "B", "C", "D"]
Confidence = Literal["LOW", "MEDIUM", "HIGH"]
Decision = Literal["CONFIRM", "REJECT", "INCONCLUSIVE", "ERROR"]


@dataclass
class Lead:
    """One candidate lead from the discovery fleet. Never a confirmed finding on its own."""
    index: int
    shape: Shape
    text: str          # human-readable candidate-lead statement
    evidence: str      # the Cypher query result / snippet the discoverer cited
    confidence: Confidence


@dataclass
class Verdict:
    """The independent verifier's decision on a single Lead."""
    lead: Lead
    decision: Decision
    reason: str
    evidence: str = ""  # what the verifier itself queried or read


# A progress event is a plain dict appended one-per-line to the run's JSONL log, and also the
# argument to OnEvent. Keys:
#   ts    : str  ISO timestamp
#   phase : "build" | "discover" | "verify" | "report"
#   shape : str | None   (discovery shape A/B/C/D, when relevant)
#   lead  : int | None   (lead index, when relevant)
#   turn  : int | None   (agent turn, when relevant)
#   event : "start" | "query" | "tool" | "lead" | "verdict" | "warn" | "done" | "error"
#   detail: str
ProgressEvent = dict
OnEvent = Callable[[ProgressEvent], None]
