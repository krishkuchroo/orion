"""Runtime observation: enrich the static graph with what actually executes.

Opt-in stage (`orion scan --runtime`) that runs AFTER the static build and persist. It boots or
rebuilds the scanned target, drives it with a bounded coverage-guided loop, correlates the observed
coverage/call-tree back onto existing graph nodes by (file_path, line), and writes the result into
the same Neo4j partition the agents query -- additive props (`executed`/`hit_count`) plus one new
edge type (`OBSERVED_CALL`), through its own driver, with its own idempotent clear.

It touches NO existing build output: no `normalize`, no taint seam, no `FLOWS_TO`, no `NODE_KEY`
change. The static graph stays byte-for-byte identical, which is why the 217/1075 FLOWS_TO parity
tripwires cannot move. See docs/superpowers/specs/2026-08-11-runtime-observation-design.md.
"""
from __future__ import annotations

from .enrich import enrich

__all__ = ["enrich"]
