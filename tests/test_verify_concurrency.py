"""Concurrency tests for verify_all: bounded-parallel verification.

Pure and token-free. A fake run_agent stands in for the claude -p subprocess (the one unavoidable
seam), so these exercise the REAL async fan-out and semaphore in verify_all without spending tokens
or needing claude/Neo4j. verify_all injects run_agent, mirroring verify_lead's existing seam.

Verification is 78% of a run's wall clock and used to run one lead at a time; these pin the fix:
several leads verify at once, but never more than the cap, and results stay in lead order.
"""
from __future__ import annotations

import re
import threading
import time

from orion.contracts import Lead
from orion.verify import verify_all


def _leads(n: int) -> list[Lead]:
    return [Lead(index=i, shape="A", text=f"claim-{i}", evidence="e", confidence="HIGH")
            for i in range(n)]


class _Tracker:
    """A fake run_agent recording peak concurrency and completion order across worker threads."""

    def __init__(self, sleep: float = 0.1, per_lead_sleep: dict | None = None):
        self.sleep = sleep
        self.per_lead_sleep = per_lead_sleep or {}
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.completed: list[int] = []

    def __call__(self, session_id, system, message, **kwargs) -> dict:
        idx = int(re.search(r"claim-(\d+)", message).group(1))
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.per_lead_sleep.get(idx, self.sleep))
        with self.lock:
            self.active -= 1
            self.completed.append(idx)
        return {"decision": "CONFIRM", "reason": "r", "evidence": f"e{idx}"}


def test_verify_all_runs_bounded_concurrent():
    tracker = _Tracker(sleep=0.1)
    leads = _leads(6)

    verdicts = verify_all("scan", leads, "repo", lambda ev: None,
                          run_agent=tracker, concurrency=3)

    # Every lead verified, returned in input order.
    assert [v.lead.index for v in verdicts] == [0, 1, 2, 3, 4, 5]
    assert all(v.decision == "CONFIRM" for v in verdicts)
    # Actually concurrent (more than one at a time) but never exceeding the cap.
    assert tracker.max_active > 1, "verification did not run concurrently"
    assert tracker.max_active <= 3, f"exceeded the concurrency cap: {tracker.max_active}"


def test_verify_all_preserves_lead_order_regardless_of_completion():
    # Lead 0 sleeps longest and finishes LAST; if results were gathered as-completed the order would
    # be reversed. verify_all must still return them in input order.
    per = {0: 0.20, 1: 0.15, 2: 0.10, 3: 0.03}
    tracker = _Tracker(per_lead_sleep=per)
    leads = _leads(4)

    verdicts = verify_all("scan", leads, "repo", lambda ev: None,
                          run_agent=tracker, concurrency=4)

    assert [v.lead.index for v in verdicts] == [0, 1, 2, 3]
    # Sanity: completion order really was reversed, so the test exercised the reordering it guards.
    assert tracker.completed == [3, 2, 1, 0]


def test_verify_all_concurrency_one_is_sequential():
    tracker = _Tracker(sleep=0.02)
    leads = _leads(4)

    verdicts = verify_all("scan", leads, "repo", lambda ev: None,
                          run_agent=tracker, concurrency=1)

    assert [v.lead.index for v in verdicts] == [0, 1, 2, 3]
    assert tracker.max_active == 1, "concurrency=1 must run strictly sequentially"
    assert tracker.completed == [0, 1, 2, 3]


def test_verify_all_empty_leads_returns_empty():
    assert verify_all("scan", [], "repo", lambda ev: None, run_agent=_Tracker()) == []


def test_verify_all_default_concurrency_is_a_positive_int():
    from orion import config
    assert isinstance(config.VERIFY_CONCURRENCY, int) and config.VERIFY_CONCURRENCY >= 1
