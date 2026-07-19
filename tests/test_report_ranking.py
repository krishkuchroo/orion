"""Token-free, DB-free tests for report.render and monitor's logging/tail plumbing.

report.py and monitor.py only import `contracts` + stdlib, so these tests run anywhere -- no
Neo4j, no `claude` CLI, no embedding model.
"""
from __future__ import annotations

import json

from orion.contracts import Lead, Verdict
from orion.monitor import read_events, run_logger
from orion.report import render


def _lead(index: int, shape="A", confidence="HIGH", text=None, evidence=None) -> Lead:
    return Lead(
        index=index,
        shape=shape,
        text=text or f"lead {index} claim",
        evidence=evidence or f"lead {index} cited evidence",
        confidence=confidence,
    )


def test_report_ranks_confirmed_first():
    confirmed = Verdict(
        lead=_lead(1, evidence="CONFIRM-EVIDENCE-1"),
        decision="CONFIRM",
        reason="reproduced the tainted flow",
        evidence="verifier query showed req.body.x reaching res.send unsanitized",
    )
    rejected = Verdict(
        lead=_lead(2, evidence="REJECT-EVIDENCE-2"),
        decision="REJECT",
        reason="input is sanitized upstream",
        evidence="verifier found an escaping call on the path",
    )
    inconclusive = Verdict(
        lead=_lead(3, evidence="INCONCLUSIVE-EVIDENCE-3"),
        decision="INCONCLUSIVE",
        reason="could not resolve the call target",
        evidence="verifier query returned no rows",
    )
    errored = Verdict(
        lead=_lead(4, evidence="ERROR-EVIDENCE-4"),
        decision="ERROR",
        reason="verifier subprocess timed out",
        evidence="",
    )

    # Deliberately out of rank order going in.
    text = render([rejected, errored, confirmed, inconclusive])

    # CONFIRM before INCONCLUSIVE before REJECT before ERROR.
    i_confirm = text.index("[CONFIRM]")
    i_inconclusive = text.index("[INCONCLUSIVE]")
    i_reject = text.index("[REJECT]")
    i_error = text.index("[ERROR]")
    assert i_confirm < i_inconclusive < i_reject < i_error

    # Both the lead's own cited evidence and the verifier's independent evidence show up.
    assert "CONFIRM-EVIDENCE-1" in text
    assert "req.body.x reaching res.send unsanitized" in text
    assert "REJECT-EVIDENCE-2" in text
    assert "escaping call on the path" in text
    assert "INCONCLUSIVE-EVIDENCE-3" in text
    assert "no rows" in text
    assert "ERROR-EVIDENCE-4" in text
    assert "timed out" in text

    # Summary line at the top counts each decision.
    assert "4 candidate leads" in text.splitlines()[0]
    assert "1 CONFIRM" in text
    assert "1 REJECT" in text
    assert "1 INCONCLUSIVE" in text
    assert "1 ERROR" in text


def test_report_stable_order_within_same_decision():
    a = Verdict(lead=_lead(5), decision="CONFIRM", reason="r5", evidence="e5")
    b = Verdict(lead=_lead(2), decision="CONFIRM", reason="r2", evidence="e2")
    text = render([a, b])
    # Same decision -> original lead index order (2 before 5), not insertion order.
    assert text.index("lead 2") < text.index("lead 5")


def test_monitor_roundtrip(tmp_path):
    run_dir = str(tmp_path / "run")
    on_event = run_logger(run_dir, quiet=True)

    events = [
        {"ts": "2026-07-18T00:00:00Z", "phase": "build", "shape": None, "lead": None,
         "turn": None, "event": "start", "detail": "building graph"},
        {"ts": "2026-07-18T00:00:01Z", "phase": "discover", "shape": "A", "lead": None,
         "turn": 1, "event": "query", "detail": "MATCH (c:CpgCall) RETURN c LIMIT 5"},
        {"ts": "2026-07-18T00:00:02Z", "phase": "verify", "shape": "A", "lead": 1,
         "turn": 1, "event": "verdict", "detail": "CONFIRM"},
    ]
    for evt in events:
        on_event(evt)

    log_path = tmp_path / "run" / "progress.jsonl"
    assert log_path.exists()
    lines = log_path.read_text().splitlines()
    assert len(lines) == 3
    round_tripped = [json.loads(line) for line in lines]
    assert round_tripped == events

    # The pure read helper (what `tail` uses under the hood) returns the same events.
    assert read_events(run_dir) == events


def test_on_event_survives_log_write_failure(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # progress.jsonl is a directory, not a file -- open(path, "a") raises IsADirectoryError
    # (an OSError), simulating a write failure (disk full, permissions, ...) without needing
    # to actually exhaust disk. A live PyGoat scan hit exactly this via ENOSPC and it took the
    # whole discovery pipeline down with it -- progress logging must be best-effort, never fatal.
    (run_dir / "progress.jsonl").mkdir()
    on_event = run_logger(str(run_dir), quiet=True)

    on_event({"ts": "t", "phase": "discover", "shape": "A", "lead": None, "turn": None,
              "event": "tool", "detail": "should not crash the caller"})


def test_monitor_run_logger_is_safe_from_threads():
    import threading

    from orion.monitor import run_logger

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        on_event = run_logger(tmp, quiet=True)

        def emit(n):
            for i in range(20):
                on_event({"ts": "t", "phase": "discover", "shape": "A", "lead": n,
                           "turn": i, "event": "query", "detail": f"worker {n} turn {i}"})

        threads = [threading.Thread(target=emit, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        got = read_events(tmp)
        assert len(got) == 80
        # Every line must have parsed cleanly as its own JSON object (no interleaved writes).
        assert all(isinstance(e, dict) and "detail" in e for e in got)
