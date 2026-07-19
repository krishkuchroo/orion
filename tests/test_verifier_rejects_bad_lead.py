"""Verifier tests.

`test_verdict_*` are PURE unit tests of `verify._verdict_from_result` -- a plain function with no
I/O. They must import cleanly even if `orion/claude_cli.py` doesn't exist yet or is mid-build
(Task C builds it in parallel): `orion/verify.py` only imports `claude_cli.run_agent` lazily
inside `verify_all`, so importing `orion.verify` here never touches that module.

`test_seeded_bad_lead_rejected` is `@pytest.mark.slow` -- it drives a REAL claude -p session (fp-check
skill, real tokens) per the trust invariant. It is written here but deliberately NOT run by this
suite; the controller runs it once `claude_cli.run_agent` lands. De-risked already: the controller's
own fp-check probe on a bogus lead (nonexistent file) returned FALSE POSITIVE headlessly.
"""
from __future__ import annotations

import pytest

from orion.contracts import Lead
from orion.verify import _verdict_from_result


def _lead(**overrides) -> Lead:
    defaults = dict(index=1, shape="A", text="claim text", evidence="cited evidence", confidence="HIGH")
    defaults.update(overrides)
    return Lead(**defaults)


def test_verdict_happy_path_reject():
    lead = _lead()
    result = {"decision": "REJECT", "reason": "no such call site in the graph", "evidence": "0 rows"}

    verdict = _verdict_from_result(lead, result)

    assert verdict.lead is lead
    assert verdict.decision == "REJECT"
    assert verdict.reason == "no such call site in the graph"
    assert verdict.evidence == "0 rows"


def test_verdict_happy_path_confirm():
    lead = _lead()
    result = {"decision": "CONFIRM", "reason": "found the sink", "evidence": "app/routes/x.js:42"}

    verdict = _verdict_from_result(lead, result)

    assert verdict.decision == "CONFIRM"
    assert verdict.evidence == "app/routes/x.js:42"


def test_verdict_happy_path_inconclusive_missing_evidence():
    """`evidence` is optional in the schema -- absence must not crash the mapper."""
    lead = _lead()
    result = {"decision": "INCONCLUSIVE", "reason": "graph and source disagree"}

    verdict = _verdict_from_result(lead, result)

    assert verdict.decision == "INCONCLUSIVE"
    assert verdict.evidence == ""


def test_verdict_from_error_sentinel_is_error_not_confirm():
    """A run_agent failure sentinel must NEVER be read as a silent CONFIRM."""
    lead = _lead()
    result = {"_error": "subprocess timed out after 180s"}

    verdict = _verdict_from_result(lead, result)

    assert verdict.decision == "ERROR"
    assert "subprocess timed out" in verdict.reason


def test_verdict_from_missing_decision_field_is_error():
    lead = _lead()
    result = {"reason": "no decision key at all"}

    verdict = _verdict_from_result(lead, result)

    assert verdict.decision == "ERROR"


def test_verdict_from_malformed_decision_value_is_error():
    lead = _lead()
    result = {"decision": "MAYBE", "reason": "not one of the enum values"}

    verdict = _verdict_from_result(lead, result)

    assert verdict.decision == "ERROR"


def test_verdict_from_non_dict_result_is_error():
    lead = _lead()

    verdict = _verdict_from_result(lead, None)

    assert verdict.decision == "ERROR"


def test_verify_lead_requests_retries():
    """The verifier is where the transient `claude -p exited 1` crashes happened (heavy fp-check
    subagent runs under batch load). verify_lead must ask run_agent to retry so a transient blip
    doesn't silently become an ERROR verdict and cost a real recall point."""
    from orion.verify import verify_lead

    captured: dict = {}

    def fake_run_agent(session_id, system, message, **kwargs):
        captured.update(kwargs)
        return {"decision": "REJECT", "reason": "r", "evidence": "e"}

    verdict = verify_lead("scan", _lead(), "fixtures/NodeGoat", lambda ev: None, fake_run_agent)

    assert verdict.decision == "REJECT"
    assert captured.get("retries", 0) >= 1  # resilience is wired, not left to chance


@pytest.mark.slow
def test_seeded_bad_lead_rejected():
    """REAL TOKENS -- written but NOT executed here; the controller runs this once
    orion/claude_cli.py::run_agent exists. Seeds a lead claiming a vuln at a file/line that does
    not exist in the loaded NodeGoat scan, and asserts the independent verifier rejects it."""
    from orion.graph_build import scan_id_for
    from orion.verify import verify_all

    scan_id = scan_id_for("fixtures/NodeGoat")
    bad_lead = _lead(
        index=999,
        shape="A",
        text=(
            "SQL injection: user input from req.body.password flows unsanitized into a raw SQL "
            "query built in app/routes/nonexistent-file-xyz123.js at line 4242."
        ),
        evidence="fabricated -- this file/line does not exist anywhere in NodeGoat",
        confidence="HIGH",
    )

    events: list[dict] = []
    verdicts = verify_all(scan_id, [bad_lead], "fixtures/NodeGoat", events.append)

    assert len(verdicts) == 1
    assert verdicts[0].decision == "REJECT"
