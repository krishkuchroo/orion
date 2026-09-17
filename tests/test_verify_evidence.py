"""Item 5: precomputed evidence subgraph handed to the verifier.

Token-free. A fake run_agent captures the message verify_lead builds; a fake fetch_subgraph stands
in for the graph read. Asserts the evidence block is inlined when a lead carries :CandidateFlow
endpoints and omitted otherwise, and that a fetch failure never breaks verification.
"""
from __future__ import annotations

from orion import verify
from orion.contracts import Lead

_SRC = "a" * 40
_SNK = "b" * 40


def _lead(**kw) -> Lead:
    base = dict(index=0, shape="A", text="claim", evidence="ev", confidence="HIGH")
    base.update(kw)
    return Lead(**base)


class _Capture:
    """Fake run_agent: records the message and returns a CONFIRM verdict."""
    def __init__(self):
        self.message = None

    def __call__(self, session_id, system, message, **kwargs):
        self.message = message
        return {"decision": "CONFIRM", "reason": "r", "evidence": "e"}


_SUBGRAPH = {
    "sink_category": "code_exec",
    "path": [
        {"uid": _SRC, "code": "req.body.cmd", "file_path": "a.js", "line": 10},
        {"uid": _SNK, "code": "exec(cmd)", "file_path": "b.js", "line": 42},
    ],
}


# --- pure formatter ---------------------------------------------------------------------------

def test_format_subgraph_marks_source_and_sink():
    block = verify._format_evidence_subgraph(_SUBGRAPH)
    assert "PRECOMPUTED EVIDENCE SUBGRAPH" in block
    assert "code_exec" in block
    assert "[source]" in block and "[sink]" in block
    assert "exec(cmd)" in block and "b.js:42" in block


def test_format_empty_path_is_blank():
    assert verify._format_evidence_subgraph({"path": []}) == ""
    assert verify._format_evidence_subgraph({}) == ""


# --- verify_lead integration ------------------------------------------------------------------

def test_evidence_block_inlined_when_lead_has_endpoints():
    cap = _Capture()
    lead = _lead(source_uid=_SRC, sink_uid=_SNK)
    verdict = verify.verify_lead("scan", lead, "repo", lambda ev: None, cap,
                                 fetch_subgraph=lambda *a: _SUBGRAPH)
    assert verdict.decision == "CONFIRM"
    assert "PRECOMPUTED EVIDENCE SUBGRAPH" in cap.message
    assert "exec(cmd)" in cap.message
    # trust invariant: still the lead's own claim, no discovery transcript
    assert "claim" in cap.message


def test_no_endpoints_means_no_fetch_and_no_block():
    cap = _Capture()
    called = {"n": 0}

    def _fetch(*a):
        called["n"] += 1
        return _SUBGRAPH

    verify.verify_lead("scan", _lead(), "repo", lambda ev: None, cap, fetch_subgraph=_fetch)
    assert called["n"] == 0                              # endpoint-less lead never hits the graph
    assert "PRECOMPUTED EVIDENCE SUBGRAPH" not in cap.message


def test_fetch_returning_none_omits_block():
    cap = _Capture()
    verify.verify_lead("scan", _lead(source_uid=_SRC, sink_uid=_SNK), "repo", lambda ev: None, cap,
                       fetch_subgraph=lambda *a: None)
    assert "PRECOMPUTED EVIDENCE SUBGRAPH" not in cap.message


def test_sink_centrality_populated_on_verdict():
    cap = _Capture()
    sub = {"sink_category": "sql", "sink_centrality": 0.73,
           "path": [{"uid": _SRC, "code": "x", "file_path": "a", "line": 1},
                    {"uid": _SNK, "code": "y", "file_path": "b", "line": 2}]}
    verdict = verify.verify_lead("scan", _lead(source_uid=_SRC, sink_uid=_SNK), "repo",
                                 lambda ev: None, cap, fetch_subgraph=lambda *a: sub)
    assert verdict.sink_centrality == 0.73


def test_sink_centrality_defaults_zero_without_endpoints():
    cap = _Capture()
    verdict = verify.verify_lead("scan", _lead(), "repo", lambda ev: None, cap,
                                 fetch_subgraph=lambda *a: _SUBGRAPH)
    assert verdict.sink_centrality == 0.0


def test_fetch_exception_is_swallowed():
    cap = _Capture()

    def _boom(*a):
        raise RuntimeError("graph down")

    verdict = verify.verify_lead("scan", _lead(source_uid=_SRC, sink_uid=_SNK), "repo",
                                 lambda ev: None, cap, fetch_subgraph=_boom)
    assert verdict.decision == "CONFIRM"                 # advisory: failure never breaks verify
    assert "PRECOMPUTED EVIDENCE SUBGRAPH" not in cap.message
