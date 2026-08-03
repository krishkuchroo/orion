"""Item 4: structural dedup.

Token-free tests for `discover._dedup` once leads can carry :CandidateFlow endpoints. Two leads on
the same (source_uid, sink_uid) collapse regardless of wording (the lexical key missed this); leads
with no endpoints keep the lexical `(shape, text[:80])` fallback; the two keyspaces stay disjoint.
"""
from __future__ import annotations

from orion import discover
from orion.contracts import Lead


def _lead(i, text, *, shape="A", source_uid=None, sink_uid=None, evidence="e"):
    return Lead(index=i, shape=shape, text=text, evidence=evidence, confidence="MEDIUM",
                source_uid=source_uid, sink_uid=sink_uid)


def test_same_endpoints_collapse_despite_different_text():
    leads = [
        _lead(0, "SQL injection: user id flows into the query", source_uid="src1", sink_uid="snk1"),
        _lead(1, "Unsanitized id reaches db.query -- injection", source_uid="src1", sink_uid="snk1"),
    ]
    deduped = discover._dedup(leads)
    assert len(deduped) == 1
    assert deduped[0].evidence == "e"        # first occurrence kept
    assert deduped[0].index == 0             # reindexed from 0


def test_distinct_sinks_are_not_merged():
    """Sharing a source but hitting different sinks are two real bugs -- they must NOT merge."""
    leads = [
        _lead(0, "flow to exec", source_uid="src1", sink_uid="snk1"),
        _lead(1, "flow to render", source_uid="src1", sink_uid="snk2"),
    ]
    deduped = discover._dedup(leads)
    assert len(deduped) == 2
    assert {l.sink_uid for l in deduped} == {"snk1", "snk2"}


def test_structural_and_lexical_keyspaces_are_disjoint():
    """A structural lead and an endpoint-less lead with similar text do not collide; the lexical
    fallback still dedups the endpoint-less ones by (shape, text[:80])."""
    leads = [
        _lead(0, "same words here", source_uid="src1", sink_uid="snk1"),   # structural
        _lead(1, "same words here"),                                        # lexical (no endpoints)
        _lead(2, "same words here"),                                        # lexical dup of #1
        _lead(3, "same words here", shape="B"),                             # different shape -> distinct
    ]
    deduped = discover._dedup(leads)
    # structural(0) + lexical A(1, collapsing 2) + lexical B(3) = 3
    assert len(deduped) == 3
    assert [l.index for l in deduped] == [0, 1, 2]      # dense reindex


def test_partial_endpoint_falls_back_to_lexical():
    """A lead with only a source (no sink) has no complete structural anchor -> lexical key."""
    leads = [
        _lead(0, "identical text", source_uid="src1"),   # sink_uid None -> lexical
        _lead(1, "identical text"),                       # lexical dup -> collapses with #0
    ]
    deduped = discover._dedup(leads)
    assert len(deduped) == 1
