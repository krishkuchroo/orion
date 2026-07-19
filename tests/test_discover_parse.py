"""Task C: discovery fleet — token-free unit tests for the stream-json parser and the discover()
fan-out/dedup logic. NO subprocess, NO real `claude -p` call, NO Claude tokens spent.

`test_one_shape_live` at the bottom is the one exception: it is real, costs tokens, and is marked
`@pytest.mark.slow` so it is excluded from the default run. It is written but NOT executed here —
the controller runs it explicitly.
"""
from __future__ import annotations

import json
import uuid

import pytest

from orion import claude_cli, discover
from orion.contracts import Lead

# ---------------------------------------------------------------------------------------------
# A realistic captured stream-json snippet, shaped exactly like streamjson_probe.jsonl: one
# assistant tool_use calling mcp__orion__run_cypher, followed by the final `{"type":"result"}`
# line carrying both `structured_output` (preferred) and `result` (its JSON-string twin).
# ---------------------------------------------------------------------------------------------

_SAMPLE_QUERY = (
    "MATCH (c:CpgCall {scan_id:$scan_id})-[:FLOWS_TO]->(c) "
    "RETURN c.code AS code, c.file_path AS file_path LIMIT 5"
)

_SAMPLE_LEADS_OBJ = {
    "leads": [
        {
            "shape": "A",
            "text": "req.query.name flows unsanitized into a template render call in profile.js.",
            "evidence": f"{_SAMPLE_QUERY} -> code='res.render(\"profile\", {{name: req.query.name}})'",
            "confidence": "HIGH",
        }
    ]
}

_SAMPLE_TOOL_USE_LINE = json.dumps({
    "type": "assistant",
    "message": {
        "content": [
            {
                "type": "tool_use",
                "name": "mcp__orion__run_cypher",
                "input": {"query": _SAMPLE_QUERY, "scan_id": "deadbeef"},
            }
        ]
    },
})

_SAMPLE_RESULT_LINE = json.dumps({
    "type": "result",
    "subtype": "success",
    "is_error": False,
    "result": json.dumps(_SAMPLE_LEADS_OBJ),
    "structured_output": _SAMPLE_LEADS_OBJ,
    "session_id": "fake-session",
})

_SAMPLE_LINES = [_SAMPLE_TOOL_USE_LINE, "not json, should be skipped", "", _SAMPLE_RESULT_LINE]


def test_leads_from_structured_output():
    """Feed a realistic stream-json final payload through the parser, then through the leads
    mapper, and check it lands on contracts.Lead with the right fields."""
    tool_events: list[dict] = []
    events, final = claude_cli.parse_stream_events(_SAMPLE_LINES, on_event=tool_events.append)

    # the unparseable/blank lines were skipped, not raised
    assert len(events) == 2
    assert final is not None
    assert final["is_error"] is False

    # the run_cypher tool_use fired exactly one "tool" notification with the cited query
    assert tool_events == [{"event": "tool", "detail": _SAMPLE_QUERY}]

    leads = discover._to_leads(final["structured_output"], "A")
    assert leads == [
        Lead(
            index=0,
            shape="A",
            text=_SAMPLE_LEADS_OBJ["leads"][0]["text"],
            evidence=_SAMPLE_LEADS_OBJ["leads"][0]["evidence"],
            confidence="HIGH",
        )
    ]

    # the `result` JSON-string twin parses to the same object as the preferred structured_output
    assert json.loads(final["result"]) == final["structured_output"]


def test_leads_from_structured_output_drops_malformed_items():
    """A missing text/evidence field drops that item rather than fabricating one; an out-of-range
    confidence is normalized down to LOW rather than raising."""
    final_json = {
        "leads": [
            {"shape": "B", "text": "no evidence here", "evidence": "", "confidence": "HIGH"},
            {"shape": "B", "text": "", "evidence": "e", "confidence": "HIGH"},
            {"shape": "B", "text": "fine", "evidence": "e", "confidence": "EXTREME"},
            "not-a-dict",
        ]
    }
    leads = discover._to_leads(final_json, "B")
    assert len(leads) == 1
    assert leads[0].text == "fine"
    assert leads[0].confidence == "LOW"


def test_result_missing_never_becomes_a_lead():
    """No `{"type":"result"}` line at all -> claude_cli surfaces a failure sentinel, not leads."""
    lines = [_SAMPLE_TOOL_USE_LINE]  # no result line
    _events, final = claude_cli.parse_stream_events(lines)
    assert final is None
    assert claude_cli._final_to_result(final) == {
        "_error": "no result event found in stream-json output"
    }


def test_is_error_never_becomes_a_lead():
    """is_error=True on the result line is a failure, even if a `result` payload is present."""
    final = {"is_error": True, "subtype": "error_max_turns", "result": json.dumps(_SAMPLE_LEADS_OBJ)}
    out = claude_cli._final_to_result(final)
    assert "_error" in out


def test_timeout_is_not_a_lead(monkeypatch):
    """One shape raises (simulating a subprocess timeout), one shape returns the `_error`
    sentinel directly, the other two succeed normally. discover() must: emit an error event for
    each failing shape, drop them (zero phantom leads), and still return the surviving shapes'
    leads. Nothing here touches a real subprocess or spends a token."""

    def _shape_of(message: str) -> str:
        for s in discover.SHAPES:
            if f"Shape {s} sweep" in message:
                return s
        raise AssertionError(f"could not find a shape marker in message: {message!r}")

    def fake_run_agent(session_id, system, message, *, json_schema=None, add_dir=None,
                        extra_allowed=(), on_event=None, max_turns=None, timeout=None,
                        retries=0, retry_backoff=None):
        shape = _shape_of(message)
        if shape == "B":
            raise TimeoutError("simulated claude -p timeout")
        if shape == "C":
            return {"_error": "simulated non-zero exit"}
        return {
            "leads": [
                {"shape": shape, "text": f"lead for shape {shape}", "evidence": "ev", "confidence": "MEDIUM"}
            ]
        }

    monkeypatch.setattr(claude_cli, "run_agent", fake_run_agent)

    events: list[dict] = []
    leads = discover.discover("fake-scan-id", events.append)

    error_events = [e for e in events if e["event"] == "error"]
    assert {e["shape"] for e in error_events} == {"B", "C"}

    shapes_with_leads = {lead.shape for lead in leads}
    assert shapes_with_leads == {"A", "D"}
    assert all(lead.text.startswith("lead for shape") for lead in leads)


def test_dedup():
    """Two leads that share (shape, text[:80]) collapse to one; a same-text lead under a
    different shape survives as a distinct lead."""
    long_text = "X" * 100  # first 80 chars identical for both "duplicate" leads below
    leads = [
        Lead(index=0, shape="A", text=long_text, evidence="e1", confidence="HIGH"),
        Lead(index=1, shape="A", text=long_text, evidence="e2 (different evidence, same claim)", confidence="LOW"),
        Lead(index=2, shape="B", text=long_text, evidence="e3", confidence="HIGH"),
    ]
    deduped = discover._dedup(leads)

    assert len(deduped) == 2
    assert {(lead.shape, lead.text[:80]) for lead in deduped} == {("A", "X" * 80), ("B", "X" * 80)}
    # first occurrence wins
    assert deduped[0].evidence == "e1"
    # indices are reassigned sequentially over the deduped, aggregated list
    assert [lead.index for lead in deduped] == [0, 1]


# ---------------------------------------------------------------------------------------------
# LIVE test — costs Claude tokens, requires Neo4j up + the loaded NodeGoat scan + the `claude`
# CLI. Written per the brief but deliberately NOT run here; the controller runs it explicitly:
#     ./.venv/bin/python -m pytest tests/test_discover_parse.py -m slow
# ---------------------------------------------------------------------------------------------

@pytest.mark.slow
def test_one_shape_live():
    """Run ONE real discovery shape (A) via claude_cli.run_agent against the loaded NodeGoat scan
    graph, over the real mcp__orion__* MCP tools. Assert at least one grounded lead comes back,
    citing at least one query it actually ran."""
    from orion import strategies
    from orion.graph_build import scan_id_for

    scan_id = scan_id_for("fixtures/NodeGoat")
    tool_events: list[dict] = []

    result = claude_cli.run_agent(
        session_id=str(uuid.uuid4()),
        system=strategies.system_for("A", scan_id),
        message=f'scan_id = "{scan_id}". Begin your Shape A sweep now.',
        json_schema=strategies.LEADS_JSON_SCHEMA,
        on_event=tool_events.append,
        max_turns=15,
        timeout=180,
    )

    assert "_error" not in result, result.get("_error")
    leads = discover._to_leads(result, "A")
    assert len(leads) >= 1
    assert any(e["event"] == "tool" for e in tool_events), "agent must cite at least one query"
