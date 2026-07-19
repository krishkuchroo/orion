"""Resilience + observability of claude_cli.run_agent under transient subprocess failure.

Motivated by a real incident: a full NodeGoat eval hit 5 `claude -p exited 1` crashes on the
heavy (fp-check-subagent-spawning) verifications. The failures were TRANSIENT — the same lead
re-verified cleanly in isolation — but run_agent (a) discarded stdout on a non-zero exit, so the
failures were opaque, and (b) had no retry, so a transient blip silently became an ERROR verdict
and cost a real recall point (A7).

These tests pin the fix: on a non-zero exit run_agent must SALVAGE diagnostics (never go blind),
and it must RETRY a transient failure with backoff on a fresh session id. All token-free — the
`claude` subprocess is faked via monkeypatch; no real call is ever made.
"""
from __future__ import annotations

import json
import subprocess

from orion import claude_cli


def _completed(returncode: int, stdout: str, stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["claude"], returncode=returncode, stdout=stdout, stderr=stderr)


_GOOD_STDOUT = json.dumps({
    "type": "result", "subtype": "success", "is_error": False,
    "structured_output": {"decision": "REJECT", "reason": "not present in source"},
    "result": json.dumps({"decision": "REJECT", "reason": "not present in source"}),
})

_TOOL_LINE = json.dumps({
    "type": "assistant",
    "message": {"content": [
        {"type": "tool_use", "name": "mcp__orion__run_cypher", "input": {"query": "MATCH (n) RETURN n"}}
    ]},
})


def test_nonzero_exit_is_not_blind(monkeypatch):
    """A crash (exit 1, empty stderr) after a tool call: the sentinel must still explain itself
    (carry a stdout tail) AND the tool event must still surface. No silent blindness."""
    calls = {"n": 0}

    def fake_run(cmd, **kw):
        calls["n"] += 1
        return _completed(1, _TOOL_LINE, "")  # process ran a query then died with no result line

    monkeypatch.setattr(claude_cli.subprocess, "run", fake_run)

    events: list[dict] = []
    out = claude_cli.run_agent("sid", "sys", "msg", on_event=events.append)

    assert "_error" in out
    assert "exited 1" in out["_error"]
    assert "stdout_tail" in out["_error"]            # not blind — the partial output is captured
    assert "MATCH (n) RETURN n" in out["_error"]     # the actual salvaged stdout is in the sentinel
    assert any(e.get("event") == "tool" for e in events)  # observability preserved through a failure
    assert calls["n"] == 1                            # retries default to 0 (no behavior change)


def test_retry_recovers_transient_failure(monkeypatch):
    """First attempt crashes (transient), second succeeds. run_agent(retries=2) must recover,
    use a FRESH session id on the retry, back off once, and emit a visible retry event."""
    sids: list[str] = []

    def fake_run(cmd, **kw):
        sids.append(cmd[cmd.index("--session-id") + 1])
        if len(sids) == 1:
            return _completed(1, "", "")            # transient crash, no output at all
        return _completed(0, _GOOD_STDOUT, "")

    slept: list[float] = []
    monkeypatch.setattr(claude_cli.subprocess, "run", fake_run)
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: slept.append(s))

    events: list[dict] = []
    out = claude_cli.run_agent("orig-sid", "sys", "msg", on_event=events.append, retries=2)

    assert out.get("decision") == "REJECT"           # recovered a real structured result
    assert len(sids) == 2                             # exactly one retry needed
    assert sids[0] == "orig-sid" and sids[1] != "orig-sid"  # fresh --session-id on retry
    assert slept == [claude_cli._RETRY_BACKOFF_BASE]  # backed off once (base * 2**0)
    assert any(e.get("event") == "error" and "retry" in e.get("detail", "").lower() for e in events)


def test_retries_exhausted_returns_rich_sentinel(monkeypatch):
    """All attempts fail: after exhausting retries, return the rich diagnostic sentinel (stderr +
    stdout tail both present), never a fabricated success."""
    monkeypatch.setattr(claude_cli.subprocess, "run",
                        lambda cmd, **kw: _completed(1, "boom-stdout", "boom-stderr"))
    monkeypatch.setattr(claude_cli.time, "sleep", lambda s: None)

    out = claude_cli.run_agent("sid", "sys", "msg", retries=2)

    assert "_error" in out and "exited 1" in out["_error"]
    assert "boom-stderr" in out["_error"]            # stderr salvaged
    assert "boom-stdout" in out["_error"]            # stdout tail salvaged
