"""Independent verification: for each candidate lead, a FRESH `claude -p` session (its own
`--session-id`, its own transcript) re-derives the claim using the **fp-check** skill against the
REAL SOURCE and the code graph. It never sees the discovery transcript -- only the lead's own
text/evidence/scan_id. That separation is the TRUST INVARIANT: verification must not be the same
agent grading its own homework (see CLAUDE.md / orion-shared-context.md).

Design (locked in task-d-brief.md):
  - one `claude_cli.run_agent` call per lead, with a fresh uuid4 session_id
  - `system` = VERIFY_SYSTEM: general verifier instructions + the schema-of-record (not
    lead-specific, so it is identical prep across leads)
  - `message` = ONLY this lead's shape/text/evidence/confidence + scan_id -- nothing from
    discovery's session or reasoning
  - `json_schema` = VERDICT_SCHEMA, forcing the reply into {decision, reason, evidence}
  - `add_dir` = repo_path (sandboxes fp-check's source reading to the target repo)
  - `extra_allowed` = ("Read", "Grep", "Glob", "Task", "Skill") -- fp-check reads source and
    spawns its own subagents; still NO Write/Edit/Bash
  - a subprocess failure sentinel, or a reply missing/mangling `decision`, maps to Verdict
    decision="ERROR" -- NEVER a silent CONFIRM. A verifier that genuinely can't decide says
    INCONCLUSIVE itself; ERROR is reserved for "the call itself broke."

verify_all() runs leads SEQUENTIALLY (simple, robust, easy to reason about under the trust
invariant) -- do not add concurrency here, it isn't needed at this scale.
"""
from __future__ import annotations

import uuid

from . import config
from .contracts import Lead, OnEvent, Verdict

_DECISIONS = {"CONFIRM", "REJECT", "INCONCLUSIVE", "ERROR"}

# Forces claude -p's structured final answer into exactly these three fields.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["CONFIRM", "REJECT", "INCONCLUSIVE", "ERROR"]},
        "reason": {"type": "string"},
        "evidence": {"type": "string"},
    },
    "required": ["decision", "reason"],
}

# Schema-of-record (must match orion/graph_build.py's persisted labels/props exactly -- see
# orion-shared-context.md "Schema-of-record"). Kept self-contained here rather than imported from
# orion/strategies.py, which Task C owns and is rewriting in parallel.
_SCHEMA_BLOCK = """Schema (all nodes carry `scan_id`):
  (:CpgFile   {scan_id, uid, file_path})
  (:CpgMethod {scan_id, full_name, name, is_external, file_path, line})
  (:CpgCall   {scan_id, uid, name, code, method_full_name, file_path, line, column})
  (:CpgModule {scan_id, import_name, language})
  (:CpgParameter {scan_id, uid, name, index})
  (:CpgReturn {scan_id, uid})
  (:EntryPoint {scan_id, uid, method_full_name, exposure, kind})
  (:Dependency {scan_id, name, version})
Edges (rel props carry scan_id):
  (:CpgMethod)-[:CONTAINS_CALL]->(:CpgCall)
  (:CpgCall)-[:RESOLVES_TO]->(:CpgMethod)
  (:CpgMethod)-[:DEFINED_IN]->(:CpgFile)
  (:CpgCall)-[:FLOWS_TO {arg_index}]->(:CpgCall)
  (:EntryPoint)-[:ENTERS_AT]->(:CpgMethod)
File attribution: use CpgCall.file_path (stamped on every call) -- CONTAINS_CALL alone is NOT
reliable (calls nested in arrow-functions assigned to object properties get no edge). Because the
graph lies by omission this way, you MUST also read the real source under the added directory --
do not trust graph attribution alone."""

VERIFY_SYSTEM = """You are an INDEPENDENT security verifier, running in your own fresh session.
A candidate lead was produced by a SEPARATE analyst agent whose session and reasoning you cannot
see and MUST NOT trust -- you are not grading your own homework, you are re-deriving the claim
from scratch.

{schema}

Use the **fp-check skill** to verify the candidate lead you are given against the REAL SOURCE
(available under the added directory for this repo) and, where useful, the code graph via the
`mcp__orion__run_cypher` tool (always filter by scan_id = "{scan_id}"). Confirm or reject the lead
ONLY on evidence you gather yourself in this session -- never on the analyst's say-so.

Rules:
- If the supporting code/structure the lead describes is not actually present in the source or the
  graph, REJECT it.
- If you cannot gather enough evidence to decide either way, say INCONCLUSIVE -- do not guess.
- CONFIRM only when you have concrete, cited evidence (a file+line, a queried graph fact, or both).

When you are done, output the final verdict as the required structured JSON with fields
`decision` (CONFIRM | REJECT | INCONCLUSIVE), `reason` (why, citing your own evidence), and
`evidence` (the specific file/line or query result you found)."""


def _lead_message(scan_id: str, lead: Lead) -> str:
    """The ENTIRE content the verifier sees about this lead -- no discovery transcript, just the
    lead's own fields. This is the trust invariant, made concrete."""
    return (
        f"scan_id: {scan_id}\n\n"
        "Candidate lead to verify (produced by a separate analyst you cannot see and must not "
        "trust -- re-derive it yourself):\n"
        f"  shape: {lead.shape}\n"
        f"  claim: {lead.text}\n"
        f"  analyst's cited evidence (unverified): {lead.evidence}\n"
        f"  analyst's confidence: {lead.confidence}\n\n"
        "Verify this one lead now."
    )


def _verdict_from_result(lead: Lead, result: dict) -> Verdict:
    """Pure mapping from a claude_cli.run_agent structured result to a Verdict. No I/O and no
    dependency on claude_cli itself -- safe to unit test without a subprocess or that module even
    existing yet.

    - a failure sentinel ({"_error": ...}) -> ERROR (never a silent CONFIRM)
    - a missing/out-of-enum `decision` -> ERROR (the model didn't answer the contract)
    - otherwise -> the decision/reason/evidence as returned
    """
    if not isinstance(result, dict) or "_error" in result:
        why = result.get("_error", "unknown failure") if isinstance(result, dict) else "malformed result (not a dict)"
        return Verdict(lead=lead, decision="ERROR", reason=f"verifier call failed: {why}", evidence="")

    decision = result.get("decision")
    if decision not in _DECISIONS:
        return Verdict(
            lead=lead,
            decision="ERROR",
            reason=f"verifier returned an unparseable/missing decision: {result!r}",
            evidence="",
        )

    return Verdict(
        lead=lead,
        decision=decision,
        reason=result.get("reason") or "",
        evidence=result.get("evidence") or "",
    )


def verify_lead(scan_id: str, lead: Lead, repo_path: str, on_event: OnEvent, run_agent) -> Verdict:
    """Verifies ONE lead in its own fresh claude -p session. `run_agent` is injected (rather than
    imported at module scope) so this stays testable without claude_cli, and so verify_all is the
    single place that does the lazy import."""
    session_id = str(uuid.uuid4())
    system = VERIFY_SYSTEM.format(schema=_SCHEMA_BLOCK, scan_id=scan_id)
    message = _lead_message(scan_id, lead)

    on_event({
        "phase": "verify", "shape": lead.shape, "lead": lead.index, "turn": None,
        "event": "start", "detail": lead.text[:200],
    })

    result = run_agent(
        session_id, system, message,
        json_schema=VERDICT_SCHEMA,
        add_dir=repo_path,
        extra_allowed=("Read", "Grep", "Glob", "Task", "Skill"),
        on_event=on_event,
        max_turns=config.VERIFY_MAX_TURNS,
        timeout=config.CALL_TIMEOUT,
        # fp-check spawns subagents and intermittently hits transient API overload under a heavy
        # back-to-back batch; retry so a blip doesn't silently degrade to an ERROR verdict.
        retries=2,
    )

    verdict = _verdict_from_result(lead, result)
    if verdict.decision == "ERROR":
        on_event({
            "phase": "verify", "shape": lead.shape, "lead": lead.index, "turn": None,
            "event": "error", "detail": verdict.reason,
        })
    on_event({
        "phase": "verify", "shape": lead.shape, "lead": lead.index, "turn": None,
        "event": "verdict", "detail": verdict.decision,
    })
    return verdict


def verify_all(scan_id: str, leads: list[Lead], repo_path: str, on_event: OnEvent) -> list[Verdict]:
    """Verifies each lead in ITS OWN fresh claude -p session, sequentially. Deliberately not
    concurrent: verification is the trust-bearing step, and sequential execution is simple,
    robust, and easy to reason about at this scale (do not overengineer)."""
    from .claude_cli import run_agent  # lazy: Task C owns claude_cli.py, built in parallel

    return [verify_lead(scan_id, lead, repo_path, on_event, run_agent) for lead in leads]
