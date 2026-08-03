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

verify_all() verifies leads with BOUNDED CONCURRENCY (config.VERIFY_CONCURRENCY, default 4). Each
lead is still its own fully isolated fresh session -- the trust invariant is per-lead and unaffected
by running several at once -- but a semaphore caps how many verify in parallel so a large lead set
does not spawn an unbounded number of claude -p processes or trip API rate limits. Verification is
the run's wall-clock bottleneck (each lead is a whole session), so this is where parallelism pays
off. Results are returned in lead order regardless of completion order; set concurrency=1 for the
old strictly-sequential behavior.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid

from . import config
from .contracts import Lead, OnEvent, Verdict
from .exploit_corpus import EXPLOIT_SEARCH_GUIDANCE

_DECISIONS = {"CONFIRM", "REJECT", "INCONCLUSIVE", "ERROR"}

# CpgCall / CandidateFlow endpoint uids are sha1 hex. The lead's source/sink uids come from an
# untrusted agent reply and are INLINED into the evidence-subgraph Cypher (run_cypher binds only
# scan_id), so we hard-gate them to this shape -- anything else disables the subgraph rather than
# building a query from arbitrary text. run_cypher is read-only anyway, but this is belt-and-braces.
_UID_RE = re.compile(r"^[0-9a-f]{40}$")

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
  (:CpgMethod {scan_id, full_name, name, is_external, file_path, line, reachable_from_entry, hop_distance, centrality})
  (:CpgCall   {scan_id, uid, name, code, method_full_name, file_path, line, column, reachable_from_entry, hop_distance, centrality})
  (:CpgModule {scan_id, import_name, language})
  (:CpgParameter {scan_id, uid, name, index})
  (:CpgReturn {scan_id, uid})
  (:EntryPoint {scan_id, uid, method_full_name, exposure, kind})
  (:Dependency {scan_id, name, version})
  (:CandidateFlow {scan_id, uid, source_uid, sink_uid, sink_category, path_uids, rank})
     -- precomputed source->sink taint path; source_uid/sink_uid are CpgCall uids, path_uids a JSON
        array of the CpgCall uids on the flow
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
- EXPLOITABILITY (reachability): if the lead's sink has `reachable_from_entry = false`, weigh that as
  evidence AGAINST exploitability and lean INCONCLUSIVE or REJECT -- but do NOT auto-REJECT on it
  alone. The graph under-links arrow-function calls, so a real reachable sink can be mislabeled
  unreachable; confirm the reach (or its absence) against the real source before you downgrade.

When you are done, output the final verdict as the required structured JSON with fields
`decision` (CONFIRM | REJECT | INCONCLUSIVE), `reason` (why, citing your own evidence), and
`evidence` (the specific file/line or query result you found)."""


def _lead_message(scan_id: str, lead: Lead, evidence_subgraph: str = "") -> str:
    """The ENTIRE content the verifier sees about this lead -- no discovery transcript, just the
    lead's own fields plus (optionally) an evidence subgraph WE derived independently from the code
    graph. Both are graph facts / the lead's own claim, never the analyst's reasoning, so the trust
    invariant holds: the verifier still re-derives the verdict, it just doesn't have to rediscover
    the flow's shape across N files first."""
    msg = (
        f"scan_id: {scan_id}\n\n"
        "Candidate lead to verify (produced by a separate analyst you cannot see and must not "
        "trust -- re-derive it yourself):\n"
        f"  shape: {lead.shape}\n"
        f"  claim: {lead.text}\n"
        f"  analyst's cited evidence (unverified): {lead.evidence}\n"
        f"  analyst's confidence: {lead.confidence}\n"
    )
    if evidence_subgraph:
        msg += "\n" + evidence_subgraph + "\n"
    return msg + "\nVerify this one lead now."


def _format_evidence_subgraph(subgraph: dict) -> str:
    """Render a fetched source->sink subgraph as a plain-text block for the verifier message. Pure
    (no I/O) so it is unit-testable without a graph. Returns "" for an empty/missing path."""
    path = subgraph.get("path") or []
    if not path:
        return ""
    lines = [
        "PRECOMPUTED EVIDENCE SUBGRAPH (derived independently from the code graph, NOT from the "
        "analyst -- verify it against real source yourself; the graph can under-link "
        "arrow-function calls, so this is a lead, not proof):",
    ]
    category = subgraph.get("sink_category")
    if category:
        lines.append(f"  sink category: {category}")
    lines.append("  tainted source -> sink path (CpgCall.uid, file:line, code):")
    last = len(path) - 1
    for i, node in enumerate(path):
        marker = "source" if i == 0 else ("sink" if i == last else f"hop {i}")
        loc = f"{node.get('file_path', '?')}:{node.get('line', '?')}"
        code = (node.get("code") or "").strip().replace("\n", " ")
        lines.append(f"    [{marker}] {node.get('uid', '?')[:12]}  {loc}  {code}")
    return "\n".join(lines)


def _fetch_evidence_subgraph(scan_id: str, source_uid: str, sink_uid: str) -> dict | None:
    """Default subgraph fetch: read the :CandidateFlow's path_uids, then the CpgCall detail for each
    node on the flow, via the read-only GraphDB. Endpoint uids are hard-gated to sha1 hex before any
    inlining. Returns {"sink_category", "path": [ordered node dicts]} or None (no flow / bad uids).
    Advisory only -- a failure here must never break verification (the caller swallows exceptions)."""
    if not (_UID_RE.match(source_uid or "") and _UID_RE.match(sink_uid or "")):
        return None
    from .graphdb import GraphDB
    db = GraphDB()
    try:
        cf = db.run_cypher(
            scan_id,
            f"MATCH (cf:CandidateFlow {{scan_id:$scan_id, source_uid:'{source_uid}', "
            f"sink_uid:'{sink_uid}'}}) RETURN cf.path_uids AS path_uids, "
            f"cf.sink_category AS sink_category LIMIT 1")
        rows = cf.get("rows") if isinstance(cf, dict) else None
        if not rows:
            return None
        try:
            path_uids = json.loads(rows[0].get("path_uids") or "[]")
        except (TypeError, ValueError):
            return None
        if not path_uids or not all(isinstance(u, str) and _UID_RE.match(u) for u in path_uids):
            return None
        uid_list = ", ".join(f"'{u}'" for u in path_uids)
        nodes = db.run_cypher(
            scan_id,
            f"MATCH (c:CpgCall {{scan_id:$scan_id}}) WHERE c.uid IN [{uid_list}] "
            f"RETURN c.uid AS uid, c.code AS code, c.file_path AS file_path, c.line AS line",
            limit=len(path_uids))
        detail = {r["uid"]: r for r in (nodes.get("rows") or [])} if isinstance(nodes, dict) else {}
        ordered = [detail.get(u, {"uid": u}) for u in path_uids]
        return {"sink_category": rows[0].get("sink_category"), "path": ordered}
    finally:
        db.close()


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


def verify_lead(scan_id: str, lead: Lead, repo_path: str, on_event: OnEvent, run_agent,
                fetch_subgraph=None) -> Verdict:
    """Verifies ONE lead in its own fresh claude -p session. `run_agent` is injected (rather than
    imported at module scope) so this stays testable without claude_cli, and so verify_all is the
    single place that does the lazy import.

    `fetch_subgraph(scan_id, source_uid, sink_uid) -> dict | None` (Item 5) is also injectable: when
    the lead is anchored on a :CandidateFlow, its result is rendered into the message as a
    precomputed source->sink evidence subgraph so the verifier need not rediscover the flow across
    files. Advisory: any failure fetching/formatting it is swallowed -- verification proceeds without
    the block, never erroring over it."""
    session_id = str(uuid.uuid4())
    system = (
        VERIFY_SYSTEM.format(schema=_SCHEMA_BLOCK, scan_id=scan_id)
        + "\n\n" + EXPLOIT_SEARCH_GUIDANCE
    )
    evidence_subgraph = ""
    if lead.source_uid and lead.sink_uid and fetch_subgraph is not None:
        try:
            sub = fetch_subgraph(scan_id, lead.source_uid, lead.sink_uid)
            if sub:
                evidence_subgraph = _format_evidence_subgraph(sub)
        except Exception:  # noqa: BLE001 -- the subgraph is advisory; never fail verify over it
            evidence_subgraph = ""
    message = _lead_message(scan_id, lead, evidence_subgraph)

    on_event({
        "phase": "verify", "shape": lead.shape, "lead": lead.index, "turn": None,
        "event": "start", "detail": lead.text[:200],
    })

    result = run_agent(
        session_id, system, message,
        json_schema=VERDICT_SCHEMA,
        add_dir=repo_path,
        # exploit_search is verifier-only (not in claude_cli._ALLOWED_BASE) -- discovery never gets
        # it; the verifier uses it advisorily for severity/version calibration per EXPLOIT_SEARCH_GUIDANCE.
        extra_allowed=("Read", "Grep", "Glob", "Task", "Skill", "mcp__orion__exploit_search"),
        on_event=on_event,
        max_turns=config.VERIFY_MAX_TURNS,
        timeout=config.VERIFY_TIMEOUT,
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


async def _verify_all_async(scan_id: str, leads: list[Lead], repo_path: str, on_event: OnEvent,
                            run_agent, concurrency: int, fetch_subgraph) -> list[Verdict]:
    """Fan the per-lead verifiers out under a semaphore. Each verify_lead is a blocking subprocess
    call, so it runs in a worker thread (asyncio.to_thread); the semaphore bounds how many are in
    flight. asyncio.gather preserves input (lead) order in the returned list."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _one(lead: Lead) -> Verdict:
        async with sem:
            return await asyncio.to_thread(
                verify_lead, scan_id, lead, repo_path, on_event, run_agent, fetch_subgraph)

    return list(await asyncio.gather(*(_one(lead) for lead in leads)))


def verify_all(scan_id: str, leads: list[Lead], repo_path: str, on_event: OnEvent,
               *, run_agent=None, concurrency: int | None = None, fetch_subgraph=None) -> list[Verdict]:
    """Verifies each lead in ITS OWN fresh claude -p session, up to `concurrency` at a time
    (defaults to config.VERIFY_CONCURRENCY). Every verifier is independent and isolated, so running
    several concurrently does not weaken the trust invariant; the cap just avoids an unbounded
    process/rate-limit spike. Verdicts are returned in lead order regardless of finish order.

    `run_agent` is injectable (defaults to the lazy claude_cli import) so concurrency is testable
    without a real subprocess; `concurrency=1` restores strictly-sequential verification.
    `fetch_subgraph` is injectable too (defaults to the GraphDB-backed `_fetch_evidence_subgraph`);
    it only runs for leads that carry :CandidateFlow endpoints, so an endpoint-less test set never
    touches a graph."""
    if not leads:
        return []
    if run_agent is None:
        from .claude_cli import run_agent as _lazy_run_agent  # lazy: keeps import off the hot path
        run_agent = _lazy_run_agent
    if fetch_subgraph is None:
        fetch_subgraph = _fetch_evidence_subgraph
    if concurrency is None:
        concurrency = config.VERIFY_CONCURRENCY
    return asyncio.run(
        _verify_all_async(scan_id, leads, repo_path, on_event, run_agent, concurrency, fetch_subgraph))
