"""`discover_lm`: the in-process Orion-LM discovery stage, signature-parallel to `discover.discover`.

Reads the scan's :CandidateFlow slices (orion.lm.slice), works them in rank order in batches of `k`, runs
one `prompter.run_session` per batch against an already-loaded model (`model.generate`), and maps the
model's final `leads` onto `contracts.Lead` (shape "LM") with `file/function/line/cwe/path` filled and
`source_uid`/`sink_uid` copied from the flow the lead names by `flow_id` -- so the shared structural
dedup (same key as `discover._dedup`) collapses two leads on one flow.

Rules this module is built around:
  * Never imports `claude_cli` (nor `orion.discover`, which imports it at module top -- `_dedup` is a
    copy of discover.py's with the same key, kept here so the lm package stays Claude-free).
  * A failure is an `error` event + zero leads for THAT batch; other batches still run, the scan never
    crashes and no lead is ever fabricated.
  * A lead whose `flow_id` is missing or not in its batch is attached to the batch's first flow and tagged
    with evidence starting "flow_id unresolved" -- never dropped silently.
  * Every prompter step goes to `on_step(step)` untouched (Task F3 logs them; `orion/` must not import
    `eval/`).

`_load_flows` and `_session` are module-level seams so the token-free test can stand in for Neo4j and
the model.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from orion.contracts import Confidence, Lead, OnEvent, ProgressEvent
from orion.lm import prompter
from orion.lm import slice as lm_slice

SHAPE = "LM"
MIN_CONTEXT_CAP = 512  # floor for the prompter's budget cap; below this no session can do useful work
_CONFIDENCES: tuple[Confidence, ...] = ("LOW", "MEDIUM", "HIGH")
# Step kinds -> progress-event names. run_cypher is a `query`; the rest of a session is `tool`, except
# the kinds that mean the model misbehaved or the context ran out, which are `warn`.
_STEP_EVENTS = {"run_cypher": "query", "read_code": "tool", "final": "tool", "forced_final": "tool",
                "malformed": "warn", "context_overflow": "warn"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(*, event: str, detail: str = "", lead: int | None = None, turn: int | None = None) -> ProgressEvent:
    """Same dict shape as `discover._event` / `cli._event`; phase and shape are fixed for this engine."""
    return {"ts": _now(), "phase": "discover", "shape": SHAPE, "lead": lead,
            "turn": turn, "event": event, "detail": detail}


# ---- seams (monkeypatched by the token-free test) ------------------------------------------------

def _load_flows(db, scan_id: str, max_flows: int) -> list[dict]:
    """Top `max_flows` CandidateFlows of the scan, each as a `flow_slice` dict (raises RuntimeError on a
    query error -- the caller turns that into an `error` event)."""
    flows = lm_slice.candidate_flows(db, scan_id, max_flows=max_flows)
    return [lm_slice.flow_slice(db, scan_id, f) for f in flows]


def _session(generate, db, repo_path: str, scan_id: str, batch: list[dict], **kw) -> tuple[list[dict], list[dict]]:
    return prompter.run_session(generate, db, repo_path, scan_id, batch, **kw)


# ---- lead mapping ------------------------------------------------------------------------------

def _confidence(value) -> Confidence:
    v = str(value or "").strip().upper()
    return v if v in _CONFIDENCES else "LOW"  # type: ignore[return-value]


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_or_none(value):
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _path(flow: dict) -> list[dict]:
    """Flow nodes with a `role`: first=source, last=sink, else step. A one-node path is the sink (a
    CandidateFlow is defined by its sink call; the path always ends there)."""
    nodes = [n for n in (flow.get("nodes") or []) if isinstance(n, dict)]
    last = len(nodes) - 1
    return [dict(n, role="sink" if i == last else "source" if i == 0 else "step") for i, n in enumerate(nodes)]


def _node_ref(n: dict) -> str:
    return f"{n.get('file')}:{n.get('function')}:{n.get('line')}"


def _to_lead(raw: dict, flow: dict, index: int, *, unresolved: bool) -> Lead:
    file = _str_or_none(raw.get("file"))
    function = _str_or_none(raw.get("function"))
    line = _int_or_none(raw.get("line"))
    cwe = _str_or_none(raw.get("cwe"))
    confidence = _confidence(raw.get("confidence"))
    flow_id = flow.get("flow_id")
    where = f"{file or '?'}:{line if line is not None else '?'}" + (f" in {function}" if function else "")
    text = f"{cwe or 'possible vulnerability'} at {where} (flow {flow_id}, {flow.get('sink_category') or 'unknown'} sink)"
    path = _path(flow)
    summary = (f"model lead: cwe={cwe} file={file} function={function} line={line} confidence={confidence}; "
               f"flow {flow_id}: sink_category={flow.get('sink_category')} source_uid={flow.get('source_uid')} "
               f"sink_uid={flow.get('sink_uid')}; path: " + (" -> ".join(_node_ref(n) for n in path) or "(no nodes)"))
    if unresolved:
        summary = (f"flow_id unresolved (model gave {raw.get('flow_id')!r}; attached to the batch's first flow "
                   f"{flow_id}). " + summary)
    return Lead(index=index, shape=SHAPE, text=text, evidence=summary, confidence=confidence,
                source_uid=flow.get("source_uid") or None, sink_uid=flow.get("sink_uid") or None,
                file=file, function=function, line=line, cwe=cwe, path=path)


def _map_batch(raw_leads: list, batch: list[dict], start_index: int) -> list[Lead]:
    """Model dicts -> Leads for one batch. Resolved leads come first so a tagged, unresolved lead never
    shadows a real one for the same flow when `_dedup` keeps the first occurrence."""
    by_id = {f.get("flow_id"): f for f in batch}
    resolved, unresolved = [], []
    for raw in raw_leads:
        if not isinstance(raw, dict):
            continue  # not a lead; nothing to attach, nothing to fabricate
        flow = by_id.get(raw.get("flow_id"))
        if flow is None:
            unresolved.append((raw, batch[0]))
        else:
            resolved.append((raw, flow))
    leads = []
    for raw, flow in resolved:
        leads.append(_to_lead(raw, flow, start_index + len(leads), unresolved=False))
    for raw, flow in unresolved:
        leads.append(_to_lead(raw, flow, start_index + len(leads), unresolved=True))
    return leads


def _dedup(leads: list[Lead]) -> list[Lead]:
    """Copy of `discover._dedup` (same keys, same first-wins rule): structural on (source_uid, sink_uid),
    lexical (shape, text[:80]) fallback for leads with no graph anchor; reindexes sequentially."""
    return [replace(lead, index=i) for i, lead in enumerate(_dedup_keep(leads))]


def _dedup_keep(leads: list[Lead]) -> list[Lead]:
    """The leads `_dedup` keeps, as the ORIGINAL objects (so the caller can still map them to their batch)."""
    seen_struct: set[tuple[str, str]] = set()
    seen_lex: set[tuple[str, str]] = set()
    kept: list[Lead] = []
    for lead in leads:
        if lead.source_uid and lead.sink_uid:
            key = (lead.source_uid, lead.sink_uid)
            if key in seen_struct:
                continue
            seen_struct.add(key)
        else:
            key = (lead.shape, lead.text[:80])
            if key in seen_lex:
                continue
            seen_lex.add(key)
        kept.append(lead)
    return kept


def _step_hook(on_event: OnEvent, on_step, turn: int):
    """Per-batch callback handed to the session: one progress event per step, then the caller's `on_step`
    (a failing logger is a `warn`, never a crash). Called by the prompter the moment a step is recorded."""
    def hook(step) -> None:
        kind = step.get("kind") if isinstance(step, dict) else None
        detail = f"batch {turn} step {step.get('step_no')}: {kind}" if isinstance(step, dict) else str(step)
        if isinstance(step, dict) and step.get("query"):
            detail += f" {step['query']}"
        if isinstance(step, dict) and step.get("error"):
            detail += f" [error: {step['error']}]"
        on_event(_event(event=_STEP_EVENTS.get(kind, "tool"), turn=turn, detail=detail))
        if on_step is not None:
            try:
                on_step(step)
            except Exception as exc:
                on_event(_event(event="warn", turn=turn, detail=f"on_step failed: {exc.__class__.__name__}: {exc}"))
    return hook


# ---- the stage ----------------------------------------------------------------------------------

def discover_lm(scan_id: str, repo_path: str, on_event: OnEvent, *, profile=None, model=None, k: int = 5,
                max_flows: int = 50, on_step=None, stop=None, flows=None, db=None) -> list[Lead]:
    """Run the Orion-LM discovery stage and return deduped `list[Lead]` (shape "LM").

    `model` is an already-loaded wrapper (`orion.lm.model.load(...)`): only its `.generate(messages)` is
    used, and the prompter's budget cap is set `prompter.CONTEXT_MARGIN` below its `context_cap` (8000
    when the object has none). `flows` bypasses the graph read (slice-shaped dicts, e.g. an OWASP case
    file); either way only the top `max_flows` are worked, in order, in batches of `k`, one session each.
    `stop` (threading.Event) is checked before each batch and forwarded to the session. `db` is an open
    GraphDB; None constructs one (and closes it at the end). `profile` is accepted for signature parity
    with `discover.discover` and is not used: the LM prompt is framework-agnostic by construction.

    Any exception in loading flows or in one batch's session becomes an `error` event and zero leads
    for that batch; the remaining batches still run and the function always returns.
    """
    if model is None:
        raise ValueError("discover_lm needs a loaded model (orion.lm.model.load(path)); got None")
    # A wrapper exposes `.generate`; a bare callable is accepted as-is. Anything else fails inside the
    # session, where it becomes an `error` event per batch rather than a crash here.
    generate = model.generate if hasattr(model, "generate") else model
    raw_cap = int(getattr(model, "context_cap", 8000)) - prompter.CONTEXT_MARGIN
    context_cap = max(raw_cap, MIN_CONTEXT_CAP)
    k = max(1, int(k))
    max_flows = max(0, int(max_flows))

    on_event(_event(event="start", detail=f"orion-lm discovery starting (k={k}, max_flows={max_flows})"))
    if context_cap != raw_cap:
        on_event(_event(event="warn", detail=f"prompter context_cap {raw_cap} floored to {context_cap}; "
                                             f"the model's context_cap is too small for a useful session"))

    own_db = db is None
    if own_db:
        from orion.graphdb import GraphDB  # local import: the driver connects lazily, on first query
        db = GraphDB()
    leads: list[Lead] = []
    turn_of: dict[int, int] = {}  # id(lead) -> batch number, for the post-dedup `lead` events
    stopped = False
    try:
        if flows is None:
            try:
                flows = _load_flows(db, scan_id, max_flows)
            except Exception as exc:  # a graph/query failure is an error event, not a crash
                on_event(_event(event="error", detail=f"loading CandidateFlows failed: {exc.__class__.__name__}: {exc}"))
                flows = []
        flows = list(flows)[:max_flows]

        for turn, start in enumerate(range(0, len(flows), k), start=1):
            if stop is not None and stop.is_set():
                on_event(_event(event="warn", turn=turn, detail="stop requested; remaining batches skipped"))
                stopped = True
                break
            batch = flows[start:start + k]
            ids = ", ".join(str(f.get("flow_id")) for f in batch)
            step_hook = _step_hook(on_event, on_step, turn)
            try:
                # Steps reach `step_hook` as they happen, so a batch that fails mid-session still reports
                # the steps it took; the returned `steps` are the same records and are NOT replayed.
                raw_leads, _steps = _session(generate, db, repo_path, scan_id, batch,
                                             context_cap=context_cap, stop=stop, on_step=step_hook)
            except Exception as exc:
                on_event(_event(event="error", turn=turn,
                                detail=f"batch {turn} ({ids}) failed: {exc.__class__.__name__}: {exc}"))
                continue
            batch_leads = _map_batch(list(raw_leads or []), batch, len(leads))
            for lead in batch_leads:
                turn_of[id(lead)] = turn
            leads.extend(batch_leads)
    finally:
        if own_db:
            db.close()

    kept = _dedup_keep(leads)
    deduped = [replace(lead, index=i) for i, lead in enumerate(kept)]
    for original, lead in zip(kept, deduped):  # indices match the returned list
        on_event(_event(event="lead", lead=lead.index, turn=turn_of.get(id(original)), detail=lead.text))
    tail = "; stopped early" if stopped else ""
    on_event(_event(event="done", detail=f"{len(deduped)} candidate leads from {len(flows)} flows{tail}"))
    return deduped
