"""Model-agnostic prompter loop for Orion-LM: one builder-check session over a batch of flow slices.

`generate(messages) -> GenResult` is the only model seam (Task B4 supplies MLX / llama-cpp; tests a
scripted function). The loop never imports claude_cli, never touches the network, and never estimates
a token count — every number in a step record is copied from the GenResult the model wrapper measured.

History is append-only: a turn, once appended, is never rewritten (a rewrite would break the model's
prompt cache, spec §5.1). Every turn the model sees comes from `orion.lm.format`.

Two caps, deliberately different: this loop's `context_cap` is a BUDGET (force the final once the last
call's prompt+completion reaches it); the model wrapper's `context_cap` (`orion.lm.model`) is the HARD
limit, above which `generate` raises `ContextOverflow` instead of truncating. The forced-final prompt is
always longer than the call that tripped the budget, and a 25-row RESULT can push any call over, so the
wiring (Task F3) must set this cap at least one turn + reply below the wrapper's — `CONTEXT_MARGIN`
(1024 tokens) is the suggested gap. If the wrapper still overflows, the session ends with a
`context_overflow` step and zero leads; it never crashes the engine and never fabricates a final.
"""
from __future__ import annotations

import time

from orion.lm import format as fmt
from orion.lm import tools
from orion.lm.model import ContextOverflow

# Suggested distance between the prompter's budget cap and the wrapper's hard cap (see module docstring).
CONTEXT_MARGIN = 1024


def _step(step_no: int, kind: str, res, wall: float, *, query=None, row_count=None, error=None) -> dict:
    """One steps-table row. `res` is None only for `context_overflow` (nothing was generated)."""
    return {
        "step_no": step_no,
        "kind": kind,
        "query": query,
        "row_count": row_count,
        "prompt_tokens": None if res is None else res.prompt_tokens,
        "completion_tokens": None if res is None else res.completion_tokens,
        "cached_tokens": None if res is None else res.cached_tokens,
        "wall_seconds": wall,
        "error": error,
    }


def _leads_of(action: dict) -> tuple[list[dict], str | None]:
    """The `leads` of a parsed final action: a list of dicts, else [] with a reason."""
    leads = action.get("leads")
    if not isinstance(leads, list):
        return [], "final.leads must be a list"
    if not all(isinstance(ld, dict) for ld in leads):
        return [], "final.leads must be a list of objects"
    return leads, None


def run_session(generate, db, repo_path: str, scan_id: str, flows: list[dict], *,
                max_actions: int = 40, context_cap: int = 8000, row_limit: int = 25,
                stop=None, on_step=None) -> tuple[list[dict], list[dict]]:
    """Run one session; return `(leads, steps)`.

    Forced final when the last call's prompt+completion tokens reach `context_cap`, when `max_actions`
    model calls have been made, or when `stop` (a threading.Event) is set: one more call after a
    `forced_final_message`; if that is not a valid `final`, leads = [].

    `context_cap` here must sit at least `CONTEXT_MARGIN` below the model wrapper's hard cap (module
    docstring). A `ContextOverflow` from `generate` on ANY call ends the session: a `context_overflow` step
    (token fields None, `error` = the wrapper's message) and `leads = []`.

    `on_step(step)`, when given, receives each step record the moment it is appended, so a caller still
    sees the steps already taken if a later `generate` or tool call raises (the returned `steps` only
    exist on a normal return). A failing callback is swallowed; it never ends the session.
    """
    messages: list[dict] = [fmt.system_message(), fmt.task_message(flows)]
    steps: list[dict] = []

    def record(step: dict) -> None:
        steps.append(step)
        if on_step is not None:
            try:
                on_step(step)
            except Exception:  # a broken logger must not cost the session its leads
                pass
    actions = 0
    last_total = 0

    while True:
        forced = (actions >= max_actions or last_total >= context_cap
                  or (stop is not None and stop.is_set()))
        if forced:
            messages.append(fmt.forced_final_message())
            t0 = time.perf_counter()
            try:
                res = generate(messages)
            except ContextOverflow as exc:
                record(_step(len(steps) + 1, "context_overflow", None, time.perf_counter() - t0,
                           error=str(exc)))
                return [], steps
            wall = time.perf_counter() - t0
            messages.append({"role": "assistant", "content": res.text})
            action = fmt.parse_action(res.text)
            if action is None or action["action"] != "final":
                leads, err = [], "forced final did not return a valid final action"
            else:
                leads, err = _leads_of(action)
            record(_step(len(steps) + 1, "forced_final", res, wall, error=err))
            return leads, steps

        t0 = time.perf_counter()
        try:
            res = generate(messages)
        except ContextOverflow as exc:
            record(_step(len(steps) + 1, "context_overflow", None, time.perf_counter() - t0,
                           error=str(exc)))
            return [], steps
        actions += 1
        last_total = int(res.prompt_tokens) + int(res.completion_tokens)
        messages.append({"role": "assistant", "content": res.text})
        action = fmt.parse_action(res.text)
        step_no = len(steps) + 1

        if action is None:
            reason = "your reply was not exactly one JSON object with an action of run_cypher, read_code or final."
            messages.append(fmt.error_message(reason))
            record(_step(step_no, "malformed", res, time.perf_counter() - t0, error=reason))
            continue

        kind = action["action"]

        if kind == "final":
            leads, err = _leads_of(action)
            record(_step(step_no, "final", res, time.perf_counter() - t0, error=err))
            return leads, steps

        if kind == "run_cypher":
            query = action.get("query")
            if not isinstance(query, str) or not query.strip():
                reason = "run_cypher needs a non-empty string field \"query\"."
                messages.append(fmt.error_message(reason))
                record(_step(step_no, "malformed", res, time.perf_counter() - t0, error=reason))
                continue
            result = tools.run_cypher(db, scan_id, query, limit=row_limit)
            messages.append(fmt.tool_result_message(action, result))
            record(_step(step_no, "run_cypher", res, time.perf_counter() - t0, query=query,
                               row_count=None if "error" in result else result.get("row_count"),
                               error=result.get("error")))
            continue

        # read_code — tools.read_code validates file/start/end itself and answers with an error dict.
        result = tools.read_code(repo_path, action.get("file"), action.get("start"), action.get("end"))
        messages.append(fmt.tool_result_message(action, result))
        record(_step(step_no, "read_code", res, time.perf_counter() - t0, error=result.get("error")))
