"""Token-free tests for orion.lm.prompter: a scripted `generate` stands in for the model, a StubDB for
Neo4j. No MLX, no network, no Claude."""
from __future__ import annotations

import json
import threading

from orion.lm import format as fmt
from orion.lm import prompter
from orion.lm.model import GenResult


class StubDB:
    def run_cypher(self, scan_id, query, limit=50):
        return {"row_count": 1, "rows": [{"c.code": "exec(userInput)"}]} if not query.startswith("EXPLAIN") \
               else {"row_count": 0, "rows": []}


def gen(text, p=100, c=10): return GenResult(text=text, prompt_tokens=p, completion_tokens=c, cached_tokens=0)


def scripted(actions):
    it = iter(actions)
    return lambda messages: gen(next(it))


Q = "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code"
FLOW = {"flow_id": "F0", "rank": 0, "sink_category": "code_exec", "source_uid": "s", "sink_uid": "k",
        "nodes": [{"file": "a.js", "function": "f", "line": 10, "code": "exec(x)"}]}


def test_run_cypher_then_final_yields_lead_and_steps(tmp_path):
    acts = [json.dumps({"action": "run_cypher", "query": Q}),
            json.dumps({"action": "final", "leads": [{"flow_id": "F0", "file": "a.js", "function": "f",
                                                       "line": 10, "cwe": "CWE-94", "confidence": "HIGH"}]})]
    leads, steps = prompter.run_session(scripted(acts), StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert leads[0]["cwe"] == "CWE-94" and leads[0]["flow_id"] == "F0"
    assert steps[0]["kind"] == "run_cypher" and steps[0]["prompt_tokens"] == 100 and steps[0]["row_count"] == 1


def test_malformed_action_does_not_crash(tmp_path):
    acts = ["this is not json", json.dumps({"action": "final", "leads": []})]
    leads, steps = prompter.run_session(scripted(acts), StubDB(), str(tmp_path), "s", flows=[])
    assert leads == [] and steps[0]["error"]


def test_forced_final_at_action_cap(tmp_path):
    loop = json.dumps({"action": "run_cypher", "query": Q})
    leads, steps = prompter.run_session(lambda m: gen(loop), StubDB(), str(tmp_path), "s", flows=[], max_actions=3)
    assert leads == [] and len(steps) == 4          # 3 actions + the forced final call


def test_forced_final_at_context_cap(tmp_path):
    loop = json.dumps({"action": "run_cypher", "query": Q})
    leads, steps = prompter.run_session(lambda m: gen(loop, p=7990, c=20), StubDB(), str(tmp_path), "s",
                                        flows=[], context_cap=8000)
    assert len(steps) == 2                           # one real call tripped the cap, then the forced final


def test_history_is_append_only(tmp_path):
    seen = []
    def g(messages): seen.append(list(messages)); return gen(json.dumps({"action": "final", "leads": []}))
    prompter.run_session(g, StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert seen[0][0]["role"] == "system" and seen[0][1]["role"] == "user"


# --- beyond the brief's verbatim assertions -------------------------------------------------------

STEP_KEYS = {"step_no", "kind", "query", "row_count", "prompt_tokens", "completion_tokens", "cached_tokens",
             "wall_seconds", "error"}


def test_step_records_have_the_steps_table_shape(tmp_path):
    acts = [json.dumps({"action": "run_cypher", "query": Q}),
            "garbage",
            json.dumps({"action": "final", "leads": []})]
    leads, steps = prompter.run_session(scripted(acts), StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert [s["step_no"] for s in steps] == [1, 2, 3]
    assert all(set(s) == STEP_KEYS for s in steps)
    assert [s["kind"] for s in steps] == ["run_cypher", "malformed", "final"]
    assert steps[0]["query"] == Q and steps[0]["error"] is None and steps[0]["completion_tokens"] == 10
    assert steps[1]["query"] is None and steps[1]["row_count"] is None and steps[1]["error"]
    assert steps[2]["row_count"] is None and steps[2]["error"] is None
    assert all(isinstance(s["wall_seconds"], float) and s["wall_seconds"] >= 0 for s in steps)


def test_every_later_prompt_extends_the_earlier_one(tmp_path):
    seen = []
    acts = [json.dumps({"action": "run_cypher", "query": Q}), "nonsense",
            json.dumps({"action": "read_code", "file": "a.js", "start": 1, "end": 3}),
            json.dumps({"action": "final", "leads": []})]
    it = iter(acts)
    def g(messages): seen.append([dict(m) for m in messages]); return gen(next(it))
    (tmp_path / "a.js").write_text("l1\nl2\nl3\nl4\n")
    prompter.run_session(g, StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert len(seen) == 4
    for earlier, later in zip(seen, seen[1:]):
        assert later[:len(earlier)] == earlier and len(later) == len(earlier) + 2   # assistant + user turn
    # the turns come from the formatter, with the fixed roles and prefixes
    assert seen[1][2]["role"] == "assistant" and seen[1][2]["content"] == acts[0]
    assert seen[1][3] == fmt.tool_result_message({"action": "run_cypher", "query": Q},
                                                 {"rows": [{"c.code": "exec(userInput)"}], "row_count": 1})
    assert seen[2][5]["content"].startswith("ERROR:")
    assert seen[3][7]["content"].startswith("RESULT:") and "l2" in seen[3][7]["content"]


def test_tool_error_is_an_error_turn_never_a_lead(tmp_path):
    acts = [json.dumps({"action": "run_cypher", "query": "MATCH (n) SET n.x = 1 RETURN n"}),
            json.dumps({"action": "read_code", "file": "../etc/passwd", "start": 1, "end": 2}),
            json.dumps({"action": "run_cypher"}),                        # missing query
            json.dumps({"action": "final", "leads": []})]
    seen = []
    it = iter(acts)
    def g(messages): seen.append(list(messages)); return gen(next(it))
    leads, steps = prompter.run_session(g, StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert leads == []
    assert steps[0]["kind"] == "run_cypher" and steps[0]["row_count"] is None and "read-only" in steps[0]["error"]
    assert steps[1]["kind"] == "read_code" and "escapes" in steps[1]["error"]
    assert steps[2]["kind"] == "malformed" and steps[2]["error"]
    assert seen[-1][-1]["content"].startswith("ERROR:")


def test_read_code_step_returns_lines(tmp_path):
    (tmp_path / "a.js").write_text("one\ntwo\nthree\n")
    acts = [json.dumps({"action": "read_code", "file": "a.js", "start": 2, "end": 3}),
            json.dumps({"action": "final", "leads": []})]
    leads, steps = prompter.run_session(scripted(acts), StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert steps[0]["kind"] == "read_code" and steps[0]["error"] is None and steps[0]["query"] is None


def test_forced_final_that_is_a_valid_final_keeps_its_leads(tmp_path):
    lead = {"flow_id": "F0", "file": "a.js", "function": "f", "line": 10, "cwe": "CWE-94", "confidence": "HIGH"}
    acts = [json.dumps({"action": "run_cypher", "query": Q}), json.dumps({"action": "run_cypher", "query": Q}),
            json.dumps({"action": "final", "leads": [lead]})]
    seen = []
    it = iter(acts)
    def g(messages): seen.append(list(messages)); return gen(next(it))
    leads, steps = prompter.run_session(g, StubDB(), str(tmp_path), "s", flows=[FLOW], max_actions=2)
    assert leads == [lead]
    assert [s["kind"] for s in steps] == ["run_cypher", "run_cypher", "forced_final"] and steps[2]["error"] is None
    assert seen[2][-1] == fmt.forced_final_message()


def test_stop_event_forces_final(tmp_path):
    stop = threading.Event()
    stop.set()
    calls = []
    def g(messages): calls.append(1); return gen(json.dumps({"action": "run_cypher", "query": Q}))
    leads, steps = prompter.run_session(g, StubDB(), str(tmp_path), "s", flows=[FLOW], stop=stop)
    assert leads == [] and len(calls) == 1 and steps[0]["kind"] == "forced_final" and steps[0]["error"]


def test_final_with_bad_leads_yields_empty_list(tmp_path):
    for bad in ('{"action":"final","leads":"nope"}', '{"action":"final","leads":[1,2]}', '{"action":"final"}'):
        leads, steps = prompter.run_session(scripted([bad]), StubDB(), str(tmp_path), "s", flows=[FLOW])
        assert leads == [] and steps[0]["kind"] == "final"


def test_token_counts_are_the_measured_ones(tmp_path):
    def g(messages): return gen(json.dumps({"action": "final", "leads": []}), p=1234, c=56)
    _, steps = prompter.run_session(g, StubDB(), str(tmp_path), "s", flows=[FLOW])
    assert (steps[0]["prompt_tokens"], steps[0]["completion_tokens"], steps[0]["cached_tokens"]) == (1234, 56, 0)
