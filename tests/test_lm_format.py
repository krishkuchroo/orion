"""Token-free tests for orion.lm.format: the ONE place that builds Orion-LM messages (runtime prompter
and training examples share it), plus the action parser and schema."""
from __future__ import annotations

import json

from orion.lm import format as fmt


def test_parse_action_accepts_one_json_object_and_rejects_noise():
    assert fmt.parse_action('{"action":"final","leads":[]}') == {"action": "final", "leads": []}
    assert fmt.parse_action("sure! here you go") is None
    assert fmt.parse_action('{"action":"nope"}') is None            # unknown action name


def test_tool_result_is_a_user_turn_with_result_prefix():
    m = fmt.tool_result_message({"action": "run_cypher", "query": "q"}, {"rows": [], "row_count": 0})
    assert m["role"] == "user" and m["content"].startswith("RESULT:")


def test_action_schema_names_three_actions():
    assert set(fmt.ACTION_SCHEMA["properties"]["action"]["enum"]) == {"run_cypher", "read_code", "final"}


# --- beyond the brief's verbatim assertions -------------------------------------------------------

def test_parse_action_tolerates_whitespace_and_json_fence_but_not_two_objects():
    act = {"action": "run_cypher", "query": "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c"}
    assert fmt.parse_action("  \n" + json.dumps(act) + "\n ") == act
    assert fmt.parse_action("```json\n" + json.dumps(act) + "\n```") == act
    assert fmt.parse_action("```\n" + json.dumps(act) + "\n```") == act
    assert fmt.parse_action(json.dumps(act) + json.dumps(act)) is None
    assert fmt.parse_action('["final"]') is None                      # not an object
    assert fmt.parse_action('{"leads": []}') is None                  # no action key
    assert fmt.parse_action("") is None


def test_read_code_result_returns_source_lines_verbatim():
    act = {"action": "read_code", "file": "a.js", "start": 2, "end": 3}
    m = fmt.tool_result_message(act, {"file": "a.js", "start": 2, "end": 3, "lines": 'x = "q";\nexec(x)'})
    assert m["role"] == "user" and m["content"].startswith("RESULT: read_code a.js:2-3\n")
    assert 'x = "q";\nexec(x)' in m["content"]                       # no JSON escaping of code


def test_tool_error_is_a_user_turn_with_error_prefix():
    m = fmt.tool_result_message({"action": "run_cypher", "query": "q"}, {"error": "SyntaxError: bad"})
    assert m["role"] == "user" and m["content"].startswith("ERROR:") and "SyntaxError: bad" in m["content"]
    e = fmt.error_message("not valid JSON")
    assert e["role"] == "user" and e["content"].startswith("ERROR:") and "not valid JSON" in e["content"]


def test_forced_final_is_a_user_turn_asking_for_final():
    m = fmt.forced_final_message()
    assert m["role"] == "user" and '"final"' in m["content"]


def test_system_message_carries_prompt_file_schema_and_rules():
    m = fmt.system_message("SCHEMA-TEXT")
    assert m["role"] == "system"
    assert "SCHEMA-TEXT" in m["content"]
    assert "{scan_id:$scan_id}" in m["content"]
    assert "flow_id" in m["content"]
    for name in ("run_cypher", "read_code", "final"):
        assert name in m["content"]


def test_task_message_is_user_turn_naming_each_flow():
    flows = [{"flow_id": "F0", "rank": 0, "sink_category": "code_exec", "source_uid": "s", "sink_uid": "k",
              "nodes": [{"file": "a.js", "function": "f", "line": 10, "code": "exec(x)"}]}]
    m = fmt.task_message(flows)
    assert m["role"] == "user"
    assert "F0" in m["content"] and "a.js" in m["content"] and "exec(x)" in m["content"]
    assert fmt.task_message(flows) == m                               # deterministic
    assert fmt.task_message([])["role"] == "user"


def test_dumps_action_is_canonical():
    a = {"query": "q", "action": "run_cypher"}
    assert fmt.dumps_action(a) == '{"action":"run_cypher","query":"q"}'
    assert fmt.parse_action(fmt.dumps_action(a)) == a


def test_action_schema_has_per_action_fields():
    p = fmt.ACTION_SCHEMA["properties"]
    assert "query" in p and {"file", "start", "end"} <= set(p)
    lead_fields = set(p["leads"]["items"]["properties"])
    assert {"flow_id", "file", "function", "line", "cwe", "confidence"} <= lead_fields
    assert fmt.ACTION_SCHEMA["required"] == ["action"]
