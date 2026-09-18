from eval import usage


def test_parse_claude_result_reads_usage_and_cost():
    final = {"type": "result", "subtype": "success", "total_cost_usd": 0.42,
             "usage": {"input_tokens": 1000, "output_tokens": 200,
                       "cache_read_input_tokens": 50, "cache_creation_input_tokens": 10}}
    out = usage.parse_claude_result(final)
    assert out == {"input_tokens": 1000, "output_tokens": 200, "cache_read": 50,
                   "cache_write": 10, "total_cost_usd": 0.42, "exit_reason": "success"}


def test_parse_claude_result_missing_fields_are_none():
    out = usage.parse_claude_result({"type": "result"})
    assert out["input_tokens"] is None and out["total_cost_usd"] is None


def test_parse_codex_turn_completed():
    ev = {"type": "turn.completed", "input_tokens": 300, "cached_input_tokens": 20,
          "output_tokens": 40, "reasoning_output_tokens": 15}
    out = usage.parse_codex_event(ev)
    assert out["input_tokens"] == 300 and out["cache_read"] == 20
    assert out["output_tokens"] == 40 and out["total_cost_usd"] is None


def test_parse_codex_ignores_other_events():
    assert usage.parse_codex_event({"type": "item.completed"}) is None
