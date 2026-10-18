import json
from pathlib import Path
from eval import usage

FIX = Path(__file__).parent / "fixtures"
CODEX = json.loads((FIX / "codex_turn_completed.json").read_text())
CLAUDE = json.loads((FIX / "claude_result.json").read_text())


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


def test_parse_codex_reads_nested_usage_from_real_event():
    out = usage.parse_codex_event(CODEX)
    assert out["input_tokens"] == 13408 and out["cache_read"] == 11136
    assert out["output_tokens"] == 38 and out["total_cost_usd"] is None


def test_parse_codex_top_level_tokens_are_not_read():
    assert usage.parse_codex_event({"type": "turn.completed", "input_tokens": 3})["input_tokens"] is None


def test_parse_codex_ignores_other_events():
    assert usage.parse_codex_event({"type": "item.completed"}) is None


def test_normalize_claude_top_level_usage_splits_cache():
    raw = {"type": "result", "subtype": "success", "usage": {"input_tokens": 1000,
           "output_tokens": 200, "cache_read_input_tokens": 50, "cache_creation_input_tokens": 10}}
    out = usage.normalize_usage(raw, source="claude")
    assert out == {"uncached_in": 1000, "cache_read": 50, "cache_write": 10, "out": 200, "reasoning": None}


def test_normalize_claude_sums_model_usage():
    raw = {"modelUsage": {
        "a": {"inputTokens": 1, "outputTokens": 2, "cacheReadInputTokens": 3, "cacheCreationInputTokens": 4},
        "b": {"inputTokens": 10, "outputTokens": 20, "cacheReadInputTokens": 30, "cacheCreationInputTokens": 40}},
        "usage": {"input_tokens": 999}}
    out = usage.normalize_usage(raw, source="claude")
    assert out == {"uncached_in": 11, "cache_read": 33, "cache_write": 44, "out": 22, "reasoning": None}


def test_normalize_claude_real_fixture():
    out = usage.normalize_usage(CLAUDE, source="claude")
    assert out == {"uncached_in": 2, "cache_read": 11201, "cache_write": 7670, "out": 4, "reasoning": None}


def test_normalize_claude_empty_is_none():
    out = usage.normalize_usage({"type": "result"}, source="claude")
    assert set(out.values()) == {None}


def test_normalize_codex_from_real_event():
    out = usage.normalize_usage(CODEX, source="codex")
    assert out == {"uncached_in": 13408 - 11136, "cache_read": 11136, "cache_write": None,
                   "out": 38, "reasoning": 31}


def test_normalize_codex_missing_fields_are_none():
    out = usage.normalize_usage({"type": "turn.completed", "usage": {}}, source="codex")
    assert set(out.values()) == {None}


def test_normalize_rejects_unknown_source():
    import pytest
    with pytest.raises(ValueError):
        usage.normalize_usage({}, source="gemini")


def test_total_does_not_double_count_reasoning():
    # reasoning is already inside out (fixture-confirmed), so it is not added again
    norm = {"uncached_in": 100, "cache_read": 50, "cache_write": 0, "out": 30, "reasoning": 20}
    assert usage.total(norm) == 180
    assert usage.total({**norm, "reasoning": None}) == 180


def test_total_treats_none_as_zero():
    assert usage.total({"uncached_in": None, "cache_read": None, "cache_write": None,
                        "out": 5, "reasoning": None}) == 5


def test_normalize_codex_uncached_never_negative():
    raw = {"type": "turn.completed", "usage": {"input_tokens": 5, "cached_input_tokens": 9}}
    assert usage.normalize_usage(raw, source="codex")["uncached_in"] == 0


def test_normalize_claude_ignores_non_dict_model_usage():
    raw = {"modelUsage": {"a": "junk"}, "usage": {"input_tokens": 7}}
    assert usage.normalize_usage(raw, source="claude")["uncached_in"] == 7
