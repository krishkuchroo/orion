def parse_claude_result(final: dict) -> dict:
    u = final.get("usage") or {}
    return {
        "input_tokens": u.get("input_tokens"),
        "output_tokens": u.get("output_tokens"),
        "cache_read": u.get("cache_read_input_tokens"),
        "cache_write": u.get("cache_creation_input_tokens"),
        "total_cost_usd": final.get("total_cost_usd"),
        "exit_reason": final.get("subtype"),
    }


def parse_codex_event(event: dict):
    if event.get("type") != "turn.completed":
        return None
    return {
        "input_tokens": event.get("input_tokens"),
        "output_tokens": event.get("output_tokens"),
        "cache_read": event.get("cached_input_tokens"),
        "cache_write": None,
        "total_cost_usd": None,
        "exit_reason": "turn.completed",
    }
