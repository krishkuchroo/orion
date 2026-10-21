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
    u = event.get("usage") or {}
    return {
        "input_tokens": u.get("input_tokens"),
        "output_tokens": u.get("output_tokens"),
        "cache_read": u.get("cached_input_tokens"),
        "cache_write": None,
        "total_cost_usd": None,
        "exit_reason": "turn.completed",
    }


# Codex nests token counts under event["usage"] (codex-cli 0.155.1 fixture):
#   {"type":"turn.completed","usage":{"input_tokens":13408,"cached_input_tokens":11136,
#    "cache_write_input_tokens":0,"output_tokens":38,"reasoning_output_tokens":31}}
# Codex input_tokens INCLUDES cached tokens, so uncached_in = input - cached.
# Claude `result` fixture (2.1.302) carried BOTH `modelUsage` (camelCase keys, one entry
# per model) and top-level `usage` (snake_case). normalize_usage sums modelUsage when
# present and falls back to top-level `usage` when absent.
#
# Reasoning double-count: the fixture has no total_tokens, so it is inferred from one
# non-zero-reasoning sample (no total_tokens to confirm). Prompt "How many primes are below 2000?" with a one-token answer ("303")
# gave output_tokens=38 and reasoning_output_tokens=31. A trivial reply costs ~5 output
# tokens ("ok" run: output_tokens=5, reasoning=0), so 38 = 31 reasoning + ~7 visible:
# reasoning is ALREADY INCLUDED in output_tokens. total() therefore never adds it again.

_FIELDS = ("uncached_in", "cache_read", "cache_write", "out", "reasoning")


def _sum_present(values):
    vals = [v for v in values if v is not None]
    return sum(vals) if vals else None


def _normalize_claude(raw: dict) -> dict:
    mu = raw.get("modelUsage")
    mu = {k: v for k, v in mu.items() if isinstance(v, dict)} if isinstance(mu, dict) else None
    if mu:
        rows = [{
            "uncached_in": m.get("inputTokens"),
            "cache_read": m.get("cacheReadInputTokens"),
            "cache_write": m.get("cacheCreationInputTokens"),
            "out": m.get("outputTokens"),
        } for m in mu.values()]
        out = {k: _sum_present(r[k] for r in rows) for k in rows[0]}
    else:
        u = raw.get("usage") or {}
        out = {
            "uncached_in": u.get("input_tokens"),
            "cache_read": u.get("cache_read_input_tokens"),
            "cache_write": u.get("cache_creation_input_tokens"),
            "out": u.get("output_tokens"),
        }
    out["reasoning"] = None
    return out


def _normalize_codex(raw: dict) -> dict:
    u = raw.get("usage") or {}
    inp, cached = u.get("input_tokens"), u.get("cached_input_tokens")
    uncached = max(0, inp - cached) if inp is not None and cached is not None else None
    return {
        "uncached_in": uncached,
        "cache_read": cached,
        "cache_write": None,
        "out": u.get("output_tokens"),
        "reasoning": u.get("reasoning_output_tokens"),
    }


def normalize_usage(raw: dict, *, source: str) -> dict:
    if source == "claude":
        return _normalize_claude(raw)
    if source == "codex":
        return _normalize_codex(raw)
    raise ValueError("unknown usage source: %r" % (source,))


def total(norm: dict) -> int:
    # reasoning is already inside out (see comment above); it is not added.
    return sum(norm.get(k) or 0 for k in ("uncached_in", "cache_read", "cache_write", "out"))
