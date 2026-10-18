"""Task B4: the MLX-LM `generate` wrapper and its llama-cpp fallback.

The pure helpers are tested without any model. The `@slow` tests load a real 4-bit MLX model from the
local Hugging Face cache (never the network) and are skipped when `mlx_lm` or the model is absent, so
the token-free suite stays green:

    ORION_LM_TEST_MODEL=<repo id or local dir>   default: mlx-community/gemma-3-1b-it-4bit
    ./.venv/bin/pytest tests/test_lm_model.py -m slow -v
"""
from __future__ import annotations

import os
import re
import sys

import pytest

from orion.lm import format as fmt
from orion.lm.model import (GenResult, common_prefix_len, constrained_schema, merge_consecutive_roles,
                            splice_prompt_tokens)

DEFAULT_TEST_MODEL = "mlx-community/gemma-3-1b-it-4bit"


# ----------------------------------------------------------------------------- token-free


def test_gen_result_import_does_not_pull_in_mlx_or_outlines():
    assert GenResult("x", 1, 2, 0).text == "x"
    assert not any(m == "mlx" or m.startswith(("mlx.", "mlx_lm", "outlines", "llama_cpp")) for m in sys.modules)


def test_merge_consecutive_roles_concatenates_same_role_runs_with_a_blank_line():
    msgs = [
        {"role": "system", "content": "S"},
        {"role": "user", "content": "A"},
        {"role": "assistant", "content": '{"action":"final","leads":[]}'},
        {"role": "user", "content": "RESULT: x"},
        {"role": "user", "content": "Budget reached."},
    ]
    merged = merge_consecutive_roles(msgs)
    assert [m["role"] for m in merged] == ["system", "user", "assistant", "user"]
    assert merged[-1]["content"] == "RESULT: x\n\nBudget reached."
    # the input is never mutated (the prompter's history is append-only and byte-identical to training)
    assert len(msgs) == 5 and msgs[-1]["content"] == "Budget reached."
    # deterministic + idempotent, so the training cutter (D5) can apply the same function
    assert merge_consecutive_roles(merged) == merged


def test_merge_consecutive_roles_leaves_alternating_history_alone():
    msgs = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "c"}]
    assert merge_consecutive_roles(msgs) == msgs


def test_common_prefix_len():
    assert common_prefix_len([1, 2, 3], [1, 2, 3, 4]) == 3
    assert common_prefix_len([1, 2, 3], [1, 9]) == 1
    assert common_prefix_len([], [1]) == 0
    assert common_prefix_len([1, 2], [1, 2]) == 2


def test_constrained_schema_sorts_properties_at_every_level_and_keeps_the_rest():
    s = constrained_schema(fmt.ACTION_SCHEMA)
    assert list(s["properties"]) == sorted(fmt.ACTION_SCHEMA["properties"])
    lead = s["properties"]["leads"]["items"]
    assert list(lead["properties"]) == sorted(lead["properties"])
    assert s["required"] == ["action"] and s["additionalProperties"] is False
    assert fmt.ACTION_SCHEMA["properties"] is not s["properties"]  # a copy, the original is untouched


def test_splice_keeps_the_models_own_reply_tokens():
    enc = lambda t: [ord(c) for c in t]            # a toy tokenizer: one token per character
    cache = [1, 2, 3, 77, 88, 99]                   # prompt (3 tokens) + reply "ab" as the model split it + stop
    last = ("PPP", "ab")
    # continues the exchange: the stop text is already in the cache, only the tail is tokenized
    out = splice_prompt_tokens("PPPab<e>\nU", last, cache, enc, "<e>")
    assert out == cache + enc("\nU")
    # llama.cpp style: the stop token is NOT in the cache, so the tail starts with its text
    assert splice_prompt_tokens("PPPab<e>\nU", last, cache[:-1], enc, None) == cache[:-1] + enc("<e>\nU")
    # not a continuation (history edited, or the template trimmed the reply): caller tokenizes normally
    assert splice_prompt_tokens("PPPa<e>\nU", last, cache, enc, "<e>") is None
    assert splice_prompt_tokens("PPPab<x>", last, cache, enc, "<e>") is None
    assert splice_prompt_tokens("anything", None, cache, enc, "<e>") is None
    # identical prompt again: nothing to add
    assert splice_prompt_tokens("PPPab<e>", last, cache, enc, "<e>") == cache


def test_action_regex_admits_exactly_the_canonical_training_target():
    pytest.importorskip("outlines_core")
    from orion.lm.model import _action_regex
    rx = re.compile(_action_regex())
    for action in ({"action": "run_cypher", "query": "MATCH (m:CpgMethod {scan_id:$scan_id}) RETURN m.name LIMIT 5"},
                   {"action": "read_code", "file": "app/routes.js", "start": 10, "end": 40},
                   {"action": "final", "leads": [{"flow_id": "F0", "file": "a.js", "function": "f",
                                                  "line": 3, "cwe": "CWE-89", "confidence": "HIGH"}]},
                   {"action": "final", "leads": []}):
        assert rx.fullmatch(fmt.dumps_action(action)), action
    # the un-sorted order the schema lists its properties in is NOT what the grammar admits
    assert not rx.fullmatch('{"action":"read_code","file":"a.js","start":1,"end":2}')
    assert not rx.fullmatch('{"action": "final", "leads": []}')  # no whitespace: dumps_action's shape
    assert not rx.fullmatch('{"action":"shell"}')


# ----------------------------------------------------------------------------- slow (real model)


def _test_model_path() -> str:
    """Local directory of the test model, or skip. Never downloads (inference is offline)."""
    pytest.importorskip("mlx_lm")
    spec = os.environ.get("ORION_LM_TEST_MODEL", DEFAULT_TEST_MODEL)
    if os.path.isdir(spec):
        return spec
    from huggingface_hub import snapshot_download
    try:
        return snapshot_download(spec, local_files_only=True)
    except Exception as e:  # LocalEntryNotFoundError / HFValidationError / OSError
        pytest.skip(f"test model {spec!r} is not in the local HF cache ({type(e).__name__}); "
                    f"download it once with: huggingface-cli download {spec}")


@pytest.fixture(scope="module")
def model():
    from orion.lm import model as lm_model
    return lm_model.load(_test_model_path(), seed=1)


@pytest.mark.slow
def test_generate_returns_str_for_a_tiny_prompt(model):
    model.reset_cache()
    out = model.generate([{"role": "user", "content": "Reply with the single word: ok"}], constrain=False)
    assert isinstance(out, GenResult)
    assert out.text.strip() != "" and out.prompt_tokens > 0 and out.completion_tokens > 0
    assert out.cached_tokens == 0
    assert "<end_of_turn>" not in out.text and "<eos>" not in out.text  # stopped on the turn end, not run on


@pytest.mark.slow
def test_second_turn_reports_cached_tokens(model):
    model.reset_cache()
    msgs = [{"role": "user", "content": "Say ok"}]
    a = model.generate(msgs, constrain=False)
    b = model.generate(msgs + [{"role": "assistant", "content": a.text}, {"role": "user", "content": "Again"}],
                       constrain=False)
    assert b.cached_tokens >= a.prompt_tokens       # the append-only history reused the cache
    assert b.cached_tokens < b.prompt_tokens        # and the new turn was really prefilled


@pytest.mark.slow
def test_constrained_turns_extend_the_cache_exactly(model):
    """Every turn constrained (the design's default): the next prompt is an exact extension of the
    cache (previous prompt + previous reply incl. its stop token), and every reply parses."""
    model.reset_cache()
    msgs = [fmt.system_message("(:CpgMethod {scan_id, name})"),
            {"role": "user", "content": 'TASK: no candidate flows. Emit {"action":"final","leads":[]}.'}]
    prev = None
    for turn in range(3):
        r = model.generate(msgs)
        assert fmt.parse_action(r.text) is not None, r.text
        if prev is not None:
            assert r.cached_tokens == prev.prompt_tokens + prev.completion_tokens, (turn, r, prev)
        prev = r
        msgs = msgs + [{"role": "assistant", "content": r.text},
                       {"role": "user", "content": f"RESULT: run_cypher: [] (turn {turn + 1}). Emit final again."}]


@pytest.mark.slow
def test_divergent_history_does_not_report_a_full_cache_hit(model):
    model.reset_cache()
    a = model.generate([{"role": "user", "content": "Say ok"}], constrain=False)
    b = model.generate([{"role": "user", "content": "Completely different question: name a colour."}],
                       constrain=False)
    assert b.cached_tokens < a.prompt_tokens        # not an extension of the previous prompt


@pytest.mark.slow
def test_consecutive_user_turns_are_accepted(model):
    # The prompter's forced final appends a user turn right after a RESULT:/ERROR: user turn; Gemma's
    # template rejects that unless the two are merged (model.merge_consecutive_roles).
    model.reset_cache()
    msgs = [{"role": "user", "content": "Say ok"}]
    a = model.generate(msgs, constrain=False)
    msgs += [{"role": "assistant", "content": a.text},
             {"role": "user", "content": "RESULT: run_cypher: []"},
             fmt.forced_final_message()]
    out = model.generate(msgs)
    assert out.prompt_tokens > a.prompt_tokens and out.completion_tokens > 0
    assert fmt.parse_action(out.text) is not None


@pytest.mark.slow
def test_context_cap_is_enforced_not_truncated(model):
    from orion.lm.model import ContextOverflow
    saved = model.context_cap
    model.context_cap = 8
    try:
        with pytest.raises(ContextOverflow):
            model.generate([{"role": "user", "content": "This prompt is longer than eight tokens, surely."}])
    finally:
        model.context_cap = saved
