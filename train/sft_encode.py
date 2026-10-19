"""Row -> (input_ids, labels) for SFT, with loss on the target tokens only.

Vendored verbatim into train/unsloth_lora.ipynb (cell 1); a repo test compares the copies, so keep these
functions self-contained (module-level names they use are defined by the notebook's earlier vendored
code: `merge_consecutive_roles`, `_turn_end_id` and `encode_prompt` from orion/lm/model.py).
"""
from __future__ import annotations

from orion.lm.model import _turn_end_id, encode_prompt, merge_consecutive_roles  # noqa: F401  (vendored in the notebook)


def resolve_turn_end(tok, *, thinking: bool = False) -> int:
    """The token id the chat template writes right after an assistant message, found exactly as the
    runtime does (model.py MlxModel.__init__). Raises if the template has none: never guess a stop."""
    special = set(tok.all_special_ids) | set(tok.get_added_vocab().values())
    tid = _turn_end_id(
        lambda msgs, gen: tok.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=gen, enable_thinking=thinking),
        lambda text: list(tok.encode(text, add_special_tokens=False)),
        special)
    if tid is None:
        raise ValueError("chat template has no turn-end token after an assistant message")
    return tid


def encode_row(row, tok, *, turn_end_id, max_len, thinking=False):
    """prompt = the runtime prompt (merge_consecutive_roles, chat template, generation prompt, same
    enable_thinking, same BOS rule via encode_prompt); completion = target tokens + the turn-end id. Prompt
    labels are -100. Returns None when the row exceeds max_len: it is never truncated (the runtime raises
    ContextOverflow)."""
    prompt = tok.apply_chat_template(merge_consecutive_roles(row["messages"]), tokenize=False,
                                     add_generation_prompt=True, enable_thinking=thinking)
    p_ids = encode_prompt(tok, prompt)
    t_ids = list(tok.encode(row["target"], add_special_tokens=False)) + [turn_end_id]
    ids = p_ids + t_ids
    if len(ids) > max_len:
        return None
    return {"input_ids": ids, "attention_mask": [1] * len(ids), "labels": [-100] * len(p_ids) + t_ids}
