import re

import pytest

from train import sft_encode

SPECIALS = ["<u>", "<s>", "<a>", "<e>"]


class StubTok:
    """Tiny vocab; template: '<role>content<e>' per message, generation prompt '<a>'."""
    def __init__(self):
        self.vocab = {t: i for i, t in enumerate(SPECIALS)}
        self.thinking_seen = []

    def _id(self, piece):
        return self.vocab.setdefault(piece, len(self.vocab))

    @property
    def all_special_ids(self):
        return []                       # like Gemma: turn end is an ADDED token, not "special"

    def get_added_vocab(self):
        return {t: self.vocab[t] for t in SPECIALS}

    def apply_chat_template(self, msgs, tokenize=False, add_generation_prompt=False, enable_thinking=None):
        assert enable_thinking is not None, "enable_thinking must be passed"
        self.thinking_seen.append(enable_thinking)
        tag = {"user": "<u>", "system": "<s>", "assistant": "<a>"}
        out = "".join(f"{tag[m['role']]}{m['content']}<e>" for m in msgs)
        return out + ("<a>" if add_generation_prompt else "")

    def encode(self, text, add_special_tokens=False):
        assert add_special_tokens is False
        return [self._id(p) for p in re.findall(r"<[usae]>|.", text)]


ROW = {"messages": [{"role": "system", "content": "S"}, {"role": "user", "content": "x"},
                    {"role": "user", "content": "y"}], "target": "TT"}


def test_turn_end_derived_from_template():
    tok = StubTok()
    assert sft_encode.resolve_turn_end(tok) == tok.vocab["<e>"]


def test_turn_end_missing_raises():
    tok = StubTok()
    tok.apply_chat_template = lambda msgs, tokenize=False, add_generation_prompt=False, enable_thinking=None: "x"
    with pytest.raises(ValueError):
        sft_encode.resolve_turn_end(tok)


def test_mask_prompt_masked_target_and_end_supervised():
    tok = StubTok()
    e = tok.vocab["<e>"]
    r = sft_encode.encode_row(ROW, tok, turn_end_id=e, max_len=100)
    # merged prompt: <s>S<e><u>x\n\ny<e><a>  (consecutive user turns merged)
    prompt_ids = tok.encode("<s>S<e><u>x\n\ny<e><a>")
    n = len(prompt_ids)
    assert r["input_ids"][:n] == prompt_ids
    assert r["labels"][:n] == [-100] * n            # includes the assistant header <a>
    assert r["labels"][n:] == tok.encode("TT") + [e]
    assert r["input_ids"][n:] == r["labels"][n:]
    assert len(r["labels"]) == len(r["input_ids"]) == len(r["attention_mask"])


def test_overlength_row_dropped_not_truncated():
    tok = StubTok()
    e = tok.vocab["<e>"]
    full = sft_encode.encode_row(ROW, tok, turn_end_id=e, max_len=100)
    n = len(full["input_ids"])
    assert sft_encode.encode_row(ROW, tok, turn_end_id=e, max_len=n) is not None
    assert sft_encode.encode_row(ROW, tok, turn_end_id=e, max_len=n - 1) is None


def test_thinking_forwarded_as_runtime_does():
    tok = StubTok()
    sft_encode.encode_row(ROW, tok, turn_end_id=3, max_len=100, thinking=True)
    sft_encode.resolve_turn_end(tok, thinking=True)
    assert tok.thinking_seen and set(tok.thinking_seen) == {True}
