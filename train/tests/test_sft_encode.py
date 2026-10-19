import re

import pytest

from train import sft_encode

SPECIALS = ["<u>", "<s>", "<a>", "<e>"]


class StubTok:
    """Tiny vocab; template: '<role>content<e>' per message, generation prompt '<a>'. `bos_token` (None = the
    tokenizer has none) is what encode(add_special_tokens=True) prepends; `template_bos` makes the template
    write it itself."""
    bos_token = None

    def __init__(self, template_bos=False):
        self.vocab = {t: i for i, t in enumerate(SPECIALS)}
        self.thinking_seen = []
        self.template_bos = template_bos

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
        return ("<b>" if self.template_bos else "") + out + ("<a>" if add_generation_prompt else "")

    def encode(self, text, add_special_tokens=False):
        ids = [self._id(p) for p in re.findall(r"<[usaeb]>|.", text)]
        return ([self._id(self.bos_token)] if add_special_tokens and self.bos_token else []) + ids


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


def test_prompt_bos_follows_the_runtime_rule():
    """Final review M3: like MlxModel._tokens_for (shared `model.encode_prompt`), specials are added only when
    the template did not write the BOS itself: one BOS either way, and never on the target."""
    from orion.lm import model
    for template_bos in (False, True):          # a template that omits BOS, then one that writes it
        tok = StubTok(template_bos=template_bos)
        tok.bos_token = "<b>"
        e, b = tok.vocab["<e>"], tok._id("<b>")
        r = sft_encode.encode_row(ROW, tok, turn_end_id=e, max_len=100)
        assert r["input_ids"][0] == b and r["input_ids"].count(b) == 1, template_bos
        assert r["labels"][-3:] == tok.encode("TT") + [e]
    tok = StubTok()
    tok.bos_token = "<b>"
    assert model.encode_prompt(tok, "<u>x") == [tok._id("<b>")] + tok.encode("<u>x")
    assert model.encode_prompt(tok, "<b><u>x") == tok.encode("<b><u>x")
