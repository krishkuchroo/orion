"""SFT rows (`{messages, target, meta}` from `examples.export`) -> Unsloth chat rows (`{messages}`).

Unsloth renders `{"messages": [...]}` with the model's own chat template and, with `train_on_completions`,
trains the assistant turn. That render equals the runtime prompt (`enable_thinking=False`) + target: checked
on Qwen3.5-4B, 200/200 rows token-identical (2026-10-23). Unsloth TRUNCATES rows over `max_seq_length`, which
would train on half an answer, so such rows are dropped here, counted by the runtime's own encoder
(`sft_encode.encode_row`).

`--tokenized` writes the runtime encoder's own `{input_ids, attention_mask, labels}` instead (prompt labels -100),
for `train.mlx_train`: the trained tokens then equal the runtime prompt + target by construction. Each row keeps
its `meta` (the trainer reads only the three token keys), and rows stay in input order: a balanced export's order
is the training order.

    python -m train.unsloth_data --in train/data/sft/train.jsonl --out train/data/unsloth/train.jsonl \
        --tokenizer unsloth/Qwen3.5-4B [--max-len 8000] [--limit N] [--tokenized]
"""
from __future__ import annotations

import argparse
import json
import os

from orion.lm.model import merge_consecutive_roles


def to_chat(row: dict) -> dict:
    return {"messages": merge_consecutive_roles(row["messages"])
            + [{"role": "assistant", "content": row["target"]}]}


def tokenized(row: dict, encode) -> dict | None:
    """`encode(row)` plus the row's meta; None (over-length) stays None."""
    enc = encode(row)
    return None if enc is None else {**enc, "meta": row.get("meta")}


def make_fits(tokenizer, max_len: int, *, schema_text: str | None = None):
    """`fits(stage1_row) -> bool` for `balance.select` / `examples.export(balance_kwargs={"fits": ...})`: True when
    the row's SFT form (`examples.to_sft`, same system message) encodes within `max_len` with the runtime encoder,
    i.e. exactly when `--tokenized --max-len max_len` would keep it. `tokenizer` is an HF id / local dir or an
    already-loaded tokenizer."""
    from train import examples, sft_encode
    if isinstance(tokenizer, str):
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(tokenizer)
    turn_end = sft_encode.resolve_turn_end(tokenizer)

    def fits(row: dict) -> bool:
        return sft_encode.encode_row(examples.to_sft(row, schema_text=schema_text), tokenizer,
                                     turn_end_id=turn_end, max_len=max_len) is not None
    return fits


def convert(in_path: str, out_path: str, *, fits=lambda row: True, render=to_chat, limit: int | None = None) -> dict:
    """Write `render(row)` of every row that `fits(row)` (a None render counts as over-length too); stop after
    `limit` written rows."""
    counts = {"read": 0, "written": 0, "dropped_over_length": 0}
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(in_path, encoding="utf-8") as src, open(out_path, "w", encoding="utf-8") as out:
        for line in src:
            if not line.strip():
                continue
            if limit is not None and counts["written"] >= limit:
                break
            row = json.loads(line)
            counts["read"] += 1
            rendered = render(row) if fits(row) else None
            if rendered is None:
                counts["dropped_over_length"] += 1
                continue
            out.write(json.dumps(rendered, sort_keys=True) + "\n")
            counts["written"] += 1
    return counts


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="python -m train.unsloth_data", description=__doc__.splitlines()[0])
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tokenizer", required=True, help="HF id or local dir of the base model")
    ap.add_argument("--max-len", type=int, default=8000, help="must equal Unsloth max_seq_length and the runtime cap")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--tokenized", action="store_true", help="write input_ids/labels rows for train.mlx_train")
    a = ap.parse_args(argv)
    from transformers import AutoTokenizer

    from train import sft_encode
    tok = AutoTokenizer.from_pretrained(a.tokenizer)
    turn_end = sft_encode.resolve_turn_end(tok)

    def encode(r):
        return sft_encode.encode_row(r, tok, turn_end_id=turn_end, max_len=a.max_len)

    if a.tokenized:
        counts = convert(a.src, a.out, limit=a.limit, render=lambda r: tokenized(r, encode))
    else:
        counts = convert(a.src, a.out, limit=a.limit, fits=lambda r: encode(r) is not None)
    print(json.dumps(counts))


if __name__ == "__main__":
    main()
