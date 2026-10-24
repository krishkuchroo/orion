"""Orion-LM LoRA on the Mac with Unsloth's MLX trainer, inside a fixed memory budget.

Why not `unsloth train`: its YAML rejects memory keys and the trainer then sets Metal's memory AND wired limits to
85% of the recommended working set (~9.7 GB on the 16 GB M4; wired memory cannot be paged out), and the CLI keeps a
torch + transformers parent process alive next to the MLX worker. This script runs the same trainer
(`unsloth_zoo.mlx`) in one process with MLX memory, wired memory and the buffer cache capped, loads the model
text-only (no vision tower), and trains on rows the runtime's own encoder already wrote
(`python -m train.unsloth_data --tokenized`), so the trained tokens equal Orion's prompt + target by construction.
The caps are starting values; `memory.json` in --out records what the run actually used.

Run from orion-train with Unsloth's Python (it has mlx + unsloth_zoo), under the memory guard:
    python -m train.guard --log train/runs/qwen35-smoke/train.log -- \\
        ~/.unsloth/studio/unsloth_studio/bin/python -m train.mlx_train \\
        --data train/data/mlx/smoke.jsonl --out train/runs/qwen35-smoke --max-steps 30 --grad-accum 1
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time

import numpy as np

GB = 1e9


def _parse(path: str, n: int, line: str, max_len: int) -> dict:
    row = json.loads(line)
    if len(row["input_ids"]) > max_len:
        raise ValueError(f"{path}:{n}: {len(row['input_ids'])} tokens > --max-len {max_len}; "
                         f"rebuild with train.unsloth_data --tokenized --max-len {max_len}")
    if not any(t != -100 for t in row["labels"]):
        raise ValueError(f"{path}:{n}: no trained tokens")
    return {k: np.asarray(row[k], dtype=np.int32) for k in ("input_ids", "attention_mask", "labels")}


class JsonlRows:
    """Pretokenized rows read from disk as the trainer asks for them, `epochs` passes in file order.

    Why: handed a list, the trainer prepares every row up front; with 7,000 rows that took the process from 2.4 GB
    to 7.6 GB before step 1 (measured 2026-10-23). With no __len__ the trainer streams it (`streaming=True`), so RAM
    stays flat. Each __iter__ re-reads the file, so a resumed run can replay the stream. The constructor checks every
    row once (refusing any over `max_len`: the trainer would truncate it, i.e. cut the answer) and keeps only counts.
    `pick` keeps only those rows (0-based among non-empty lines), still in file order: the fixed dev sample."""

    def __init__(self, path: str, max_len: int, *, epochs: int = 1, pick: frozenset[int] | None = None):
        self.path, self.max_len, self.epochs, self.pick = path, max_len, epochs, pick
        self.rows = self.tokens = 0
        for n, line in self._lines():
            self.rows += 1
            self.tokens += len(_parse(path, n, line, max_len)["input_ids"])

    def _lines(self):
        with open(self.path, encoding="utf-8") as fh:
            i = -1
            for n, line in enumerate(fh, 1):
                if line.strip():
                    i += 1
                    if self.pick is None or i in self.pick:
                        yield n, line

    def __iter__(self):
        for _ in range(self.epochs):
            for n, line in self._lines():
                yield _parse(self.path, n, line, self.max_len)


def eval_pick(n_rows: int, k: int, *, seed: int) -> frozenset[int]:
    """A fixed, seeded sample of `k` row indices, so every eval point scores the same held-out rows."""
    return frozenset(random.Random(seed).sample(range(n_rows), min(k, n_rows)))


def total_steps(n_rows: int, *, epochs: int, grad_accum: int, max_steps: int) -> int:
    """Whole optimizer steps the stream can fill (a partial last step is dropped: the stream would run dry)."""
    return max_steps if max_steps > 0 else (n_rows * epochs) // grad_accum


def config_kwargs(a: argparse.Namespace, steps: int) -> dict:
    """MLXTrainingConfig kwargs. Everything that differs from the trainer's defaults is set here on purpose."""
    scored = getattr(a, "eval_data", None)
    held_out = dict(max_eval_batches=a.eval_rows) if scored else {}   # batch 1: one batch per held-out row
    return dict(
        eval_steps=a.eval_steps if scored else 0,   # validation loss every N steps (0 = off)
        **held_out,
        output_dir=a.out, max_steps=steps, per_device_train_batch_size=1,
        gradient_accumulation_steps=a.grad_accum, learning_rate=a.lr, lr_scheduler_type="linear",
        warmup_steps=a.warmup_steps, weight_decay=a.weight_decay, max_grad_norm=1.0, logging_steps=1,
        save_steps=a.save_steps, seed=a.seed, max_seq_length=a.max_len, packing=False,
        append_eos=False,                    # the row already ends with the template's turn-end token
        use_cce=True,                        # lm_head logits only on trained tokens
        gradient_checkpointing=True,
        memory_limit_gb=a.memory_gb, wired_limit_gb=a.wired_gb, cache_limit_gb=a.cache_gb,
        report_to="tensorboard",             # live graphs: tensorboard --logdir <out>/runs
        report_grad_norm=True,
        streaming=True,                      # rows come from JsonlRows as needed, never all in RAM
        streaming_text_length_window_batches=1,   # exact file order (default 8 pools, length-sorts, permutes);
                                                  # the balanced export keeps each vulnerable row + twin in one step
    )


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="python -m train.mlx_train", description=__doc__.splitlines()[0])
    ap.add_argument("--data", required=True, help="pretokenized jsonl (train.unsloth_data --tokenized)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--model", default="unsloth/Qwen3.5-4B")
    ap.add_argument("--max-len", type=int, default=4096, help="longest row allowed; rows are never truncated")
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--max-steps", type=int, default=0, help="> 0 overrides --epochs")
    ap.add_argument("--grad-accum", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--warmup-steps", type=int, default=5)
    ap.add_argument("--weight-decay", type=float, default=0.01)
    ap.add_argument("--save-steps", type=int, default=200)
    ap.add_argument("--resume", help="checkpoint dir (<out>/checkpoint-N) to continue a stopped run from")
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--last-n-layers", type=int, default=0,
                    help="LoRA on the top N of 32 layers only (0 = all): the backward pass then stops at layer "
                         "32-N, so the layers below run forward only (about half the cost per token at N=8)")
    ap.add_argument("--memory-gb", type=float, default=6.0, help="MLX memory limit (soft: MLX frees cache to stay under)")
    ap.add_argument("--wired-gb", type=float, default=4.0, help="most MLX memory pinned in RAM; the rest can page")
    ap.add_argument("--cache-gb", type=float, default=0.5, help="MLX buffer cache cap")
    ap.add_argument("--eval-data", help="pretokenized dev jsonl: validation loss on a fixed sample of it")
    ap.add_argument("--eval-rows", type=int, default=100, help="size of the fixed, seeded dev sample")
    ap.add_argument("--eval-steps", type=int, default=100, help="score the dev sample every N optimizer steps")
    a = ap.parse_args(argv)

    import mlx.core as mx
    from unsloth_zoo.mlx.loader import FastMLXModel
    from unsloth_zoo.mlx.trainer import MLXTrainer, MLXTrainingConfig

    rows = JsonlRows(a.data, a.max_len, epochs=a.epochs)
    steps = total_steps(rows.rows, epochs=a.epochs, grad_accum=a.grad_accum, max_steps=a.max_steps)
    if steps * a.grad_accum > rows.rows * a.epochs:
        raise SystemExit(f"mlx_train: {steps} steps x {a.grad_accum} rows needs more than the {rows.rows * a.epochs} "
                         f"rows the stream has")
    held_out = None
    if a.eval_data:
        n_dev = JsonlRows(a.eval_data, a.max_len).rows
        held_out = JsonlRows(a.eval_data, a.max_len, pick=eval_pick(n_dev, a.eval_rows, seed=a.seed))
        a.eval_rows = held_out.rows
    os.makedirs(a.out, exist_ok=True)
    print(f"mlx_train: {rows.rows} rows, {rows.tokens} tokens, {steps} steps"
          + (f"; eval {held_out.rows} dev rows every {a.eval_steps} steps" if held_out else ""), flush=True)

    t0 = time.time()
    model, tokenizer = FastMLXModel.from_pretrained(a.model, max_seq_length=a.max_len, load_in_4bit=True,
                                                    text_only=True)
    model = FastMLXModel.get_peft_model(model, r=a.lora_r, lora_alpha=a.lora_alpha, lora_dropout=0.0,
                                        target_modules="all-linear", use_gradient_checkpointing=True,
                                        random_state=a.seed, max_seq_length=a.max_len,
                                        finetune_last_n_layers=a.last_n_layers or None)
    mem = {"load_s": round(time.time() - t0, 1), "load_peak_gb": round(mx.get_peak_memory() / GB, 2),
           "after_load_active_gb": round(mx.get_active_memory() / GB, 2)}
    print(f"mlx_train: loaded {json.dumps(mem)}", flush=True)
    mx.reset_peak_memory()

    from transformers import TrainerCallback

    class StepLog(TrainerCallback):
        """One JSON line per logged step: loss, seconds since the last line, MLX peak memory so far."""
        last = time.time()

        def on_log(self, args, state, control, logs=None, **kw):
            now = time.time()
            print("mlx_train: step " + json.dumps({"step": state.global_step, "s": round(now - self.last, 2),
                                                   "peak_gb": round(mx.get_peak_memory() / GB, 2),
                                                   **{k: v for k, v in (logs or {}).items()
                                                      if isinstance(v, (int, float))}}), flush=True)
            self.last = now

    trainer = MLXTrainer(model=model, tokenizer=tokenizer, train_dataset=rows, eval_dataset=held_out,
                         args=MLXTrainingConfig(**config_kwargs(a, steps)), callbacks=[StepLog()])
    t1 = time.time()
    trainer.train(resume_from_checkpoint=a.resume)
    mem.update(train_s=round(time.time() - t1, 1), train_peak_gb=round(mx.get_peak_memory() / GB, 2),
               steps=steps, rows=rows.rows, caps={"memory_gb": a.memory_gb, "wired_gb": a.wired_gb,
                                                  "cache_gb": a.cache_gb})
    trainer.save_model(a.out)
    with open(os.path.join(a.out, "memory.json"), "w") as fh:
        json.dump(mem, fh, indent=1)
    print(f"mlx_train: done {json.dumps(mem)}", flush=True)


if __name__ == "__main__":
    main()
