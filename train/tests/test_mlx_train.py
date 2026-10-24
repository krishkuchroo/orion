import argparse
import json

import pytest

from train import mlx_train

ROW = {"input_ids": [1, 2, 3, 4], "attention_mask": [1, 1, 1, 1], "labels": [-100, -100, 3, 4]}


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_rows_stream_from_disk_with_only_training_keys(tmp_path):
    p = tmp_path / "d.jsonl"
    _write(p, [{**ROW, "meta": "x"}, ROW])
    rows = mlx_train.JsonlRows(str(p), 8)
    assert (rows.rows, rows.tokens) == (2, 8)
    assert not hasattr(rows, "__len__")        # unsized: the trainer streams it instead of preparing every row
    got = list(rows)
    assert [{k: v.tolist() for k, v in r.items()} for r in got] == [ROW, ROW]
    assert got[0]["input_ids"].dtype.name == "int32"
    assert len(list(rows)) == 2                 # re-iterable, so a resumed run can replay the stream


def test_rows_repeat_per_epoch(tmp_path):
    p = tmp_path / "d.jsonl"
    _write(p, [ROW])
    assert len(list(mlx_train.JsonlRows(str(p), 8, epochs=2))) == 2


def test_rows_keep_only_picked_rows_in_file_order(tmp_path):
    p = tmp_path / "d.jsonl"
    _write(p, [{**ROW, "input_ids": [i, 2, 3, 4]} for i in range(3)])
    rows = mlx_train.JsonlRows(str(p), 8, pick=frozenset({2, 0}))
    assert rows.rows == 2
    assert [r["input_ids"][0] for r in rows] == [0, 2]


def test_eval_pick_is_seeded_and_bounded():
    assert mlx_train.eval_pick(10, 3, seed=1) == mlx_train.eval_pick(10, 3, seed=1)
    assert len(mlx_train.eval_pick(10, 3, seed=1)) == 3 and max(mlx_train.eval_pick(10, 3, seed=1)) < 10
    assert mlx_train.eval_pick(2, 5, seed=1) == frozenset({0, 1})


def test_rows_refuse_over_length_instead_of_truncating(tmp_path):
    """The trainer truncates long rows, which would cut the answer off; refuse so the data gets rebuilt."""
    p = tmp_path / "d.jsonl"
    _write(p, [ROW])
    with pytest.raises(ValueError, match="> --max-len 3"):
        mlx_train.JsonlRows(str(p), 3)


def test_rows_refuse_rows_with_nothing_to_train(tmp_path):
    p = tmp_path / "d.jsonl"
    _write(p, [{**ROW, "labels": [-100] * 4}])
    with pytest.raises(ValueError, match="no trained tokens"):
        mlx_train.JsonlRows(str(p), 8)


def test_total_steps_drops_a_partial_last_step():
    assert mlx_train.total_steps(7000, epochs=1, grad_accum=16, max_steps=0) == 437
    assert mlx_train.total_steps(100, epochs=1, grad_accum=16, max_steps=30) == 30


def test_config_caps_memory_and_keeps_the_rows_eos():
    a = argparse.Namespace(
        out="o", grad_accum=1, lr=2e-4, warmup_steps=5, weight_decay=0.01, save_steps=0, seed=3407, max_len=4096,
        memory_gb=6.0, wired_gb=4.0, cache_gb=0.5)
    kw = mlx_train.config_kwargs(a, 30)
    assert (kw["memory_limit_gb"], kw["wired_limit_gb"], kw["cache_limit_gb"]) == (6.0, 4.0, 0.5)
    assert kw["append_eos"] is False and kw["use_cce"] is True and kw["max_steps"] == 30
    assert kw["report_to"] == "tensorboard" and kw["streaming"] is True


def test_config_trains_in_file_order():
    """The trainer's streaming default pools 8 micro-batches, length-sorts and permutes them; 1 keeps the file
    order, which the balanced export lays out on purpose (a vulnerable row and its twin share one 16-row step)."""
    a = argparse.Namespace(
        out="o", grad_accum=16, lr=2e-4, warmup_steps=5, weight_decay=0.01, save_steps=200, seed=3407, max_len=4096,
        memory_gb=6.0, wired_gb=4.0, cache_gb=0.5)
    kw = mlx_train.config_kwargs(a, 437)
    assert kw["streaming_text_length_window_batches"] == 1
    assert kw["per_device_train_batch_size"] == 1 and kw["gradient_accumulation_steps"] == 16


def test_config_scores_held_out_rows_only_when_given():
    """Validation loss on a fixed dev sample every --eval-steps; off without --eval-data."""
    base = dict(out="o", grad_accum=16, lr=2e-4, warmup_steps=5, weight_decay=0.01, save_steps=25, seed=3407,
                max_len=4096, memory_gb=6.0, wired_gb=4.0, cache_gb=0.5)
    off = mlx_train.config_kwargs(argparse.Namespace(**base, eval_data=None, eval_rows=100, eval_steps=100), 437)
    assert off["eval_steps"] == 0 and "max_eval_batches" not in off
    on = mlx_train.config_kwargs(argparse.Namespace(**base, eval_data="dev.jsonl", eval_rows=100, eval_steps=100), 437)
    assert on["eval_steps"] == 100 and on["max_eval_batches"] == 100
