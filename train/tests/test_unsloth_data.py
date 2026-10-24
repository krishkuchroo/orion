import json

from train import unsloth_data

ROW = {"messages": [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}],
       "target": '{"action":"final","leads":[]}', "meta": {"pair_id": "P", "label": "patched"}}


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_to_chat_appends_target_as_assistant_turn_and_drops_meta():
    """Unsloth trains the assistant turn, so the target becomes that turn; meta never reaches Unsloth."""
    assert unsloth_data.to_chat(ROW) == {"messages": [
        {"role": "system", "content": "S"}, {"role": "user", "content": "U"},
        {"role": "assistant", "content": '{"action":"final","leads":[]}'}]}


def test_to_chat_merges_consecutive_roles_like_the_runtime():
    row = {**ROW, "messages": ROW["messages"] + [{"role": "user", "content": "V"}]}
    assert unsloth_data.to_chat(row)["messages"][1] == {"role": "user", "content": "U\n\nV"}


def test_convert_drops_rows_that_do_not_fit(tmp_path):
    """Unsloth truncates over-length rows (it would train on half an answer), so they are dropped here."""
    src, out = tmp_path / "in.jsonl", tmp_path / "out.jsonl"
    _write(src, [ROW, {**ROW, "target": "LONG"}, ROW])
    counts = unsloth_data.convert(str(src), str(out), fits=lambda r: r["target"] != "LONG")
    assert counts == {"read": 3, "written": 2, "dropped_over_length": 1}
    assert [json.loads(line) for line in out.read_text().splitlines()] == [unsloth_data.to_chat(ROW)] * 2


def test_convert_limit_stops_after_n_written_rows(tmp_path):
    src, out = tmp_path / "in.jsonl", tmp_path / "out.jsonl"
    _write(src, [ROW] * 5)
    assert unsloth_data.convert(str(src), str(out), fits=lambda r: True, limit=2)["written"] == 2
    assert len(out.read_text().splitlines()) == 2


def test_convert_tokenized_render_drops_rows_it_returns_none_for(tmp_path):
    """--tokenized: the encoder itself returns None for an over-length row, so that row is dropped."""
    src, out = tmp_path / "in.jsonl", tmp_path / "out.jsonl"
    _write(src, [ROW, {**ROW, "target": "LONG"}])
    enc = {"input_ids": [1, 2], "attention_mask": [1, 1], "labels": [-100, 2]}
    counts = unsloth_data.convert(str(src), str(out), render=lambda r: None if r["target"] == "LONG" else enc)
    assert counts == {"read": 2, "written": 1, "dropped_over_length": 1}
    assert json.loads(out.read_text()) == enc


def test_tokenized_render_carries_meta_and_keeps_none_for_over_length():
    enc = {"input_ids": [1, 2], "attention_mask": [1, 1], "labels": [-100, 2]}
    assert unsloth_data.tokenized(ROW, lambda r: enc) == {**enc, "meta": ROW["meta"]}
    assert unsloth_data.tokenized(ROW, lambda r: None) is None
    assert unsloth_data.tokenized({k: v for k, v in ROW.items() if k != "meta"}, lambda r: enc) == {**enc, "meta": None}


def test_main_tokenized_writes_meta_in_input_order(tmp_path, monkeypatch):
    """The balanced export's order IS the training order, so --tokenized must keep it (and the meta with it)."""
    import transformers

    import train.sft_encode as se
    monkeypatch.setattr(transformers.AutoTokenizer, "from_pretrained", lambda *a, **k: object())
    monkeypatch.setattr(se, "resolve_turn_end", lambda tok: 9)
    monkeypatch.setattr(se, "encode_row", lambda r, tok, *, turn_end_id, max_len: None if r["target"] == "LONG" else
                        {"input_ids": [1, turn_end_id], "attention_mask": [1, 1], "labels": [-100, turn_end_id]})
    rows = [{**ROW, "meta": {"pair_id": f"P{i}"}} for i in range(6)]
    rows[2] = {**rows[2], "target": "LONG"}
    src, out = tmp_path / "in.jsonl", tmp_path / "out.jsonl"
    _write(src, rows)
    unsloth_data.main(["--in", str(src), "--out", str(out), "--tokenizer", "x", "--tokenized"])
    got = [json.loads(line) for line in out.read_text().splitlines()]
    assert [g["meta"]["pair_id"] for g in got] == ["P0", "P1", "P3", "P4", "P5"]
    assert got[0]["input_ids"] == [1, 9] and got[0]["labels"] == [-100, 9]


def test_make_fits_measures_the_exported_row_with_the_runtime_encoder(monkeypatch):
    """The balanced sampler's `fits`: a Stage 1 row fits when its SFT row (to_sft, same system message) encodes
    within max_len, exactly as --tokenized will encode it."""
    import train.sft_encode as se
    from train import examples
    tok, calls = object(), []
    monkeypatch.setattr(se, "resolve_turn_end", lambda t: 7 if t is tok else None)

    def enc(row, t, *, turn_end_id, max_len):
        calls.append((row, t, turn_end_id, max_len))
        return None if "LONG" in row["messages"][1]["content"] else {"input_ids": [1]}
    monkeypatch.setattr(se, "encode_row", enc)
    case = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
            "snippets": [{"role": "target", "file": "a.py", "function": "f", "start": 1, "end": 1, "code": "x = 1"}]}
    row = {"pair_id": "P", "label": "negative", "tier": "negative", "case": case, "lead": None, "split": "train"}
    fits = unsloth_data.make_fits(tok, 4096, schema_text="S")
    assert fits(row) is True
    assert calls[0] == (examples.to_sft(row, schema_text="S"), tok, 7, 4096)
    long_row = {**row, "case": {**case, "snippets": [{**case["snippets"][0], "code": "LONG"}]}}
    assert fits(long_row) is False
