import sys

from train import convert


def test_to_mlx_builds_exact_argv():
    calls = []
    out = convert.to_mlx("/m/merged", "/m/mlx", run=calls.append)
    assert out == "/m/mlx"
    assert calls == [[sys.executable, "-m", "mlx_lm", "convert", "--hf-path", "/m/merged",
                      "--mlx-path", "/m/mlx", "-q", "--q-bits", "4"]]


def test_to_mlx_q_bits():
    calls = []
    convert.to_mlx("a", "b", q_bits=8, run=calls.append)
    assert calls[0][-2:] == ["--q-bits", "8"]


def _fake_base(tmp_path):
    import json

    import mlx.core as mx
    base = tmp_path / "base"
    base.mkdir()
    q = {"group_size": 64, "bits": 4, "mode": "affine"}
    (base / "config.json").write_text(json.dumps({"model_type": "x", "quantization": q, "quantization_config": q}))
    (base / "tokenizer.json").write_text("{}")
    mx.random.seed(0)
    w = {"emb.weight": mx.random.normal((4, 128)).astype(mx.bfloat16)}
    for m in ("m.a", "m.b"):
        w[f"{m}.weight"], w[f"{m}.scales"], w[f"{m}.biases"] = mx.quantize(
            (0.02 * mx.random.normal((8, 128))).astype(mx.bfloat16), group_size=64, bits=4)
    mx.save_safetensors(str(base / "model.safetensors"), w, metadata={"format": "mlx"})
    (base / "model.safetensors.index.json").write_text(
        json.dumps({"metadata": {"total_size": 0}, "weight_map": {k: "model.safetensors" for k in w}}))
    ad = tmp_path / "adapter"
    ad.mkdir()
    (ad / "adapter_config.json").write_text(json.dumps({"lora_parameters": {"rank": 2, "scale": 0.5}}))
    mx.save_safetensors(str(ad / "adapters.safetensors"), {"m.a.lora_a": 1e-3 * mx.random.normal((128, 2)),
                                                           "m.a.lora_b": mx.random.normal((2, 8))})
    return base, ad, w


def test_merge_lora_folds_the_delta_unquantized_and_copies_the_rest(tmp_path):
    import json

    import mlx.core as mx
    base, ad, w = _fake_base(tmp_path)
    out = convert.merge_lora(str(base), str(ad), str(tmp_path / "out"))

    got = mx.load(f"{out}/model.safetensors")
    a = mx.load(str(ad / "adapters.safetensors"))
    want = (mx.dequantize(w["m.a.weight"], w["m.a.scales"], w["m.a.biases"], group_size=64, bits=4)
            .astype(mx.float32) + 0.5 * (a["m.a.lora_a"] @ a["m.a.lora_b"]).T).astype(mx.bfloat16)
    assert got["m.a.weight"].dtype == mx.bfloat16 and mx.array_equal(got["m.a.weight"], want)
    assert "m.a.scales" not in got and "m.a.biases" not in got           # loads as a plain Linear
    for k in ("m.b.weight", "m.b.scales", "m.b.biases", "emb.weight"):  # unadapted tensors untouched
        assert mx.array_equal(got[k], w[k])
    index = json.loads((tmp_path / "out" / "model.safetensors.index.json").read_text())["weight_map"]
    assert sorted(index) == sorted(got)
    assert (tmp_path / "out" / "tokenizer.json").read_text() == "{}"
    assert json.loads((tmp_path / "out" / "config.json").read_text())["quantization"]["bits"] == 4


def test_merge_lora_refuses_an_existing_out_dir_and_unknown_modules(tmp_path):
    import mlx.core as mx
    import pytest
    base, ad, _ = _fake_base(tmp_path)
    (tmp_path / "taken").mkdir()
    with pytest.raises(FileExistsError):
        convert.merge_lora(str(base), str(ad), str(tmp_path / "taken"))
    mx.save_safetensors(str(ad / "adapters.safetensors"), {"m.zz.lora_a": mx.zeros((128, 2)),
                                                           "m.zz.lora_b": mx.zeros((2, 8))})
    with pytest.raises(ValueError, match="m.zz"):
        convert.merge_lora(str(base), str(ad), str(tmp_path / "out2"))
