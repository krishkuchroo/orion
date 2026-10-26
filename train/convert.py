"""MLX conversion. One call for both local arms: `orion-lm-base` (unmerged base weights) and
`orion-lm` (merged fine-tune), so both carry identical quantization."""
from __future__ import annotations

import subprocess
import sys


def to_mlx(model_dir: str, out_dir: str, *, q_bits: int = 4, run=None) -> str:
    """Quantize `model_dir` to MLX at `out_dir`; returns `out_dir`. `run(argv)` is injectable for tests."""
    argv = [sys.executable, "-m", "mlx_lm", "convert", "--hf-path", model_dir,
            "--mlx-path", out_dir, "-q", "--q-bits", str(q_bits)]
    (run or (lambda a: subprocess.run(a, check=True)))(argv)
    return out_dir


def merge_lora(base_dir: str, adapter_dir: str, out_dir: str) -> str:
    """Fold the LoRA adapter at `adapter_dir` (trained on the 4-bit MLX `base_dir`) into a copy at `out_dir`.

    Each adapted layer becomes bf16 dequant(W) + scale * (A @ B)^T, left unquantized: run C1's change is about 3%
    of one 4-bit step, so re-quantizing it would round the fine-tune away. Every other tensor is copied as is, so
    the unadapted layers stay identical to the base arm. mlx_lm loads a layer without `.scales` as a plain Linear."""
    import json
    import shutil
    from pathlib import Path

    import mlx.core as mx

    base, out = Path(base_dir), Path(out_dir)
    if out.exists():
        raise FileExistsError(out)
    q = json.loads((base / "config.json").read_text())["quantization"]
    scale = json.loads((Path(adapter_dir) / "adapter_config.json").read_text())["lora_parameters"]["scale"]
    ad = mx.load(str(Path(adapter_dir) / "adapters.safetensors"))
    index = json.loads((base / "model.safetensors.index.json").read_text())
    adapted = sorted({k.rsplit(".", 1)[0] for k in ad})
    if missing := [m for m in adapted if f"{m}.scales" not in index["weight_map"]]:
        raise ValueError(f"adapter layers not quantized in {base_dir}: {missing}")

    shutil.copytree(base, out, ignore=shutil.ignore_patterns("*.safetensors", "*.safetensors.index.json"))
    total = 0
    for shard in sorted(set(index["weight_map"].values())):
        w, meta = mx.load(str(base / shard), return_metadata=True)
        for m in adapted:
            if f"{m}.weight" in w:
                W = mx.dequantize(w.pop(f"{m}.weight"), w.pop(f"{m}.scales"), w.pop(f"{m}.biases"),
                                  group_size=q["group_size"], bits=q["bits"], mode=q.get("mode", "affine"))
                delta = scale * (ad[f"{m}.lora_a"] @ ad[f"{m}.lora_b"]).T
                w[f"{m}.weight"] = (W.astype(mx.float32) + delta).astype(mx.bfloat16)
        mx.save_safetensors(str(out / shard), w, metadata=meta)
        total += sum(v.nbytes for v in w.values())
        del w
        mx.clear_cache()
    for m in adapted:
        del index["weight_map"][f"{m}.scales"], index["weight_map"][f"{m}.biases"]
    index.setdefault("metadata", {})["total_size"] = total
    (out / "model.safetensors.index.json").write_text(json.dumps(index, indent=2))
    return out_dir
