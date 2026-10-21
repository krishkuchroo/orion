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
