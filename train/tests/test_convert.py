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
