import json
from collections import Counter, defaultdict
from pathlib import Path
import pytest
from orion.graph import stream_build as S
from orion.graph import taint_summary as T
from tests.test_taint_summary import _export  # reuse exporter

def _read_segments(path: Path):
    recs = [json.loads(l) for l in path.read_text().splitlines()]
    preamble = [r for r in recs if r["seg"] == -1]
    perfunc = [r for r in recs if r["seg"] >= 0]
    return preamble, perfunc

def _consulted_cross_rd(g):
    """The part of _closure_edges' cross_rd the stitch actually consults: source keys owned by some
    method. Method-less-source keys are inert (never walked) and are NOT carried by the producer."""
    own = T.owner_map(g)
    raw, _ = T._closure_edges(g)
    return {src: set(dsts) for src, dsts in raw.items() if own.get(src) is not None}

def _prod_closure(perfunc):
    prod_cross, prod_targets = defaultdict(set), defaultdict(set)
    for seg in perfunc:
        for (o, i) in seg["cross_rd"]:
            prod_cross[o].add(i)
        for t in seg["closure_targets"]:
            prod_targets[seg["method_id"]].add(t)
    return {k: set(v) for k, v in prod_cross.items()}, dict(prod_targets)

@pytest.mark.slow
def test_producer_matches_python_partition(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    out = tmp_path / "segments.jsonl"
    n = S.run_producer(cpg, str(out))
    preamble, perfunc = _read_segments(out)
    assert len(preamble) == 1
    assert n == len(perfunc) == 281
    # Per-method vertex-id sets. The Python partition INCLUDES the METHOD vertex; so does the producer.
    g = _export(cpg)
    methods, _ = T.partition(g)
    py = {mid: {T._unwrap(v["id"]) for v in sub["vertices"]} for mid, sub in methods.items()}
    prod = {seg["method_id"]: {v["id"] for v in seg["vertices"]} for seg in perfunc}
    assert prod == py
    # Closure-edge parity gate (delta D.3.C): union over segments == the consulted closure seam.
    _, targets_by_method = T._closure_edges(g)
    prod_cross, prod_targets = _prod_closure(perfunc)
    assert prod_cross == _consulted_cross_rd(g)
    assert prod_targets == {m: set(v) for m, v in targets_by_method.items()}

@pytest.mark.slow
def test_producer_closure_parity_pygoat(tmp_path):
    cpg = "fixtures/PyGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("PyGoat cpg.bin not present")
    out = tmp_path / "segments.jsonl"
    S.run_producer(cpg, str(out))
    _, perfunc = _read_segments(out)
    g = _export(cpg)
    _, targets_by_method = T._closure_edges(g)
    prod_cross, prod_targets = _prod_closure(perfunc)
    assert prod_cross == _consulted_cross_rd(g)
    assert prod_targets == {m: set(v) for m, v in targets_by_method.items()}
