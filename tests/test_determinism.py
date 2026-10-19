"""Change 1: the build-time precompute must give the same answer on every run.

Each hash-seed test runs `tests/_hashseed_probe.py` in fresh subprocesses with different
PYTHONHASHSEED values (str hashing, and so set iteration order, changes with the seed) and
compares what they print. The edge-order test runs in-process: `orion reanalyze` reads FLOWS_TO
back from Neo4j in storage order, so pathfind must not depend on the order edges are listed in.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from orion.graph import pathfind, profiles, reachability, schema
from tests import graph_snapshot

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "tests" / "_hashseed_probe.py"


def _probe(seed: int, *args: str) -> dict:
    env = {**os.environ, "PYTHONHASHSEED": str(seed)}
    r = subprocess.run([sys.executable, str(PROBE), *args], capture_output=True, text=True,
                       env=env, cwd=ROOT, timeout=600)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_tied_sources_pick_the_same_flow_under_any_hash_seed():
    runs = {seed: _probe(seed, "tie")["candidate_flows"] for seed in range(5)}
    first = runs[0]
    for seed, flows in runs.items():
        assert flows == first, (
            f"CandidateFlow rows differ: PYTHONHASHSEED=0 picked {first[0]['source_uid']}, "
            f"PYTHONHASHSEED={seed} picked {flows[0]['source_uid']}")


def test_sampled_centrality_is_the_same_under_any_hash_seed():
    runs = {seed: _probe(seed, "big")["centrality"] for seed in range(5)}
    first = runs[0]
    for seed, cent in runs.items():
        differing = [u for u in first if first[u] != cent[u]]
        assert not differing, (
            f"centrality differs on {len(differing)} calls between PYTHONHASHSEED=0 and {seed}: "
            f"max {max(first.values()):.7f} vs {max(cent.values()):.7f}")


def _diamond(order: str) -> schema.Batch:
    """src -> a -> sink and src -> b -> sink: two equally short tainted paths to one eval()."""
    b = schema.Batch("diamond")
    b.emit_node("CpgMethod", {"full_name": "m"})
    b.emit_node("EntryPoint", {"uid": "ep"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "ep"}, "CpgMethod", {"full_name": "m"})
    for uid, name in (("src", "get"), ("a", "f"), ("b", "g"), ("sink", "eval")):
        b.emit_node("CpgCall", {"uid": uid, "name": name, "code": f"{name}()"})
    b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "m"}, "CpgCall", {"uid": "src"})
    first, second = ("a", "b") if order == "ab" else ("b", "a")
    for mid in (first, second):
        b.emit_edge("FLOWS_TO", "CpgCall", {"uid": "src"}, "CpgCall", {"uid": mid})
    for mid in (first, second):
        b.emit_edge("FLOWS_TO", "CpgCall", {"uid": mid}, "CpgCall", {"uid": "sink"})
    return b


def _flows(b: schema.Batch) -> list:
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    pathfind.pathfind(b, profiles.EXPRESS)
    return [(p["source_uid"], p["sink_uid"], json.loads(p["path_uids"]), p["rank"])
            for label, p in b.nodes if label == "CandidateFlow"]


def test_pathfind_ignores_flows_to_edge_order():
    ab, ba = _flows(_diamond("ab")), _flows(_diamond("ba"))
    assert ab == ba, f"path depends on edge order: {ab} vs {ba}"


@pytest.mark.slow
@pytest.mark.parametrize("repo", ["fixtures/NodeGoat", "fixtures/pygoat"])
def test_repo_rows_equal_under_two_hash_seeds(tmp_path, repo):
    """A real build, row for row: FLOWS_TO, CandidateFlow and every stored centrality value.
    Seeds 0 and 3 gave different NodeGoat centrality before the fix (6 of 2052 calls)."""
    if not Path(f"{repo}/cpg.bin").exists():
        pytest.skip(f"{repo} cpg.bin not present")
    a = _probe(0, "repo", repo, str(tmp_path / "s0"))
    b = _probe(3, "repo", repo, str(tmp_path / "s3"))
    d = graph_snapshot.diff(a, b)
    assert not d, "PYTHONHASHSEED=0 vs 3:\n" + graph_snapshot.format_diff(d)
