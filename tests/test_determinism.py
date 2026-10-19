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


def _located_tie(scan_id: str) -> schema.Batch:
    """The 20-source tie again, but with real uids (synthesize_uid hashes the scan_id in), as a
    build makes them: whichever uid sorts first differs from one scan_id to the next."""
    from orion.graph.schema import synthesize_uid
    b = schema.Batch(scan_id)
    b.emit_node("CpgMethod", {"full_name": "a.js::h"})
    b.emit_node("EntryPoint", {"uid": "ep"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "ep"}, "CpgMethod", {"full_name": "a.js::h"})
    sink = synthesize_uid(scan_id, "CALL", "a.js", 99, 0, "eval(x)")
    b.emit_node("CpgCall", {"uid": sink, "name": "eval", "code": "eval(x)", "file_path": "a.js", "line": 99,
                            "column": 0})
    for i in range(20):
        u = synthesize_uid(scan_id, "CALL", "a.js", i + 1, 0, "get()")
        b.emit_node("CpgCall", {"uid": u, "name": "get", "code": "get()", "file_path": "a.js", "line": i + 1,
                                "column": 0})
        b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "a.js::h"}, "CpgCall", {"uid": u})
        b.emit_edge("FLOWS_TO", "CpgCall", {"uid": u}, "CpgCall", {"uid": sink})
    return b


def _located(b: schema.Batch, profile) -> dict:
    """Precompute, then the scan_id-free snapshot plus every centrality value keyed by location."""
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    pathfind.pathfind(b, profile)
    snap = graph_snapshot.from_batch(b)
    snap["centrality"] = sorted([p.get("file_path"), p.get("line"), p.get("column"), p.get("code"),
                                 p["centrality"]] for label, p in b.nodes if label == "CpgCall")
    return snap


def test_tie_break_does_not_depend_on_the_scan_id():
    a = _located(_located_tie("scan-a"), profiles.EXPRESS)
    b = _located(_located_tie("scan-b"), profiles.EXPRESS)
    d = graph_snapshot.diff(a, b)
    assert not d, "scan-a vs scan-b:\n" + graph_snapshot.format_diff(d)


@pytest.mark.slow
@pytest.mark.parametrize("repo", ["fixtures/NodeGoat", "fixtures/pygoat"])
@pytest.mark.parametrize("variant", ["default", "lm"])
def test_repo_rows_do_not_depend_on_the_scan_id(tmp_path, repo, variant):
    """The same envelope normalized under two scan_ids must rank, path and score identically.
    Before: tie-breaks sorted by call uid, which hashes the scan_id in (NodeGoat: 84 of 116
    CandidateFlow ranks moved; PyGoat lm: 44 of the 300 kept flows changed)."""
    from orion.graph import joern_adapter, stream_build
    if not Path(f"{repo}/cpg.bin").exists():
        pytest.skip(f"{repo} cpg.bin not present")
    prof = profiles.select_profile(repo)
    if variant == "lm":
        prof = profiles.with_lm_sinks(prof)
    env = stream_build.build_envelope(f"{repo}/cpg.bin", tmp_path, prof)
    a = _located(joern_adapter.normalize(env, "scan-a", language="x"), prof)
    b = _located(joern_adapter.normalize(env, "scan-b", language="x"), prof)
    d = graph_snapshot.diff(a, b)
    assert not d, "scan-a vs scan-b:\n" + graph_snapshot.format_diff(d)


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
