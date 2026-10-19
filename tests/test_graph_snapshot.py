"""Golden snapshots of FLOWS_TO + CandidateFlow on the parity fixtures (see tests/graph_snapshot.py).

A guard, not a bug test: a change that moves any taint edge or candidate flow on NodeGoat or PyGoat
fails here with the rows it added and the rows it lost.

Where the goldens come from: all four are written by the code after the determinism fixes
(hash-seed-free, then scan_id-free tie-breaks), because the old code had no single output to freeze:
  - its CandidateFlow ranks broke ties by call uid, which hashes the scan_id in, so every scan_id
    of the same code ranked tied flows differently (NodeGoat: 84 of 116 ranks moved between two
    scan_ids);
  - on PyGoat (4080 reachable nodes, sampled centrality) the output also changed with
    PYTHONHASHSEED (lm: 135-171 of the 300 kept flows changed between seeds).
Against the old goldens (NodeGoat from eval/orion-lm @ d20173a, PyGoat from the first fix):
FLOWS_TO identical (217, 1075); NodeGoat default/lm and PyGoat default keep exactly the same flows
(sink, category, path) with only ranks moved; PyGoat lm swaps 48 of its 300 capped flows, since
which flows fit under pathfind's 300 cap follows the ranking.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from orion.graph import joern_adapter, pathfind, profiles, reachability
from orion.graph import stream_build as S
from tests import graph_snapshot
from tests.test_stream_build import PYGOAT, pygoat_cpg_or_skip

GOLDEN = Path(__file__).parent / "golden"


def snapshot(repo: str, cpg: str, work, lm: bool) -> dict:
    prof = profiles.select_profile(repo)
    if lm:
        prof = profiles.with_lm_sinks(prof)
    env = S.build_envelope(cpg, work, prof)
    b = joern_adapter.normalize(env, "golden", language="golden")
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    pathfind.pathfind(b, prof)
    return graph_snapshot.from_batch(b)


@pytest.mark.slow
@pytest.mark.parametrize("name,repo", [("nodegoat", "fixtures/NodeGoat"), ("pygoat", PYGOAT)])
@pytest.mark.parametrize("variant", ["default", "lm"])
def test_snapshot_matches_golden(tmp_path, name, repo, variant):
    if name == "pygoat":
        cpg = pygoat_cpg_or_skip()
    else:
        cpg = f"{repo}/cpg.bin"
        if not Path(cpg).exists():
            pytest.skip(f"{repo} cpg.bin not present")
    golden = json.loads((GOLDEN / f"{name}_{variant}.json").read_text())
    got = snapshot(repo, cpg, tmp_path, variant == "lm")
    d = graph_snapshot.diff(golden, got)
    assert not d, f"{name}/{variant} differs from its golden:\n" + graph_snapshot.format_diff(d)
