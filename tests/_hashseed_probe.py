"""Subprocess body for tests/test_determinism.py: build a batch, run the build-time precompute
(reachability -> centrality -> pathfind) and print what it produced as JSON. The test runs this
under several PYTHONHASHSEED values and compares the outputs; anything that iterates a str-keyed
set shows up as a difference. Not collected by pytest (no `test_` prefix).

    python tests/_hashseed_probe.py tie
    python tests/_hashseed_probe.py big
    python tests/_hashseed_probe.py repo <repo> <work_dir> [lm]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # repo root, for `tests.` / `orion`

from orion.graph import pathfind, profiles, reachability, schema  # noqa: E402


def _entry(b: schema.Batch) -> None:
    b.emit_node("CpgMethod", {"full_name": "m"})
    b.emit_node("EntryPoint", {"uid": "ep"})
    b.emit_edge("ENTERS_AT", "EntryPoint", {"uid": "ep"}, "CpgMethod", {"full_name": "m"})


def tie_batch() -> schema.Batch:
    """20 calls in one entry method, each FLOWS_TO the same eval() sink: a 20-way tie for the
    sink's nearest source."""
    b = schema.Batch("probe")
    _entry(b)
    b.emit_node("CpgCall", {"uid": "sink", "name": "eval", "code": "eval(x)"})
    for i in range(20):
        u = f"src{i:02d}"
        b.emit_node("CpgCall", {"uid": u, "name": "get", "code": "get()"})
        b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "m"}, "CpgCall", {"uid": u})
        b.emit_edge("FLOWS_TO", "CpgCall", {"uid": u}, "CpgCall", {"uid": "sink"})
    return b


def big_batch(n: int = 2600) -> schema.Batch:
    """A reachable binary tree of n calls: more than reachability._CENTRALITY_EXACT_MAX nodes, so
    centrality takes the k-sample path."""
    b = schema.Batch("probe")
    _entry(b)
    for i in range(n):
        b.emit_node("CpgCall", {"uid": f"c{i}", "name": "f", "code": "f()"})
        b.emit_edge("CONTAINS_CALL", "CpgMethod", {"full_name": "m"}, "CpgCall", {"uid": f"c{i}"})
        if i:
            b.emit_edge("FLOWS_TO", "CpgCall", {"uid": f"c{i // 2}"}, "CpgCall", {"uid": f"c{i}"})
    return b


def _precompute(b: schema.Batch, profile) -> None:
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    pathfind.pathfind(b, profile)


def _synthetic(b: schema.Batch) -> dict:
    _precompute(b, profiles.EXPRESS)
    return {
        "candidate_flows": [{k: p[k] for k in ("uid", "source_uid", "sink_uid", "path_uids", "rank")}
                            for label, p in b.nodes if label == "CandidateFlow"],
        "centrality": {p["uid"]: p["centrality"] for label, p in b.nodes if label == "CpgCall"},
    }


def _repo(repo: str, work: str, lm: bool) -> dict:
    from orion.graph import joern_adapter, stream_build
    from tests import graph_snapshot
    prof = profiles.select_profile(repo)
    if lm:
        prof = profiles.with_lm_sinks(prof)
    env = stream_build.build_envelope(f"{repo}/cpg.bin", work, prof)
    b = joern_adapter.normalize(env, "probe", language="probe")
    _precompute(b, prof)
    snap = graph_snapshot.from_batch(b)
    cent = sorted([p.get("file_path"), p.get("line"), p.get("code"), repr(p["centrality"])]
                  for label, p in b.nodes if label == "CpgCall")
    cent += sorted([p.get("full_name"), None, None, repr(p["centrality"])]
                   for label, p in b.nodes if label == "CpgMethod")
    return {**snap, "centrality": cent}


if __name__ == "__main__":
    case = sys.argv[1]
    if case == "tie":
        out = _synthetic(tie_batch())
    elif case == "big":
        out = _synthetic(big_batch())
    else:
        out = _repo(sys.argv[2], sys.argv[3], len(sys.argv) > 4 and sys.argv[4] == "lm")
    print(json.dumps(out))
