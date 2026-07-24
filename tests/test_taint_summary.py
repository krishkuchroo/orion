"""Task 1: partition a raw Joern GraphSON graph into per-function subgraphs + a call graph.

Real joern-export of fixtures/NodeGoat/cpg.bin (present, ~634KB); marked slow since it shells out
to a real JVM subprocess. See docs/superpowers/specs/2026-07-23-streaming-graph-build-design.md.
"""
import json, subprocess, tempfile, shutil
from pathlib import Path
import pytest
from orion.graph import taint_summary as T
from orion.graph import joern_adapter as J
from orion.graph import profiles

JOERN_EXPORT = Path.home() / "joern/joern-cli/joern-export"

def _export(cpg_bin: str) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="orion_ts_"))
    try:
        subprocess.run([str(JOERN_EXPORT), "--repr=all", "--format=graphson",
                        "--out", str(tmp / "e"), cpg_bin], check=True,
                       capture_output=True, text=True)
        return json.loads((tmp / "e" / "export.json").read_text())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

@pytest.fixture(scope="session")
def nodegoat_graphson():
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    return _export(cpg)

@pytest.mark.slow
def test_partition_covers_graph(nodegoat_graphson):
    g = nodegoat_graphson
    inner = g["@value"] if "@type" in g else g
    methods, callgraph = T.partition(g)
    # Every METHOD id appears as a partition key.
    method_ids = {J._unwrap(v["id"]) for v in inner["vertices"] if v["label"] == "METHOD"}
    assert set(methods) == method_ids
    # NodeGoat has 281 functions (measured).
    assert len(methods) == 281
    # Cross-method edges (dropped from every slice) match the measured 12531.
    inside = sum(len(m["edges"]) for m in methods.values())
    assert len(inner["edges"]) - inside == 12531

@pytest.mark.slow
def test_summary_direct_reach(nodegoat_graphson):
    methods, _ = T.partition(nodegoat_graphson)
    # Every function's summary builds without error and every direct target is a real call
    # that lives in that same function (intra-function invariant).
    for mid, sub in methods.items():
        s = T.build_summary(mid, sub, frozenset({"req", "request"}), None)
        for entry, targets in s.direct.items():
            for (rc, idx) in targets:
                assert rc in s.real_calls


def _flowset(flows):
    return {(f["out"], f["in"], f["arg_index"], f["provenance"]) for f in flows}


@pytest.mark.slow
def test_oracle_parity_nodegoat(nodegoat_graphson):
    g = nodegoat_graphson
    prof = profiles.select_profile("fixtures/NodeGoat")
    entry_ids = J._entry_method_ids(g["@value"] if "@type" in g else g)
    entry_taint = frozenset(entry_ids) if prof.entrypoint_params_are_sources else None
    oracle = J.collapse_flows(g["@value"] if "@type" in g else g,
                              request_source_names=prof.request_source_names,
                              entrypoint_method_ids=entry_taint)
    got = T.flows_via_summaries(g, request_source_names=prof.request_source_names,
                                entrypoint_method_ids=entry_taint)
    assert len(oracle) == 217, "baseline changed; re-derive expectation"
    assert _flowset(got) == _flowset(oracle)   # EXACT: edges + provenance


@pytest.mark.slow
def test_oracle_parity_pygoat():
    cpg = "fixtures/pygoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("PyGoat cpg.bin not present")
    g = _export(cpg)
    inner = g["@value"] if "@type" in g else g
    prof = profiles.select_profile("fixtures/pygoat")
    entry_ids = J._entry_method_ids(inner)
    entry_taint = frozenset(entry_ids) if prof.entrypoint_params_are_sources else None
    oracle = J.collapse_flows(inner, request_source_names=prof.request_source_names,
                              entrypoint_method_ids=entry_taint)
    got = T.flows_via_summaries(g, request_source_names=prof.request_source_names,
                                entrypoint_method_ids=entry_taint)
    assert len(oracle) > 0, "vacuous parity: oracle produced no flows"  # GENERIC path is only covered here
    assert _flowset(got) == _flowset(oracle)   # EXACT: edges + provenance
