"""Task 1: partition a raw Joern GraphSON graph into per-function subgraphs + a call graph.

Real joern-export of fixtures/NodeGoat/cpg.bin (present, ~634KB); marked slow since it shells out
to a real JVM subprocess. See docs/superpowers/specs/2026-07-23-streaming-graph-build-design.md.
"""
import json, subprocess, tempfile, shutil
from pathlib import Path
import pytest
from orion.graph import taint_summary as T
from orion.graph import joern_adapter as J

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
