"""Change 5: two parameters are one CpgParameter only if they are the same parameter.

The uid was synthesize_uid(scan_id, "METHOD_PARAMETER_IN", "<param>", line, 0, name): no file, no
method. So `function h(req)` on line 1 of a.js and of b.js -- or the p0/p1 parameters of every
external stub, all on line 0 -- collapsed into one node (NodeGoat: 831 parameters -> 290 nodes).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from orion.graph import joern_adapter, persist, profiles
from orion.graph import stream_build as S
from tests.test_stream_build import PYGOAT, PYGOAT_FLOWS_TO, pygoat_cpg_or_skip


def _two_files_same_param() -> dict:
    """Minimal GraphSON: a.js::h(req) and b.js::h(req), both declared on line 1."""
    vertices, edges = [], []
    for i, f in enumerate(("a.js", "b.js")):
        fid, mid, pid = 100 * i + 1, 100 * i + 2, 100 * i + 3
        vertices += [
            {"id": fid, "label": "FILE", "properties": {"NAME": f}},
            {"id": mid, "label": "METHOD", "properties": {
                "FULL_NAME": f"{f}::h", "NAME": "h", "FILENAME": f, "LINE_NUMBER": 1, "IS_EXTERNAL": False}},
            {"id": pid, "label": "METHOD_PARAMETER_IN", "properties": {
                "NAME": "req", "INDEX": 1, "LINE_NUMBER": 1, "CODE": "req"}},
        ]
        edges += [
            {"label": "AST", "outV": mid, "inV": pid, "outVLabel": "METHOD", "inVLabel": "METHOD_PARAMETER_IN"},
            {"label": "SOURCE_FILE", "outV": mid, "inV": fid, "outVLabel": "METHOD", "inVLabel": "FILE"},
        ]
    return {"vertices": vertices, "edges": edges}


def test_same_name_same_line_in_two_files_are_two_parameters():
    env = joern_adapter.project_graphson(_two_files_same_param(), profile=profiles.GENERIC)
    batch = joern_adapter.normalize(env, "sid")
    params = persist._node_rows(batch.nodes)["CpgParameter"]
    assert len(params) == 2
    assert params[0]["props"]["uid"] != params[1]["props"]["uid"]


@pytest.mark.slow
@pytest.mark.parametrize("repo,flows", [("fixtures/NodeGoat", 217), (PYGOAT, PYGOAT_FLOWS_TO)])
def test_repo_keeps_every_parameter(repo, flows):
    cpg = pygoat_cpg_or_skip() if repo == PYGOAT else f"{repo}/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip(f"{repo} cpg.bin not present")
    env = S.build_envelope(cpg, tempfile.mkdtemp(prefix="orion_param_"), profiles.select_profile(repo))
    declared = sum(n["label"] == "METHOD_PARAMETER_IN" for n in env["nodes"])
    batch = joern_adapter.normalize(env, "sid")
    params = persist._node_rows(batch.nodes)["CpgParameter"]
    assert len(params) == declared, f"{declared} parameters in the CPG became {len(params)} CpgParameter nodes"
    assert sum(e[0] == "FLOWS_TO" for e in batch.edges) == flows
