"""Change 8: the schema the agents are told about must be the schema the build emits.

`strategies.SCHEMA` (discovery) and `verify._SCHEMA_BLOCK` (verifier) are pre-registered prompt
text, so this test never edits them: it parses every `(:Label {props})` and
`(:A)-[:TYPE {props}]->(:B)` they describe and compares them with a real batch (normalize +
dependencies + reachability/centrality/pathfind), and with NODE_KEY. A drift -- a new property, a
renamed label, an extra node type such as the OrionScan record -- fails here with the difference.

One allowance: OBSERVED_CALL {hits} exists only after a `--runtime` scan (the prompts say so); it is
checked against the runtime writer instead of the static batch.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from orion import strategies, verify
from orion.graph import deps, joern_adapter, pathfind, profiles, reachability
from orion.graph import stream_build as S
from orion.graph.schema import NODE_KEY
from orion.runtime import writeback
from tests.test_stream_build import PYGOAT, pygoat_cpg_or_skip

_NODE = re.compile(r"\(:(\w+)\s*\{([^}]*)\}\)")
_EDGE = re.compile(r"\(:(\w+)\)-\[:(\w+)(?:\s*\{([^}]*)\})?\]->\(:(\w+)\)")
_RUNTIME_ONLY = {("CpgMethod", "OBSERVED_CALL", "CpgMethod"): {"hits"}}


def _names(csv: str | None) -> set[str]:
    return {x.strip() for x in (csv or "").split(",") if x.strip()}


def _described(text: str) -> tuple[dict[str, set], dict[tuple, set]]:
    nodes = {m.group(1): _names(m.group(2)) for m in _NODE.finditer(text)}
    edges = {(m.group(1), m.group(2), m.group(4)): _names(m.group(3)) for m in _EDGE.finditer(text)}
    return nodes, edges


def _emitted(repo: str, cpg: str) -> tuple[dict[str, set], dict[tuple, set]]:
    prof = profiles.select_profile(repo)
    env = S.build_envelope(cpg, tempfile.mkdtemp(prefix="orion_schema_"), prof)
    b = joern_adapter.normalize(env, "schema", language="schema",
                                dependencies=deps.parse_dependencies(repo))
    reachability.tag_reachability(b)
    reachability.tag_centrality(b)
    pathfind.pathfind(b, prof)
    nodes: dict[str, set] = {}
    for label, props in b.nodes:
        nodes.setdefault(label, set()).update(props)
    edges: dict[tuple, set] = {}
    for rtype, fl, _fk, tl, _tk, props in b.edges:
        edges.setdefault((fl, rtype, tl), set()).update(set(props) - {"scan_id"})
    return nodes, edges


@pytest.mark.slow
@pytest.mark.parametrize("repo", ["fixtures/NodeGoat", PYGOAT])
@pytest.mark.parametrize("block", ["strategies.SCHEMA", "verify._SCHEMA_BLOCK"])
def test_prompt_schema_matches_emitted_batch(repo, block):
    cpg = pygoat_cpg_or_skip() if repo == PYGOAT else f"{repo}/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip(f"{repo} cpg.bin not present")
    text = strategies.SCHEMA if block == "strategies.SCHEMA" else verify._SCHEMA_BLOCK
    want_nodes, want_edges = _described(text)
    got_nodes, got_edges = _emitted(repo, cpg)

    assert set(want_nodes) == set(NODE_KEY) == set(got_nodes), (
        f"labels -- {block}: {sorted(want_nodes)}; NODE_KEY: {sorted(NODE_KEY)}; emitted: {sorted(got_nodes)}")
    for label in sorted(NODE_KEY):
        assert set(NODE_KEY[label]) <= got_nodes[label], f"{label} key {NODE_KEY[label]} not emitted"
        assert want_nodes[label] == got_nodes[label], (
            f"{label}: in {block} only {sorted(want_nodes[label] - got_nodes[label])}, "
            f"emitted only {sorted(got_nodes[label] - want_nodes[label])}")

    static = {k: v for k, v in want_edges.items() if k not in _RUNTIME_ONLY}
    assert static == got_edges, f"edges -- {block}: {static}; emitted: {got_edges}"
    for (a, rtype, b), props in _RUNTIME_ONLY.items():
        assert want_edges.get((a, rtype, b)) == props
        assert f"(a)-[:{rtype} {{scan_id:$scan_id, hits:row.hits}}]->(b)" in writeback.CREATE_EDGES
