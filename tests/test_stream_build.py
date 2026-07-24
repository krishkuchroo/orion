import json
from collections import Counter, defaultdict
from itertools import islice
from pathlib import Path
import pytest
from orion.graph import stream_build as S
from orion.graph import taint_summary as T
from orion.graph import joern_adapter as J
from orion.graph import profiles
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


# ─────────────────────────── Task 6: consumer pass-1 structural + property parity ───────────────────────────
def _struct_from_segments(seg_path: Path, profile):
    """Mirror collect_structural's projection over an already-produced segments file, exercising the
    real consumer helpers (_read_preamble/_iter_segments/_structural) without re-running the producer."""
    node_set, edge_ctr = set(), Counter()
    for f in S._read_preamble(str(seg_path))["files"]:
        node_set.add(("FILE", f["id"]))
    it = S._iter_segments(str(seg_path))
    while True:
        batch = list(islice(it, 64))
        if not batch:
            break
        for _, seg in batch:
            nodes, edges = S._structural(seg, profile)
            node_set.update((n["label"], n["id"]) for n in nodes)
            edge_ctr.update((e["label"], e["out"], e["in"]) for e in edges)
    return node_set, edge_ctr


# The property keys the summary/structural passes actually read (spec §5). NAME/FULL_NAME also cover
# IDENTIFIER.NAME and ANNOTATION.FULL_NAME/NAME (both eval repos have 0 ANNOTATION nodes, so that case
# is vacuously covered here; the universal check would catch any divergence on a repo that has them).
_PROP_KEYS = ("ARGUMENT_INDEX", "INDEX", "NAME", "FULL_NAME", "METHOD_FULL_NAME")


def _prod_prop(props: dict, key: str):
    """Read one producer-node property the same way joern_adapter._prop flattens a GraphSON one:
    absent -> None, a singleton list -> its element, else the raw scalar/list."""
    if key not in props:
        return None
    v = props[key]
    if isinstance(v, list):
        return v[0] if len(v) == 1 else (v or None)
    return v


@pytest.mark.slow
def test_stream_structural_parity(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    prof = profiles.select_profile("fixtures/NodeGoat")
    g = _export(cpg)
    legacy = J.project_graphson(g, profile=prof)
    legacy_nodes = {(n["label"], n["id"]) for n in legacy["nodes"]}
    # Structural edge multiset (excludes FLOWS_TO): CONTAINS_CALL + RESOLVES_TO + DEFINED_IN, by ids.
    legacy_struct = Counter((e["label"], e["out"], e["in"])
                            for e in legacy["edges"] if e["label"] != "FLOWS_TO")
    nodes, edges = S.collect_structural(str(cpg), tmp_path, prof)
    assert nodes == legacy_nodes
    assert edges == legacy_struct   # EXACT multiset (RESOLVES_TO now from call_edges, no subset)
    # Guard the fix specifically: RESOLVES_TO (raw label CALL) must be the FULL 2047, not the
    # taint-callsites subset (409). If this ever regresses to callsites, the count drops.
    assert sum(c for (lbl, _, _), c in edges.items() if lbl == "CALL") == 2047


@pytest.mark.slow
@pytest.mark.parametrize("repo", ["fixtures/NodeGoat", "fixtures/PyGoat"])
def test_stream_structural_and_property_parity(tmp_path, repo):
    """Structural node+edge parity (both repos) AND property parity for every summary-read key.
    Runs the producer once per repo and drives the real consumer helpers on its output."""
    cpg = f"{repo}/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip(f"{repo} cpg.bin not present")
    prof = profiles.select_profile(repo)
    out = tmp_path / "segments.jsonl"
    S.run_producer(cpg, str(out))
    g = _export(cpg)
    inner = g["@value"] if "@type" in g else g

    # --- structural node + edge multiset parity, EXACT ---
    legacy = J.project_graphson(g, profile=prof)
    legacy_nodes = {(n["label"], n["id"]) for n in legacy["nodes"]}
    legacy_struct = Counter((e["label"], e["out"], e["in"])
                            for e in legacy["edges"] if e["label"] != "FLOWS_TO")
    nodes, edges = _struct_from_segments(out, prof)
    assert nodes == legacy_nodes
    assert edges == legacy_struct

    # --- property parity: every producer node (preamble FILE + segment vertices) vs legacy _prop ---
    legacy_vert = {J._unwrap(v["id"]): v for v in inner["vertices"]}
    preamble, perfunc = _read_segments(out)
    prod_nodes = list(preamble[0]["files"])
    for seg in perfunc:
        prod_nodes.extend(seg["vertices"])
    for pn in prod_nodes:
        lv = legacy_vert.get(pn["id"])
        assert lv is not None, f"producer node {pn['id']} absent from legacy graph"
        props = pn.get("properties", {})
        for key in _PROP_KEYS:
            assert _prod_prop(props, key) == J._prop(lv, key), (pn["id"], pn["label"], key)


# ─────────────────────────── Task 7: two-pass envelope, FLOWS_TO == 217 end-to-end ───────────────────────────
@pytest.mark.slow
def test_stream_flows_parity(tmp_path):
    cpg = "fixtures/NodeGoat/cpg.bin"
    if not Path(cpg).exists():
        pytest.skip("NodeGoat cpg.bin not present")
    prof = profiles.select_profile("fixtures/NodeGoat")
    env = S.build_envelope(str(cpg), tmp_path, prof)
    flows = [e for e in env["edges"] if e["label"] == "FLOWS_TO"]
    assert len(flows) == 217
    # C.3 fix: entry_methods are full_names (not sorted summary ids) and match legacy exactly.
    legacy = J.project_graphson(_export(cpg), profile=prof)
    assert env["entry_methods"] == legacy["entry_methods"]
