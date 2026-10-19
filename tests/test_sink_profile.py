"""Opt-in extended sink hints (LM profile) layered on any profile + build(profile=). Token-free."""
from types import SimpleNamespace

from orion import graph_build
from orion.graph import pathfind, profiles


def test_with_lm_sinks_keeps_sources_and_adds_categories():
    for base in (profiles.EXPRESS, profiles.GENERIC):
        lm = profiles.with_lm_sinks(base)
        assert lm.name == base.name + "+lm"
        assert {"path", "ssrf", "xxe", "template", "deserialize", "prototype_pollution"} <= set(lm.sink_hints)
        assert set(base.sink_hints) <= set(lm.sink_hints)
        assert lm.request_source_names == base.request_source_names
        assert lm.entrypoint_params_are_sources == base.entrypoint_params_are_sources
        for k, v in base.sink_hints.items():  # base categories win on a clash
            assert lm.sink_hints[k] == v


def test_with_lm_sinks_does_not_mutate_base():
    before = dict(profiles.GENERIC.sink_hints)
    profiles.with_lm_sinks(profiles.GENERIC)
    assert profiles.GENERIC.sink_hints == before
    assert "path" not in profiles.GENERIC.sink_hints


def test_classify_sink_finds_a_path_traversal_sink():
    props = {"name": "readFileSync", "code": "fs.readFileSync(userPath)"}
    assert pathfind._classify_sink(props, profiles.with_lm_sinks(profiles.GENERIC)) == "path"
    assert pathfind._classify_sink(props, profiles.GENERIC) != "path"


def test_new_categories_have_explicit_severity():
    for c in ("path", "template", "ssrf", "xxe", "prototype_pollution"):
        assert c in pathfind._SINK_SEVERITY


def _stub_build(monkeypatch, tmp_path, select_calls, pathfind_seen):
    def fake_select(repo, lang=None):
        select_calls.append(repo)
        return profiles.GENERIC

    monkeypatch.setattr(graph_build.profiles, "select_profile", fake_select)
    monkeypatch.setattr(graph_build.joern_adapter, "resolve_language", lambda r, l: ("jssrc", "javascript"))
    monkeypatch.setattr(graph_build.joern_adapter, "export_repo", lambda r, f, p: {})
    batch = SimpleNamespace(nodes=[], edges=[])
    monkeypatch.setattr(graph_build.joern_adapter, "normalize", lambda *a, **k: batch)
    monkeypatch.setattr(graph_build.deps, "parse_dependencies", lambda r: [])
    monkeypatch.setattr(graph_build.reachability, "tag_reachability",
                        lambda b: {"reached_methods": 0, "total_methods": 0, "reached_calls": 0, "total_calls": 0})
    monkeypatch.setattr(graph_build.reachability, "tag_centrality",
                        lambda b: {"nodes": 0, "max_centrality": 0.0})

    def fake_pathfind(b, profile):
        pathfind_seen.append(profile)
        return {"flows": 0, "sources": 0, "sinks": 0}

    monkeypatch.setattr(graph_build.pathfind, "pathfind", fake_pathfind)
    monkeypatch.setattr(graph_build.persist, "persist", lambda b: {})
    monkeypatch.setattr(graph_build.scans, "mark_building", lambda *a, **k: None)   # no Neo4j here
    monkeypatch.setattr(graph_build.scans, "mark_complete", lambda *a, **k: None)
    monkeypatch.setattr(graph_build, "_ambiguity_warning", lambda *a, **k: None)


def test_build_accepts_explicit_profile(monkeypatch, tmp_path):
    select_calls, seen = [], []
    _stub_build(monkeypatch, tmp_path, select_calls, seen)
    lm = profiles.with_lm_sinks(profiles.EXPRESS)
    sid = graph_build.build(str(tmp_path), profile=lm)
    assert seen == [lm]
    # select_profile is consulted only to NAME the scan: a non-default profile gets its own scan_id
    # (it changes the CandidateFlows); the build itself runs on the explicit profile.
    assert sid == graph_build.scan_id_for(str(tmp_path), profile=lm) != graph_build.scan_id_for(str(tmp_path))


def test_build_without_profile_still_selects(monkeypatch, tmp_path):
    select_calls, seen = [], []
    _stub_build(monkeypatch, tmp_path, select_calls, seen)
    graph_build.build(str(tmp_path))
    assert len(select_calls) == 1
    assert seen == [profiles.GENERIC]
