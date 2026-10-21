"""Change 3: a default and an lm scan of the same commit must get different scan_ids.

`profiles.with_lm_sinks` changes the CandidateFlows pathfind emits, but scan_id was only
abspath|commit, so an lm build cleared and reloaded the default partition (and back). The default
scan's id must stay byte-for-byte what it was.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

import pytest

from orion import cli, config, graph_build
from orion.graph import profiles
from tests.test_cli_engine import _repo, _stub_env


def test_default_scan_id_formula_is_unchanged(tmp_path):
    d = str(tmp_path)    # not a git repo -> commit sentinel 'nocommit'
    expected = hashlib.sha1(f"{os.path.abspath(d)}|nocommit".encode()).hexdigest()
    assert graph_build.scan_id_for(d) == expected
    assert graph_build.scan_id_for(d, profile=profiles.select_profile(d)) == expected


def test_lm_profile_gets_its_own_scan_id(tmp_path):
    d = str(tmp_path)
    lm = profiles.with_lm_sinks(profiles.select_profile(d))
    assert graph_build.scan_id_for(d, profile=lm) != graph_build.scan_id_for(d)


def _scan_id_printed(monkeypatch, capsys, argv) -> str:
    """Run `orion scan` with the build, discovery and model stubbed out and return the printed
    scan_id. graph_build.scan_id_for is the REAL one."""
    from orion.lm import engine
    import orion.discover as discover
    import orion.verify as verify
    monkeypatch.setattr(graph_build, "build", lambda *a, **k: "unused")
    monkeypatch.setattr(discover, "discover", lambda *a, **k: [])
    monkeypatch.setattr(verify, "verify_all", lambda *a, **k: [])
    monkeypatch.setattr(engine, "discover_lm", lambda *a, **k: [])
    monkeypatch.setattr(cli, "_load_lm_model", lambda path: object())
    _stub_env(monkeypatch)
    assert cli.main(argv) == 0
    return next(line.split(": ", 1)[1] for line in capsys.readouterr().out.splitlines()
                if line.startswith("scan_id: "))


def test_cli_prints_different_scan_ids_per_engine(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    repo = _repo(tmp_path)
    claude_sid = _scan_id_printed(monkeypatch, capsys, ["scan", str(repo), "--quiet"])
    lm_sid = _scan_id_printed(monkeypatch, capsys,
                              ["scan", str(repo), "--engine", "lm", "--model", "/m/x", "--quiet"])
    assert claude_sid == hashlib.sha1(f"{os.path.abspath(repo)}|nocommit".encode()).hexdigest()
    assert lm_sid != claude_sid, "same scan_id for both engines"


def _candidate_flows(driver, sid: str) -> int:
    with driver.session(database=config.NEO4J_DATABASE) as s:
        return s.run("MATCH (f:CandidateFlow {scan_id:$sid}) RETURN count(f) AS n", sid=sid).single()["n"]


@pytest.mark.slow
def test_lm_build_leaves_the_default_partition_alone(neo4j_driver, tmp_path):
    """Builds a tmp copy of NodeGoat's cpg.bin + package.json (the real NodeGoat partition is never
    touched), default then lm, and checks the default partition kept its own flows. The two ids
    derive from a fresh tmp path, so they are throwaway; both are deleted at the end."""
    if not Path("fixtures/NodeGoat/cpg.bin").exists():
        pytest.skip("NodeGoat cpg.bin not present")
    repo = tmp_path / "ng"
    repo.mkdir()
    shutil.copy("fixtures/NodeGoat/cpg.bin", repo / "cpg.bin")
    shutil.copy("fixtures/NodeGoat/package.json", repo / "package.json")
    lm = profiles.with_lm_sinks(profiles.select_profile(str(repo)))
    made = []
    try:
        made.append(graph_build.build(str(repo), "jssrc"))
        default_sid = made[0]
        before = _candidate_flows(neo4j_driver, default_sid)
        made.append(graph_build.build(str(repo), "jssrc", profile=lm))
        lm_sid = made[1]
        after = _candidate_flows(neo4j_driver, default_sid)
        assert after == before, f"default partition now has {after} CandidateFlows, expected {before}"
        assert lm_sid != default_sid
        assert _candidate_flows(neo4j_driver, lm_sid) > before
    finally:
        with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
            for sid in set(made):     # ids derived from this test's own tmp path, nothing else
                s.run("MATCH (n {scan_id:$sid}) DETACH DELETE n", sid=sid).consume()
