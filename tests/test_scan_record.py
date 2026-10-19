"""Change 6: every build leaves an (:OrionScan) record; `--scan-id` and `orion gc` trust only it.

Builds here are REAL `graph_build.build` calls into throwaway `test-<uuid>` scans; only Joern is
replaced (by a fixed tiny envelope) because Joern is not what is under test.
"""
from __future__ import annotations

import json

import pytest

from orion import cli, config, graph_build
from orion.graph import joern_adapter, persist, scans
from orion.graphdb import GraphDB


def _envelope() -> dict:
    """a.js: handler(req) calls get() whose value flows into eval()."""
    return {
        "nodes": [
            {"label": "FILE", "id": 1, "props": {"NAME": "a.js"}},
            {"label": "METHOD", "id": 2, "props": {"FULL_NAME": "a.js::handler", "NAME": "handler",
                                                    "IS_EXTERNAL": False, "FILENAME": "a.js", "LINE_NUMBER": 1}},
            {"label": "CALL", "id": 3, "props": {"METHOD_FULL_NAME": "get", "NAME": "get", "CODE": "get()",
                                                  "LINE_NUMBER": 2, "COLUMN_NUMBER": 1, "file_path": "a.js"}},
            {"label": "CALL", "id": 4, "props": {"METHOD_FULL_NAME": "eval", "NAME": "eval", "CODE": "eval(x)",
                                                  "LINE_NUMBER": 3, "COLUMN_NUMBER": 1, "file_path": "a.js"}},
        ],
        "edges": [
            {"label": "CONTAINS", "out": 2, "in": 3, "out_label": "METHOD", "in_label": "CALL"},
            {"label": "CONTAINS", "out": 2, "in": 4, "out_label": "METHOD", "in_label": "CALL"},
            {"label": "SOURCE_FILE", "out": 2, "in": 1, "out_label": "METHOD", "in_label": "FILE"},
            {"label": "FLOWS_TO", "out": 3, "in": 4, "arg_index": 1},
        ],
        "entry_methods": ["a.js::handler"],
    }


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """An Express-looking repo whose Joern export is the tiny envelope above."""
    r = tmp_path / "repo"
    r.mkdir()
    (r / "package.json").write_text(json.dumps({"dependencies": {"express": "4"}}))
    monkeypatch.setattr(joern_adapter, "export_repo", lambda *a, **k: _envelope())
    return str(r)


def _build(repo: str, sid: str) -> str:
    return graph_build.build(repo, "jssrc", stream=False, scan_id=sid)


def test_build_records_building_then_complete(neo4j_driver, scan_ids, repo, monkeypatch):
    sid = scan_ids()
    seen = {}
    real_clear = persist._clear

    def spy(driver, scan_id):
        seen["at_clear"] = scans.get_record(scan_id)
        return real_clear(driver, scan_id)

    monkeypatch.setattr(persist, "_clear", spy)
    _build(repo, sid)
    assert seen["at_clear"] is not None, f"no OrionScan record for {sid} when the clear ran"
    assert seen["at_clear"]["status"] == "building"
    rec = scans.get_record(sid)
    assert rec["status"] == "complete"
    assert rec["profile"] == "express" and rec["commit"] == "nocommit"
    assert rec["orion_version"] and rec["built_at"]
    assert rec["counts"]["edges"]["FLOWS_TO"] == 1 and rec["counts"]["mismatches"] == []


def _scan_rc(monkeypatch, argv, *, refused: bool) -> int:
    """`orion scan` with discovery/verify/embed/model stubbed; the scan-record gate itself is real.
    With `refused`, any discovery call FAILS the test: the gate must stop the scan before it."""
    import orion.discover as discover
    import orion.embed as embed
    import orion.monitor as monitor
    import orion.verify as verify
    from orion.lm import engine

    def found(*a, **k):
        if refused:
            pytest.fail("discovery ran on a scan the gate should have refused")
        return []

    monkeypatch.setattr(discover, "discover", found)
    monkeypatch.setattr(engine, "discover_lm", found)
    monkeypatch.setattr(cli, "_load_lm_model", lambda path: object())
    monkeypatch.setattr(verify, "verify_all", lambda *a, **k: [])
    monkeypatch.setattr(embed, "index", lambda *a, **k: None)
    monkeypatch.setattr(embed, "ensure_exploit_index", lambda *a, **k: False)
    monkeypatch.setattr(monitor, "run_logger", lambda run_dir, quiet=False: (lambda ev: None))
    return cli.main(argv)


def test_crashed_build_stays_building_and_is_refused(neo4j_driver, scan_ids, repo, monkeypatch,
                                                     tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    sid = scan_ids()
    real_run_jobs, calls = persist._run_jobs, []

    def edges_crash(driver, jobs, concurrency):     # fault injection: nodes load, then edges die
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("injected crash while writing edges")
        return real_run_jobs(driver, jobs, concurrency)

    monkeypatch.setattr(persist, "_run_jobs", edges_crash)
    with pytest.raises(RuntimeError, match="injected crash"):
        _build(repo, sid)
    rec = scans.get_record(sid)
    assert rec is not None and rec["status"] == "building"
    capsys.readouterr()
    rc = _scan_rc(monkeypatch, ["scan", "--scan-id", sid, "--quiet"], refused=True)
    assert rc == 2
    assert "incomplete" in capsys.readouterr().err


def test_scan_id_refuses_wrong_profile_and_unrecorded(neo4j_driver, scan_ids, repo, monkeypatch,
                                                     tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    express, lm, bare = scan_ids("express"), scan_ids("lm"), scan_ids("unrecorded")
    for sid, prof in ((express, "express"), (lm, "express+lm")):
        scans.mark_building(sid, commit="nocommit", profile=prof)
        scans.mark_complete(sid, {})
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        s.run("CREATE (:CpgFile {scan_id:$sid, uid:'f', file_path:'a.js'})", sid=bare).consume()
    def rc(*argv, refused=True):
        capsys.readouterr()
        code = _scan_rc(monkeypatch, list(argv), refused=refused)
        return code, capsys.readouterr().err

    code, err = rc("scan", repo, "--scan-id", express, "--engine", "lm", "--model", "/m/x", "--quiet")
    assert code == 2 and "'express+lm'" in err and "orion scan" in err
    code, err = rc("scan", repo, "--scan-id", lm, "--quiet")
    assert code == 2 and "'express'" in err
    code, err = rc("scan", "--scan-id", lm, "--quiet")            # no repo: any lm profile is refused
    assert code == 2 and "lm sinks" in err
    code, err = rc("scan", repo, "--scan-id", bare, "--quiet")
    assert code == 2 and "no OrionScan record" in err and f"orion scan {repo}" in err
    code, _ = rc("scan", repo, "--scan-id", express, "--quiet", refused=False)   # right profile: accepted
    assert code == 0
    code, _ = rc("scan", repo, "--scan-id", lm, "--engine", "lm", "--model", "/m/x", "--quiet", refused=False)
    assert code == 0


def test_scan_record_is_invisible_to_get_schema(neo4j_driver, scan_ids):
    db = GraphDB()
    try:
        before = db.schema()
        with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
            s.run("CREATE (:OrionScan {scan_id:$sid, commit:'c', profile:'express', orion_version:'0', "
                  "status:'complete', built_at:'t', counts:'{}'})", sid=scan_ids()).consume()
        after = db.schema()
    finally:
        db.close()
    labels = {label for row in after["node_properties"] for label in row["nodeLabels"]}
    assert "OrionScan" not in labels, "OrionScan leaked into get_schema"
    assert after == before


def _exists(driver, sid: str) -> bool:
    with driver.session(database=config.NEO4J_DATABASE) as s:
        return s.run("MATCH (n {scan_id:$sid}) RETURN count(n) > 0 AS e", sid=sid).single()["e"]


def test_gc_keeps_newest_and_ignores_others(neo4j_driver, scan_ids, repo, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    old, mid, new = scan_ids("1"), scan_ids("2"), scan_ids("3")
    for sid in (old, mid, new):                   # built in this order -> built_at ascending
        _build(repo, sid)
    bare = scan_ids("unrecorded")
    with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
        s.run("CREATE (:CpgFile {scan_id:$sid, uid:'f', file_path:'a.js'})", sid=bare).consume()
    other = f"test-other-{scan_ids.base[5:]}"     # recorded, but outside the gc prefix
    _build(repo, other)
    try:
        assert cli.main(["gc", "--keep", "1", "--prefix", scan_ids.base, "--dry-run"]) == 0
        assert all(_exists(neo4j_driver, s) for s in (old, mid, new, bare, other))
        assert cli.main(["gc", "--keep", "1", "--prefix", scan_ids.base]) == 0
        assert [_exists(neo4j_driver, s) for s in (old, mid, new, bare, other)] == [False, False, True, True, True]

        # unrecorded scans: refused until listed by a dry run, then deleted once
        assert cli.main(["gc", "--keep", "1", "--prefix", scan_ids.base, "--include-unrecorded"]) == 2
        assert _exists(neo4j_driver, bare)
        assert cli.main(["gc", "--keep", "1", "--prefix", scan_ids.base, "--include-unrecorded",
                         "--dry-run"]) == 0
        assert _exists(neo4j_driver, bare)
        assert cli.main(["gc", "--keep", "1", "--prefix", scan_ids.base, "--include-unrecorded"]) == 0
        assert [_exists(neo4j_driver, s) for s in (new, bare, other)] == [True, False, True]
    finally:
        with neo4j_driver.session(database=config.NEO4J_DATABASE) as s:
            s.run("MATCH (n {scan_id:$sid}) DETACH DELETE n", sid=other).consume()
