import json
import os
import tempfile

import pytest

from eval import precheck


def _export(files=("pom.xml",)):
    seen = []

    def export(mirror_dir, sha, dest, **kw):
        seen.append((mirror_dir, sha, dest))
        os.makedirs(dest)
        for f in files:
            open(os.path.join(dest, f), "w").write("x")
    return export, seen


def _buildable(tmp_path, builder, **kw):
    export, seen = _export()
    mirrored = []
    res = precheck.buildable("https://github.com/acme/widget", "abc123", mirror_root=str(tmp_path / "m"),
                             builder=builder, tmp_root=str(tmp_path / "tmp"),
                             _mirror=lambda url, d: mirrored.append((url, d)), _export=export, **kw)
    return res, seen, mirrored


def test_buildable_ok_runs_the_builder_on_the_exported_tree_and_deletes_it(tmp_path):
    (tmp_path / "tmp").mkdir()
    trees = []

    def builder(tree):
        trees.append(tree)
        assert os.path.exists(os.path.join(tree, "pom.xml"))     # the exported tree, intact
        return 1234
    res, seen, mirrored = _buildable(tmp_path, builder)
    assert res["ok"] is True and res["nodes"] == 1234 and res["error"] is None
    assert isinstance(res["seconds"], float) and res["seconds"] >= 0
    assert res["stage"] == "build"
    assert mirrored == [("https://github.com/acme/widget", str(tmp_path / "m" / "acme__widget"))]
    assert seen[0][:2] == (str(tmp_path / "m" / "acme__widget"), "abc123")
    assert seen[0][2] == trees[0] and trees[0].startswith(str(tmp_path / "tmp"))
    assert not os.path.exists(trees[0])                          # tree deleted
    assert os.listdir(tmp_path / "tmp") == []                    # and its work dir


def test_buildable_failing_build_is_not_ok_with_its_error_and_measured_seconds(tmp_path):
    (tmp_path / "tmp").mkdir()
    trees = []

    def builder(tree):
        trees.append(tree)
        raise RuntimeError("joern-parse failed (rc=137): java.lang.OutOfMemoryError")
    res, _, _ = _buildable(tmp_path, builder)
    assert res["ok"] is False and res["stage"] == "build"
    assert "OutOfMemoryError" in res["error"]
    assert res["nodes"] is None                                  # nothing measured, nothing invented
    assert isinstance(res["seconds"], float)                     # time until it failed is measured
    assert not os.path.exists(trees[0])


def test_buildable_export_failure_is_not_a_build_failure(tmp_path):
    (tmp_path / "tmp").mkdir()

    def export(*a, **k):
        raise RuntimeError("fatal: not a valid object name abc123")
    res = precheck.buildable("https://github.com/acme/widget", "abc123", mirror_root=str(tmp_path / "m"),
                             builder=lambda t: pytest.fail("built"), tmp_root=str(tmp_path / "tmp"),
                             _mirror=lambda *a: None, _export=export)
    assert res == {"ok": False, "seconds": None, "nodes": None, "stage": "export",
                   "error": "RuntimeError: fatal: not a valid object name abc123"}
    assert os.listdir(tmp_path / "tmp") == []


def test_buildable_refuses_a_tree_under_a_repo(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "tmp").mkdir()
    res, _, _ = _buildable(tmp_path, lambda t: pytest.fail("built"))
    assert res["ok"] is False and res["stage"] == "setup" and ".git" in res["error"]


def test_mirror_dir_is_one_per_repo_url():
    assert precheck.mirror_dir_for("https://github.com/Apache/airflow.git", "/m") == "/m/Apache__airflow"
    assert precheck.mirror_dir_for("https://github.com/apache/airflow", "/m") == "/m/apache__airflow"




# ---- machine failures are never build failures (fix round 1) -------------------------------------

@pytest.mark.parametrize("make", [
    lambda: __import__("neo4j.exceptions", fromlist=["x"]).ServiceUnavailable("Couldn't connect to localhost:7688"),
    lambda: __import__("neo4j.exceptions", fromlist=["x"]).SessionExpired("connection dropped"),
    lambda: __import__("neo4j.exceptions", fromlist=["x"]).AuthError("unauthorized"),
    lambda: precheck.InfraError("Joern binaries not found: /j/joern-parse"),
    lambda: FileNotFoundError(2, "No such file or directory", "/home/k/joern/joern-cli/joern"),
])
def test_a_machine_failure_inside_the_build_is_setup_not_build(tmp_path, make):
    (tmp_path / "tmp").mkdir()

    def builder(tree):
        raise make()
    res, _, _ = _buildable(tmp_path, builder)
    assert res["ok"] is False and res["stage"] == "setup"


def test_a_wrapped_neo4j_failure_is_still_setup(tmp_path):
    from neo4j.exceptions import ServiceUnavailable
    (tmp_path / "tmp").mkdir()

    def builder(tree):
        try:
            raise ServiceUnavailable("bolt connection lost")
        except ServiceUnavailable as e:
            raise RuntimeError("persist failed") from e
    res, _, _ = _buildable(tmp_path, builder)
    assert res["stage"] == "setup"


# ---- the default builder -------------------------------------------------------------------------

def _default_builder_seams(monkeypatch, *, record, pathfind_error=None, build=None):
    """The default builder over eval.lmbuild.lm_build with Orion's own build (lmbuild._orion_build)
    and the Joern check stubbed: lm_build's heap/temp pinning runs for real."""
    from orion.graph import scans
    from eval import infra, lmbuild
    from eval.arms import lm
    seen = {}
    monkeypatch.setattr(lmbuild, "_orion_build", build or (lambda tree, on_event: "sid1"))
    monkeypatch.setattr(scans, "get_record", lambda sid: record)
    monkeypatch.setattr(lm, "_pathfind_error", lambda sid: pathfind_error)
    monkeypatch.setattr(precheck, "_drop_scan", lambda sid: seen.setdefault("dropped", sid))
    monkeypatch.setattr(infra, "joern_missing", lambda: [])
    return seen


def test_default_builder_pins_the_joern_heap_keeps_temp_files_in_the_work_dir_and_cleans_up(tmp_path,
                                                                                              monkeypatch):
    from orion import config
    seen = {}
    tree = tmp_path / "work" / "tree"
    tree.mkdir(parents=True)

    def fake_build(repo_dir, on_event):
        seen["heap"] = config.JOERN_HEAP_GB
        seen["tmp"] = tempfile.mkdtemp(prefix="orion_cpg_")
        on_event({"phase": "build", "event": "timing", "detail": "persist: 1.0s"})
        return "sid1"
    seams = _default_builder_seams(monkeypatch, build=fake_build,
                                   record={"counts": {"nodes": {"CpgCall": 7, "CpgMethod": 3}}})
    before = (config.JOERN_HEAP_GB, tempfile.tempdir)
    assert precheck.lm_graph_build(str(tree)) == 10
    assert seen["heap"] == "8"
    assert seen["tmp"].startswith(str(tmp_path / "work"))         # Joern's temp files die with the tree
    assert seams["dropped"] == "sid1"                             # Neo4j partition deleted
    assert (config.JOERN_HEAP_GB, tempfile.tempdir) == before     # restored


def test_default_builder_reports_unknown_nodes_as_none(tmp_path, monkeypatch):
    tree = tmp_path / "work" / "tree"
    tree.mkdir(parents=True)
    _default_builder_seams(monkeypatch, record={"status": "complete"})
    assert precheck.lm_graph_build(str(tree)) is None


def test_a_commit_whose_pathfind_failed_is_a_build_failure(tmp_path, monkeypatch):
    (tmp_path / "tmp").mkdir()
    seams = _default_builder_seams(monkeypatch, record={"counts": {"nodes": {"CpgCall": 5}}},
                                   pathfind_error="RecursionError: maximum recursion depth exceeded")
    res, _, _ = _buildable(tmp_path, None)                        # the default builder
    assert res["ok"] is False and res["stage"] == "build"         # a real failure of this commit
    assert "pathfind failed: RecursionError" in res["error"]
    assert res["nodes"] == 5                                      # the graph exists: measured, kept
    assert seams["dropped"] == "sid1"


def test_default_builder_with_joern_missing_is_a_machine_failure(tmp_path, monkeypatch):
    from eval import infra
    (tmp_path / "tmp").mkdir()
    _default_builder_seams(monkeypatch, record=None)
    monkeypatch.setattr(infra, "joern_missing", lambda: ["/j/joern-parse"])
    res, _, _ = _buildable(tmp_path, None)
    assert res["stage"] == "setup" and "joern-parse" in res["error"]


# ---- the CLI -------------------------------------------------------------------------------------

ROWS = [
    {"id": "CVE-1", "repo_url": "https://github.com/a/one", "tier": "headline",
     "vulnerable_commit": "v1", "patched_commit": "p1"},
    {"id": "CVE-2", "repo_url": "https://github.com/a/two", "tier": "headline",
     "vulnerable_commit": "v2", "patched_commit": "p2"},
    {"id": "CVE-3", "repo_url": "https://github.com/a/three", "tier": "headline",
     "vulnerable_commit": "v3", "patched_commit": "p3"},
]


def _ok(seconds=1.5, nodes=100):
    return {"ok": True, "seconds": seconds, "nodes": nodes, "error": None, "stage": "build"}


OUTCOMES = {
    "v1": _ok(), "p1": _ok(),
    "v2": _ok(), "p2": {"ok": False, "seconds": 9.0, "nodes": None, "error": "OOM", "stage": "build"},
    "v3": {"ok": False, "seconds": None, "nodes": None, "error": "no such commit", "stage": "export"},
    "p3": _ok(),
}


def _manifest(tmp_path):
    man = tmp_path / "manifest.json"
    if not man.exists():
        man.write_text(json.dumps({"version": 2, "repos": [dict(r) for r in ROWS]}, indent=1) + "\n")
    return man


def _cli(tmp_path, monkeypatch, *args, outcomes=OUTCOMES, preflight=()):
    man = _manifest(tmp_path)
    calls = []

    def fake(repo_url, sha, **kw):
        calls.append((repo_url, sha))
        return dict(outcomes[sha])
    monkeypatch.setattr(precheck, "buildable", fake)
    monkeypatch.setattr(precheck, "_orion_commit", lambda: "deadbeef")
    monkeypatch.setattr(precheck, "_preflight", lambda: list(preflight))
    rc = precheck.main(["--manifest", str(man), *args])
    report = tmp_path / "precheck_report.json"
    return rc, json.loads(man.read_text()), calls, (json.loads(report.read_text()) if report.exists() else None)


def test_cli_checks_both_commits_and_a_dry_run_leaves_the_manifest_untouched(tmp_path, monkeypatch):
    man = _manifest(tmp_path)
    before = man.read_bytes()
    rc, data, calls, report = _cli(tmp_path, monkeypatch)
    assert rc == 0
    assert calls == [("https://github.com/a/one", "v1"), ("https://github.com/a/one", "p1"),
                     ("https://github.com/a/two", "v2"), ("https://github.com/a/two", "p2"),
                     ("https://github.com/a/three", "v3"), ("https://github.com/a/three", "p3")]
    assert man.read_bytes() == before                                  # truly dry
    one, two, three = (report["rows"][k] for k in ("CVE-1", "CVE-2", "CVE-3"))
    assert one["result"] == "ok" and one["vulnerable"] == dict(_ok(), sha="v1")
    assert one["joern_heap_gb"] == 8 and one["orion_commit"] == "deadbeef"
    assert two["result"] == "build_failed" and two["patched"]["error"] == "OOM"
    assert three["result"] == "not_checked"


def test_cli_write_moves_only_rows_whose_build_failed_on_either_commit(tmp_path, monkeypatch):
    rc, data, _, report = _cli(tmp_path, monkeypatch, "--write")
    assert rc == 0
    one, two, three = data["repos"]
    assert one["tier"] == "headline" and one["precheck"]["result"] == "ok"
    assert two["tier"] == "scale" and two["precheck"]["tier_before"] == "headline"
    assert three["tier"] == "headline" and three["precheck"]["result"] == "not_checked"   # never moved
    assert data["version"] == 2 and set(report["rows"]) == {"CVE-1", "CVE-2", "CVE-3"}


def test_cli_a_machine_failure_never_moves_a_row(tmp_path, monkeypatch):
    down = {"ok": False, "seconds": 0.2, "nodes": None, "stage": "setup",
            "error": "ServiceUnavailable: Couldn't connect to localhost:7688"}
    rc, data, _, _ = _cli(tmp_path, monkeypatch, "--write", outcomes={k: dict(down) for k in OUTCOMES})
    assert rc == 0
    assert [r["tier"] for r in data["repos"]] == ["headline"] * 3
    assert {r["precheck"]["result"] for r in data["repos"]} == {"not_checked"}


def test_cli_a_failing_preflight_writes_nothing(tmp_path, monkeypatch, capsys):
    man = _manifest(tmp_path)
    before = man.read_bytes()
    rc, _, calls, report = _cli(tmp_path, monkeypatch, "--write",
                                preflight=["Neo4j at bolt://localhost:7688 is not usable: ServiceUnavailable"])
    assert rc == 1 and calls == [] and report is None
    assert man.read_bytes() == before
    assert "not usable" in capsys.readouterr().out


def test_cli_a_rerun_keeps_the_move_and_the_first_failure(tmp_path, monkeypatch):
    rc, _, _, _ = _cli(tmp_path, monkeypatch, "--write")
    assert rc == 0
    healed = dict(OUTCOMES, p2=_ok(seconds=3.0))                       # the second run builds CVE-2 fine
    rc, data, _, report = _cli(tmp_path, monkeypatch, "--write", outcomes=healed)
    assert rc == 0
    two = data["repos"][1]
    assert two["tier"] == "scale"                                       # never silently restored
    assert two["precheck"]["result"] == "ok"
    assert two["precheck"]["tier_before"] == "headline"                 # carried forward
    (first,) = two["precheck"]["history"]
    assert first["result"] == "build_failed" and first["patched"]["error"] == "OOM"
    assert [h["result"] for h in report["rows"]["CVE-2"]["history"]] == ["build_failed"]


def test_cli_id_filter_checks_and_moves_only_the_named_rows(tmp_path, monkeypatch):
    rc, data, calls, report = _cli(tmp_path, monkeypatch, "--write", "--id", "CVE-1")
    assert rc == 0 and [sha for _, sha in calls] == ["v1", "p1"]
    one, two, three = data["repos"]
    assert "precheck" in one and "precheck" not in two and "precheck" not in three
    assert two["tier"] == "headline"              # never moved: it was not checked
    assert set(report["rows"]) == {"CVE-1"}


def test_cli_refuses_an_unknown_id(tmp_path, monkeypatch, capsys):
    rc, _, calls, _ = _cli(tmp_path, monkeypatch, "--id", "CVE-9")
    assert rc == 2 and calls == [] and "CVE-9" in capsys.readouterr().out


def test_preflight_reports_neo4j_down_and_missing_joern(monkeypatch):
    import neo4j
    from neo4j.exceptions import ServiceUnavailable

    class Driver:
        def session(self, **kw):
            raise ServiceUnavailable("Couldn't connect to localhost:7688")

        def close(self):
            pass
    monkeypatch.setattr(neo4j.GraphDatabase, "driver", lambda *a, **k: Driver())
    monkeypatch.setattr(precheck, "_joern_missing", lambda: ["/j/joern"])
    problems = precheck._preflight()
    assert any("Joern" in p for p in problems) and any("ServiceUnavailable" in p for p in problems)
