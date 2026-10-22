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


def test_default_builder_pins_the_joern_heap_keeps_temp_files_in_the_work_dir_and_cleans_up(tmp_path,
                                                                                              monkeypatch):
    from orion import config
    from orion.graph import scans
    from eval.arms import lm
    seen = {}
    tree = tmp_path / "work" / "tree"
    tree.mkdir(parents=True)

    def fake_build(repo_dir, on_event):
        seen["heap"] = config.JOERN_HEAP_GB
        seen["tmp"] = tempfile.mkdtemp(prefix="orion_cpg_")
        on_event({"phase": "build", "event": "timing", "detail": "persist: 1.0s"})
        return "sid1"
    monkeypatch.setattr(lm, "_build_graph", fake_build)
    monkeypatch.setattr(scans, "get_record", lambda sid: {"counts": {"nodes": {"CpgCall": 7, "CpgMethod": 3}}})
    monkeypatch.setattr(precheck, "_drop_scan", lambda sid: seen.setdefault("dropped", sid))
    before = (config.JOERN_HEAP_GB, tempfile.tempdir)
    assert precheck.lm_graph_build(str(tree)) == 10
    assert seen["heap"] == "8"
    assert seen["tmp"].startswith(str(tmp_path / "work"))         # Joern's temp files die with the tree
    assert seen["dropped"] == "sid1"                              # Neo4j partition deleted
    assert (config.JOERN_HEAP_GB, tempfile.tempdir) == before     # restored


def test_default_builder_reports_unknown_nodes_as_none(tmp_path, monkeypatch):
    from orion.graph import scans
    from eval.arms import lm
    tree = tmp_path / "work" / "tree"
    tree.mkdir(parents=True)
    monkeypatch.setattr(lm, "_build_graph", lambda repo_dir, on_event: "sid1")
    monkeypatch.setattr(scans, "get_record", lambda sid: None)
    monkeypatch.setattr(precheck, "_drop_scan", lambda sid: None)
    assert precheck.lm_graph_build(str(tree)) is None


# ---- the CLI -----------------------------------------------------------------------------------

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


def _cli(tmp_path, monkeypatch, *args):
    man = tmp_path / "manifest.json"
    man.write_text(json.dumps({"version": 2, "repos": [dict(r) for r in ROWS]}, indent=1) + "\n")
    calls = []

    def fake(repo_url, sha, **kw):
        calls.append((repo_url, sha))
        return dict(OUTCOMES[sha])
    monkeypatch.setattr(precheck, "buildable", fake)
    monkeypatch.setattr(precheck, "_orion_commit", lambda: "deadbeef")
    rc = precheck.main(["--manifest", str(man), *args])
    return rc, json.loads(man.read_text()), calls


def test_cli_checks_both_commits_of_every_row_and_writes_a_record_per_row(tmp_path, monkeypatch):
    rc, data, calls = _cli(tmp_path, monkeypatch)
    assert rc == 0
    assert calls == [("https://github.com/a/one", "v1"), ("https://github.com/a/one", "p1"),
                     ("https://github.com/a/two", "v2"), ("https://github.com/a/two", "p2"),
                     ("https://github.com/a/three", "v3"), ("https://github.com/a/three", "p3")]
    one, two, three = data["repos"]
    assert one["precheck"]["result"] == "ok"
    assert one["precheck"]["vulnerable"] == dict(_ok(), sha="v1")
    assert one["precheck"]["joern_heap_gb"] == 8 and one["precheck"]["orion_commit"] == "deadbeef"
    assert two["precheck"]["result"] == "build_failed"
    assert two["precheck"]["patched"]["error"] == "OOM"
    assert three["precheck"]["result"] == "not_checked"
    assert [r["tier"] for r in data["repos"]] == ["headline"] * 3   # no --write: no tier moves
    assert data["version"] == 2                                        # rest of the file kept


def test_cli_write_moves_only_rows_whose_build_failed_on_either_commit(tmp_path, monkeypatch):
    rc, data, _ = _cli(tmp_path, monkeypatch, "--write")
    assert rc == 0
    one, two, three = data["repos"]
    assert one["tier"] == "headline"
    assert two["tier"] == "scale" and two["precheck"]["tier_before"] == "headline"
    assert three["tier"] == "headline"            # export failed: not checked, never moved


def test_cli_id_filter_checks_and_moves_only_the_named_rows(tmp_path, monkeypatch):
    rc, data, calls = _cli(tmp_path, monkeypatch, "--write", "--id", "CVE-1")
    assert rc == 0 and [sha for _, sha in calls] == ["v1", "p1"]
    one, two, three = data["repos"]
    assert "precheck" in one and "precheck" not in two and "precheck" not in three
    assert two["tier"] == "headline"              # never moved: it was not checked


def test_cli_refuses_an_unknown_id(tmp_path, monkeypatch, capsys):
    rc, _, calls = _cli(tmp_path, monkeypatch, "--id", "CVE-9")
    assert rc == 2 and calls == [] and "CVE-9" in capsys.readouterr().out
