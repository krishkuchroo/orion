"""CLI pre-flight guards: a missing/absent repo path (e.g. after a failed `git clone`) must fail
fast with a clean message and exit code 2 -- NOT reach joern-parse and surface a Java AssertionError
stack trace that reads like an Orion crash. Token-free: the guard runs before any heavy import, so
no Neo4j, no joern, no embedding model, no `claude` subprocess.
"""
from __future__ import annotations

from orion import cli


def test_missing_repo_path_exits_2_cleanly(capsys):
    rc = cli.main(["scan", "/no/such/path/orion-does-not-exist-xyzzy"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "repo path not found" in err
    assert "orion-does-not-exist-xyzzy" in err


def test_file_instead_of_dir_exits_2(tmp_path, capsys):
    # A path that exists but is a FILE (not a repo directory) is also rejected.
    f = tmp_path / "not-a-repo.txt"
    f.write_text("hi")
    rc = cli.main(["scan", str(f)])
    assert rc == 2
    assert "not found or not a directory" in capsys.readouterr().err


def test_no_repo_and_no_scan_id_exits_2(capsys):
    rc = cli.main(["scan"])
    assert rc == 2
    assert "provide a repo path or --scan-id" in capsys.readouterr().err


def test_existing_dir_passes_the_guard(tmp_path, monkeypatch, capsys):
    """A real directory clears the path guard and proceeds past it. We stub _run_scan's body by
    intercepting the first heavy step so the test stays token-free -- the point is only that the
    guard did NOT reject a valid directory."""
    import orion.graph_build as graph_build

    def _boom(*a, **k):
        raise RuntimeError("reached-build")  # proves we passed the guard into the pipeline

    monkeypatch.setattr(graph_build, "scan_id_for", _boom)
    try:
        cli.main(["scan", str(tmp_path)])
    except RuntimeError as exc:
        assert "reached-build" in str(exc)
    else:
        raise AssertionError("guard should have passed a valid dir through to the build path")
    # crucially, it did NOT print the path-guard rejection
    assert "repo path not found" not in capsys.readouterr().err
