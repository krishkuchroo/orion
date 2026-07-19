"""Pure, DB-free tests for repo language detection + the ambiguous-repo warning.

joern_adapter's marker detection and graph_build's ambiguity warning are plain file-existence
logic -- no Joern, no Neo4j -- so these run anywhere. They pin the fix for the language-detection
gap: a repo is no longer force-guessed JS-or-Python by a single `package.json` check. Every backend
marker (go.mod / pom.xml / requirements) is recognised, a polyglot repo is flagged rather than
silently scanned, and `orion scan --language` can override the guess.
"""
from __future__ import annotations

from orion.graph.joern_adapter import _guess_language, detect_language_markers, resolve_language
from orion.graph_build import _ambiguity_warning


def test_go_module_detected(tmp_path):
    # 'golang' is Joern's actual --language id for Go (NOT 'gosrc' -- verified against
    # `joern-parse --list-languages`); an id Joern rejects would fail the build instantly.
    (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.21\n")
    assert detect_language_markers(tmp_path) == [("go.mod", "golang")]


def test_maven_project_detected(tmp_path):
    (tmp_path / "pom.xml").write_text("<project></project>\n")
    assert detect_language_markers(tmp_path) == [("pom.xml", "javasrc")]


def test_python_requirements_detected(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    assert detect_language_markers(tmp_path) == [("requirements.txt", "pythonsrc")]


def test_python_pyproject_detected(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    assert detect_language_markers(tmp_path) == [("pyproject.toml", "pythonsrc")]


def test_node_package_detected(tmp_path):
    (tmp_path / "package.json").write_text("{}\n")
    assert detect_language_markers(tmp_path) == [("package.json", "jssrc")]


def test_no_marker_is_empty(tmp_path):
    assert detect_language_markers(tmp_path) == []


def test_polyglot_lists_all_markers_backend_before_js(tmp_path):
    # A Go backend that also ships a package.json for frontend/build tooling: BOTH are real markers,
    # and the JS one (most likely to be mere tooling) must sort AFTER the backend marker so the
    # guess prefers Go.
    (tmp_path / "package.json").write_text("{}\n")
    (tmp_path / "go.mod").write_text("module x\n")
    assert detect_language_markers(tmp_path) == [("go.mod", "golang"), ("package.json", "jssrc")]


def test_guess_prefers_backend_over_js(tmp_path):
    # The exact regression the gap analysis named: a Django app carrying a small package.json must
    # be scanned as Python, not silently as JavaScript.
    (tmp_path / "package.json").write_text("{}\n")
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    assert _guess_language(tmp_path) == "pythonsrc"


def test_guess_pure_js_unchanged(tmp_path):
    # No regression for the NodeGoat-style single-marker JS repo (the sacred 14/15 benchmark).
    (tmp_path / "package.json").write_text("{}\n")
    assert _guess_language(tmp_path) == "jssrc"


def test_guess_fallback_is_python(tmp_path):
    # A repo with no recognised marker keeps the historical python default.
    assert _guess_language(tmp_path) == "pythonsrc"


def test_explicit_language_overrides_detection(tmp_path):
    # `--language` wins over whatever the repo looks like: a package.json repo forced to golang.
    (tmp_path / "package.json").write_text("{}\n")
    assert resolve_language(tmp_path, "golang") == ("golang", "go")


def test_ambiguity_warning_fires_on_polyglot(tmp_path):
    (tmp_path / "package.json").write_text("{}\n")
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    evt = _ambiguity_warning(str(tmp_path), None, "pythonsrc")
    assert evt is not None
    assert evt["event"] == "warn"
    assert evt["phase"] == "build"
    # Names both markers found and points at the override.
    assert "package.json" in evt["detail"] and "requirements.txt" in evt["detail"]
    assert "--language" in evt["detail"]


def test_ambiguity_warning_silent_on_single_marker(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    assert _ambiguity_warning(str(tmp_path), None, "pythonsrc") is None


def test_ambiguity_warning_suppressed_by_explicit_language(tmp_path):
    # If the user pinned --language, they've already decided -- no second-guessing warning.
    (tmp_path / "package.json").write_text("{}\n")
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    assert _ambiguity_warning(str(tmp_path), "jssrc", "jssrc") is None
