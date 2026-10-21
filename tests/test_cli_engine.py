"""`orion scan --engine lm`: the in-process Orion-LM discovery engine, wired into the CLI.

Token-free and Neo4j-free: the pipeline tests drive `cli.main` with `--scan-id prebuilt` (no graph
build) or a stubbed `graph_build.build`, stub `discover.discover` / `verify.verify_all` /
`lm.engine.discover_lm` / the `cli._load_lm_model` seam, and `_stub_env` replaces the environment
probes (`graphdb.GraphDB`, `embed.index`, `embed.ensure_exploit_index`). Events are captured by
replacing the run-logger factory the scan pulls from `orion.monitor` (cli has no `_emit` seam;
`run_logger` IS the on_event factory, imported lazily inside `_run_scan`).
"""
from __future__ import annotations

import json

import pytest

from orion import cli
from orion.contracts import Lead


def _stub_env(monkeypatch) -> list[dict]:
    """Isolate a `cli.main` run from Neo4j / the embedding model / the exploit corpus and return the
    list every progress event is appended to."""
    import orion.embed as embed
    import orion.graphdb as graphdb
    import orion.monitor as monitor
    from orion.graph import scans

    class _NoDB:
        def __init__(self):
            raise RuntimeError("neo4j stubbed out")

    monkeypatch.setattr(graphdb, "GraphDB", _NoDB)
    monkeypatch.setattr(scans, "check_usable", lambda *a, **k: None)   # the --scan-id record gate
    monkeypatch.setattr(embed, "index", lambda *a, **k: None)
    monkeypatch.setattr(embed, "ensure_exploit_index", lambda *a, **k: False)
    events: list[dict] = []
    monkeypatch.setattr(monitor, "run_logger", lambda run_dir, quiet=False: events.append)
    return events


def _fake_lead() -> Lead:
    return Lead(index=0, shape="LM", text="t", evidence="e", confidence="HIGH", file="a.js", line=1)


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.js").write_text("x\n")
    return repo


# --- parser -------------------------------------------------------------------------------------

def test_engine_defaults_to_claude():
    args = cli._build_parser().parse_args(["scan", "somerepo"])
    assert args.engine == "claude"
    assert args.lm_model is None


def test_engine_lm_parses_model_path():
    args = cli._build_parser().parse_args(["scan", "somerepo", "--engine", "lm", "--model", "/m/orion-lm"])
    assert args.engine == "lm"
    assert args.lm_model == "/m/orion-lm"


def test_engine_rejects_unknown_value():
    with pytest.raises(SystemExit) as exc:
        cli._build_parser().parse_args(["scan", "somerepo", "--engine", "ollama"])
    assert exc.value.code == 2


# --- pre-flight guards (before any heavy import) ------------------------------------------------

def test_lm_engine_without_model_exits_2(monkeypatch, tmp_path, capsys):
    """No default model path exists: --engine lm needs --model, and must fail BEFORE any heavy import."""
    monkeypatch.chdir(tmp_path)
    import orion.graph_build as graph_build
    monkeypatch.setattr(graph_build, "scan_id_for", lambda *a, **k: pytest.fail("reached the pipeline"))
    rc = cli.main(["scan", str(_repo(tmp_path)), "--engine", "lm", "--quiet"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--model" in err and "engine" in err


def test_lm_engine_without_repo_exits_2_even_with_scan_id(monkeypatch, tmp_path, capsys):
    """The repo path is the engine's read_code sandbox; falling back to the CWD (Orion's own checkout)
    is never acceptable, so --scan-id alone is rejected for engine=lm."""
    monkeypatch.chdir(tmp_path)
    import orion.graph_build as graph_build
    monkeypatch.setattr(graph_build, "scan_id_for", lambda *a, **k: pytest.fail("reached the pipeline"))
    rc = cli.main(["scan", "--scan-id", "x", "--engine", "lm", "--model", "m", "--quiet"])
    assert rc == 2
    assert "--engine lm needs the repo path for read_code even with --scan-id" in capsys.readouterr().err


# --- lm pipeline --------------------------------------------------------------------------------

def test_lm_engine_skips_verify_and_wraps_inconclusive(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    repo = _repo(tmp_path)
    import orion.verify as verify, orion.discover as discover
    from orion.lm import engine
    calls = {"verify": 0, "claude": 0, "load": []}
    seen: dict = {}
    monkeypatch.setattr(verify, "verify_all", lambda *a, **k: calls.__setitem__("verify", calls["verify"] + 1) or [])
    monkeypatch.setattr(discover, "discover", lambda *a, **k: calls.__setitem__("claude", calls["claude"] + 1) or [])

    sentinel_model = object()

    def _fake_discover_lm(scan_id, repo_path, on_event, **kw):
        seen.update(scan_id=scan_id, repo_path=repo_path, **kw)
        return [_fake_lead()]

    monkeypatch.setattr(engine, "discover_lm", _fake_discover_lm)
    monkeypatch.setattr(cli, "_load_lm_model", lambda path: calls["load"].append(path) or sentinel_model)  # no MLX in tests
    events = _stub_env(monkeypatch)
    rc = cli.main(["scan", str(repo), "--scan-id", "prebuilt", "--engine", "lm", "--model", "/m/orion-lm",
                   "--quiet", "--json", str(tmp_path / "o.json")])
    assert rc == 0 and calls["verify"] == 0 and calls["claude"] == 0
    assert calls["load"] == ["/m/orion-lm"]
    # discover_lm gets the REPO PATH (the read_code sandbox), never the "." fallback.
    assert seen["scan_id"] == "prebuilt" and seen["repo_path"] == str(repo) and seen["model"] is sentinel_model
    out = json.loads((tmp_path / "o.json").read_text())
    assert out[0]["decision"] == "INCONCLUSIVE" and "engine=lm" in out[0]["reason"]
    assert out[0]["lead"]["shape"] == "LM" and out[0]["lead"]["file"] == "a.js"
    assert any(e.get("phase") == "verify" and "skipped" in (e.get("detail") or "") for e in events)
    # --scan-id no longer warns "used as-is": a scan built without the lm profile is refused by the
    # OrionScan record gate before this point (tests/test_scan_record.py), so nothing to warn about.
    assert not any("as-is" in (e.get("detail") or "") for e in events)
    # Exactly one discover/start on the lm path (model loading folded into it).
    assert [e for e in events if (e["phase"], e["event"]) == ("discover", "start")].__len__() == 1
    # The rendered report and the JSON both carry the lead.
    assert "INCONCLUSIVE" in capsys.readouterr().out


def test_lm_engine_never_imports_claude_cli(monkeypatch, tmp_path):
    """The lm branch must not touch the `claude -p` wrapper at all."""
    import sys
    monkeypatch.chdir(tmp_path)
    import orion.verify as verify, orion.discover as discover
    from orion.lm import engine
    monkeypatch.setattr(verify, "verify_all", lambda *a, **k: pytest.fail("verify_all called"))
    monkeypatch.setattr(discover, "discover", lambda *a, **k: pytest.fail("discover called"))
    monkeypatch.setattr(engine, "discover_lm", lambda *a, **k: [])
    monkeypatch.setattr(cli, "_load_lm_model", lambda path: object())
    _stub_env(monkeypatch)
    monkeypatch.delitem(sys.modules, "orion.claude_cli", raising=False)
    monkeypatch.setitem(sys.modules, "orion.claude_cli", None)   # any import attempt -> ImportError
    rc = cli.main(["scan", str(_repo(tmp_path)), "--scan-id", "prebuilt", "--engine", "lm", "--model", "/m/x", "--quiet"])
    assert rc == 0


# --- build-time sink profile (the headline ruling) ---------------------------------------------

def _stub_build(monkeypatch) -> dict:
    """Stub graph_build.build/scan_id_for and record the kwargs build was called with."""
    import orion.graph_build as graph_build
    captured: dict = {}

    def _build(repo_path, language=None, on_event=None, **kwargs):
        captured.update(kwargs)
        captured["called"] = True
        return "sid"

    monkeypatch.setattr(graph_build, "build", _build)
    monkeypatch.setattr(graph_build, "scan_id_for", lambda repo, profile=None: "sid")
    return captured


def test_lm_engine_builds_with_lm_sink_profile(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    repo = _repo(tmp_path)
    from orion.lm import engine
    seen: dict = {}

    def _fake_discover_lm(scan_id, repo_path, on_event, **kw):
        seen.update(kw)
        return []

    monkeypatch.setattr(engine, "discover_lm", _fake_discover_lm)
    monkeypatch.setattr(cli, "_load_lm_model", lambda path: object())
    _stub_env(monkeypatch)
    captured = _stub_build(monkeypatch)
    rc = cli.main(["scan", str(repo), "--engine", "lm", "--model", "/m/x", "--quiet"])
    assert rc == 0 and captured["called"]
    assert "profile" in captured and captured["profile"].name.endswith("+lm")
    # The very same profile object the graph was built with reaches discovery.
    assert seen["profile"] is captured["profile"]


def test_claude_engine_builds_without_profile_kwarg(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    repo = _repo(tmp_path)
    import orion.verify as verify, orion.discover as discover
    monkeypatch.setattr(discover, "discover", lambda *a, **k: [])
    monkeypatch.setattr(verify, "verify_all", lambda *a, **k: [])
    _stub_env(monkeypatch)
    captured = _stub_build(monkeypatch)
    rc = cli.main(["scan", str(repo), "--quiet"])
    assert rc == 0 and captured["called"]
    assert "profile" not in captured   # build auto-selects, exactly as before


# --- claude path guard --------------------------------------------------------------------------

def test_claude_engine_path_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    import orion.verify as verify, orion.discover as discover
    from orion.lm import engine
    calls = {"verify": 0, "discover": 0}
    order: list[str] = []
    monkeypatch.setattr(discover, "discover",
                        lambda *a, **k: (order.append("discover"), calls.__setitem__("discover", calls["discover"] + 1))
                        and [])
    monkeypatch.setattr(verify, "verify_all",
                        lambda *a, **k: (order.append("verify"), calls.__setitem__("verify", calls["verify"] + 1))
                        and [])
    monkeypatch.setattr(engine, "discover_lm", lambda *a, **k: pytest.fail("discover_lm called on the claude path"))
    monkeypatch.setattr(cli, "_load_lm_model", lambda path: pytest.fail("model loaded on the claude path"))
    events = _stub_env(monkeypatch)
    rc = cli.main(["scan", "--scan-id", "prebuilt", "--quiet"])
    assert rc == 0
    assert calls == {"discover": 1, "verify": 1} and order == ["discover", "verify"]
    # Same events as before: discover start/done then verify start/done, nothing lm-flavoured.
    phases = [(e["phase"], e["event"]) for e in events if e["phase"] in ("discover", "verify") and e["event"] != "warn"]
    assert phases == [("discover", "start"), ("discover", "done"), ("verify", "start"), ("verify", "done")]
    assert not any("engine=lm" in (e.get("detail") or "") for e in events)
