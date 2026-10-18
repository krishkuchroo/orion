"""`orion scan --engine lm`: the in-process Orion-LM discovery engine, wired into the CLI.

Token-free and Neo4j-free: every test drives `cli.main` with `--scan-id prebuilt` (no graph build),
stubs `discover.discover` / `verify.verify_all` / `lm.engine.discover_lm` / the `cli._load_lm_model`
seam, and the `_pipeline` node-count probe is already wrapped in a try/except that warns and
continues when Neo4j is down. Events are captured by replacing the run-logger factory the scan
pulls from `orion.monitor` (cli has no `_emit` seam; `run_logger` IS the on_event factory).
"""
from __future__ import annotations

import json

import pytest

from orion import cli
from orion.contracts import Lead


def _capture_events(monkeypatch) -> list[dict]:
    import orion.monitor as monitor
    events: list[dict] = []
    monkeypatch.setattr(monitor, "run_logger", lambda run_dir, quiet=False: events.append)
    return events


def _fake_lead() -> Lead:
    return Lead(index=0, shape="LM", text="t", evidence="e", confidence="HIGH", file="a.js", line=1)


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


def test_lm_engine_without_model_exits_2(monkeypatch, tmp_path, capsys):
    """No default model path exists: --engine lm needs --model, and must fail BEFORE any heavy import."""
    monkeypatch.chdir(tmp_path)
    import orion.graph_build as graph_build
    monkeypatch.setattr(graph_build, "scan_id_for", lambda *a, **k: pytest.fail("reached the pipeline"))
    rc = cli.main(["scan", "--scan-id", "prebuilt", "--engine", "lm", "--quiet"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--model" in err and "engine" in err


def test_lm_engine_skips_verify_and_wraps_inconclusive(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
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
    events = _capture_events(monkeypatch)
    rc = cli.main(["scan", "--scan-id", "prebuilt", "--engine", "lm", "--model", "/m/orion-lm",
                   "--quiet", "--json", str(tmp_path / "o.json")])
    assert rc == 0 and calls["verify"] == 0 and calls["claude"] == 0
    assert calls["load"] == ["/m/orion-lm"]
    assert seen["scan_id"] == "prebuilt" and seen["model"] is sentinel_model
    out = json.loads((tmp_path / "o.json").read_text())
    assert out[0]["decision"] == "INCONCLUSIVE" and "engine=lm" in out[0]["reason"]
    assert out[0]["lead"]["shape"] == "LM" and out[0]["lead"]["file"] == "a.js"
    assert any(e.get("phase") == "verify" and "skipped" in (e.get("detail") or "") for e in events)
    # --scan-id: the prebuilt graph is used as-is (no lm sink profile at build time) and says so.
    assert any(e.get("phase") == "discover" and e.get("event") == "warn"
               and "as-is" in (e.get("detail") or "") for e in events)
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
    _capture_events(monkeypatch)
    monkeypatch.delitem(sys.modules, "orion.claude_cli", raising=False)
    monkeypatch.setitem(sys.modules, "orion.claude_cli", None)   # any import attempt -> ImportError
    rc = cli.main(["scan", "--scan-id", "prebuilt", "--engine", "lm", "--model", "/m/x", "--quiet"])
    assert rc == 0


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
    events = _capture_events(monkeypatch)
    rc = cli.main(["scan", "--scan-id", "prebuilt", "--quiet"])
    assert rc == 0
    assert calls == {"discover": 1, "verify": 1} and order == ["discover", "verify"]
    # Same events as before: discover start/done then verify start/done, nothing lm-flavoured.
    phases = [(e["phase"], e["event"]) for e in events if e["phase"] in ("discover", "verify") and e["event"] != "warn"]
    assert phases == [("discover", "start"), ("discover", "done"), ("verify", "start"), ("verify", "done")]
    assert not any("engine=lm" in (e.get("detail") or "") for e in events)
