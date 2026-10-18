from eval import preflight


def test_check_marks_missing_tools_without_raising():
    def run(cmd):
        if cmd[0] == "codex":
            raise FileNotFoundError("codex")
        return "ok"
    rows = preflight.check(run=run)
    codex = [r for r in rows if r["tool"] == "codex"][0]
    assert codex["ok"] is False
    assert any(r["ok"] for r in rows)


def test_render_flags_missing():
    rows = [{"tool": "codex", "ok": False, "detail": "not found"},
            {"tool": "claude", "ok": True, "detail": "2.1.210"}]
    out = preflight.render(rows)
    assert "MISSING: codex" in out


def test_checks_cover_the_model_clis_and_graph_stack_without_ollama():
    tools = [t for t, _ in preflight._CHECKS]
    assert "ollama" not in tools and "ollama-serve" not in tools
    for t in ("claude", "codex", "docker", "joern", "neo4j", "cloc"):
        assert t in tools
    assert not any("11434" in " ".join(cmd) for _, cmd in preflight._CHECKS)
