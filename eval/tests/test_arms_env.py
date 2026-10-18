from eval.arms import env


def test_plain_claude_env_isolates_config_and_shims_usage():
    out = env.plain_claude_env({"PATH": "/bin"}, usage_log="/r/u.jsonl", shim_dir="/shim",
                               config_dir="/cfg/claude")
    assert out["CLAUDE_CONFIG_DIR"] == "/cfg/claude"   # no user plugins / hooks / memory / MCP
    assert out["EVAL_USAGE_LOG"] == "/r/u.jsonl"
    assert out["PATH"].startswith("/shim:")            # shim resolves `claude` first
    assert out["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] == "1"
    assert "ANTHROPIC_BASE_URL" not in out              # frontier arms talk to Anthropic directly


def test_plain_claude_env_overrides_an_inherited_config_dir():
    out = env.plain_claude_env({"PATH": "/bin", "CLAUDE_CONFIG_DIR": "/Users/me/.claude"},
                               usage_log="l", shim_dir="s", config_dir="/cfg/claude")
    assert out["CLAUDE_CONFIG_DIR"] == "/cfg/claude"


def test_codex_env_isolates_home():
    out = env.codex_env({"PATH": "/bin", "CODEX_HOME": "/Users/me/.codex"}, home="/cfg/codex")
    assert out["CODEX_HOME"] == "/cfg/codex"
    assert out["PATH"] == "/bin"                        # Codex reports usage itself; no shim


def test_env_builders_do_not_mutate_base():
    base = {"PATH": "/bin"}
    env.plain_claude_env(base, usage_log="l", shim_dir="s", config_dir="c")
    env.codex_env(base, home="h")
    assert base == {"PATH": "/bin"}


def test_no_ollama_plumbing_left():
    assert not hasattr(env, "orion_env")
