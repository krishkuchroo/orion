from eval.arms import env


def test_orion_env_sets_wiring_usage_and_memory_knobs():
    out = env.orion_env({"PATH": "/bin"}, ollama_url="http://127.0.0.1:11434",
                        model_tag="gemma3:12b", usage_log="/r/usage.jsonl", shim_dir="/shim")
    assert out["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:11434"
    assert out["ORION_MODEL"] == "gemma3:12b"
    for k in ("ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
              "ANTHROPIC_DEFAULT_HAIKU_MODEL"):
        assert out[k] == "gemma3:12b"
    assert out["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] == "1"
    assert out["EVAL_USAGE_LOG"] == "/r/usage.jsonl"
    assert out["PATH"].startswith("/shim:")  # shim resolves `claude` first
    assert out["ORION_JOERN_HEAP_GB"] == "7"
    assert out["OLLAMA_KEEP_ALIVE"] == "0"


def test_plain_claude_env_frontier_has_no_base_url():
    out = env.plain_claude_env({"PATH": "/bin"}, usage_log="/r/u.jsonl", shim_dir="/shim")
    assert "ANTHROPIC_BASE_URL" not in out
    assert out["PATH"].startswith("/shim:")


def test_env_builders_do_not_mutate_base():
    base = {"PATH": "/bin"}
    env.orion_env(base, ollama_url="u", model_tag="m", usage_log="l", shim_dir="s")
    assert "ANTHROPIC_BASE_URL" not in base
