def _model_defaults(env: dict, model_tag: str) -> None:
    env["ORION_MODEL"] = model_tag
    env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = model_tag
    env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = model_tag
    env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = model_tag


def _with_shim(env: dict, usage_log: str, shim_dir: str) -> None:
    env["EVAL_USAGE_LOG"] = usage_log
    env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"


def orion_env(base, *, ollama_url, model_tag, usage_log, shim_dir, joern_heap_gb="7") -> dict:
    env = dict(base)
    env["ANTHROPIC_BASE_URL"] = ollama_url
    env["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] = "1"
    env["ORION_JOERN_HEAP_GB"] = joern_heap_gb
    env["OLLAMA_KEEP_ALIVE"] = "0"
    _model_defaults(env, model_tag)
    _with_shim(env, usage_log, shim_dir)
    return env


def plain_claude_env(base, *, usage_log, shim_dir, ollama_url=None, model_tag=None) -> dict:
    env = dict(base)
    env["CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"] = "1"
    if ollama_url:
        env["ANTHROPIC_BASE_URL"] = ollama_url
    if model_tag:
        _model_defaults(env, model_tag)
    _with_shim(env, usage_log, shim_dir)
    return env
