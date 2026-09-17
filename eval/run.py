import argparse
import subprocess

from . import db, queue

ARMS = ["orion-gemma4", "orion-gptoss20b", "plain-gemma4",
        "plain-sonnet5", "plain-opus5", "plain-gpt"]

# Exact tags confirmed in Phase 0; frozen at pre-registration.
MODEL_TAGS = {
    "orion-gemma4": "gemma3:12b",
    "orion-gptoss20b": "gpt-oss:20b",
    "plain-gemma4": "gemma3:12b",
    "plain-sonnet5": "claude-sonnet-5",
    "plain-opus5": "claude-opus-5",
    "plain-gpt": "gpt-5.6-sol",
}


def git_head(path: str = ".") -> str:
    try:
        return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""


def run_one(conn, *, arm, repo_meta, run_no, model_tags, ollama_url, base_env,
            orion_commit, cli_versions, launcher) -> str:
    model_tag = model_tags.get(arm, arm)
    rid = db.start_run(conn, arm=arm, repo=repo_meta["id"], tier=repo_meta.get("tier", ""),
                       run_no=run_no, model_tag=model_tag, cli_versions=cli_versions,
                       orion_commit=orion_commit)

    def on_line(line):
        db.log_event(conn, rid, stage="run", level="info", message=line[:2000])
    try:
        status, _findings = launcher(arm, repo_meta, model_tag, on_line)
    except Exception as e:
        db.log_event(conn, rid, stage="run", level="error", message=str(e)[:2000])
        db.finish_run(conn, rid, "error")
        return "error"
    db.finish_run(conn, rid, status)
    return status


def _default_orion(**kw):
    from .arms.launch import orion_arm
    return orion_arm(**kw)


def _default_plain(**kw):
    from .arms.plain import plain_arm  # runs Claude Code / Codex with TASK_PROMPT
    return plain_arm(**kw)


def build_launcher(*, ollama_url, base_env, shim_dir, graph_cache,
                   _orion=_default_orion, _plain=_default_plain):
    def launcher(arm, repo_meta, model_tag, on_line):
        rid = repo_meta["id"]
        run_dir = f"eval/runs/{arm}/{rid}"
        usage_log = f"{run_dir}/usage.jsonl"
        if arm.startswith("orion-"):
            json_out = f"{run_dir}/findings.orion.json"
            status, sid = _orion(repo_dir=repo_meta["repo_dir"], ollama_url=ollama_url,
                                 model_tag=model_tag, json_out=json_out, usage_log=usage_log,
                                 shim_dir=shim_dir, base_env=base_env, on_line=on_line,
                                 scan_id=graph_cache.get(rid))
            if sid:
                graph_cache[rid] = sid
            return status, json_out
        json_out = f"{run_dir}/findings.json"
        status, _ = _plain(arm=arm, repo_dir=repo_meta["repo_dir"], ollama_url=ollama_url,
                           model_tag=model_tag, json_out=json_out, usage_log=usage_log,
                           shim_dir=shim_dir, base_env=base_env, on_line=on_line)
        return status, json_out
    return launcher


def main(argv=None):
    import json as _json
    import os
    from . import preflight
    from .shim_setup import shim_dir as _shim_dir
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", action="append", choices=ARMS)
    ap.add_argument("--manifest", default="eval/dataset/manifest.json")
    ap.add_argument("--db", default="eval/runs.db")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    args = ap.parse_args(argv)
    arms = args.arm or ARMS
    repos = _json.loads(open(args.manifest).read())["repos"]  # [{id, repo_dir, tier, ...}]
    repo_ids = [r["id"] for r in repos]
    meta_by_id = {r["id"]: r for r in repos}
    conn = db.connect(args.db)
    versions = "; ".join(f"{r['tool']}={r['detail']}" for r in preflight.check())
    orion_commit = git_head()
    graph_cache = {}
    launcher = build_launcher(ollama_url=args.ollama_url, base_env=dict(os.environ),
                              shim_dir=_shim_dir(), graph_cache=graph_cache)
    todo = queue.pending(conn, queue.plan(arms, repo_ids, args.runs))
    for arm, repo_id, n in todo:
        run_one(conn, arm=arm, repo_meta=meta_by_id[repo_id], run_no=n,
                model_tags=MODEL_TAGS, ollama_url=args.ollama_url, base_env=dict(os.environ),
                orion_commit=orion_commit, cli_versions=versions, launcher=launcher)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
