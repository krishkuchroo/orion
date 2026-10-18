import argparse
import glob
import os
import shutil
import subprocess
import tempfile

from . import db, queue, repo

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
                       orion_commit=orion_commit,
                       commit_kind=repo_meta.get("commit_kind", ""),
                       commit_sha=repo_meta["commit_sha"],
                       case_id=repo_meta.get("case_id", ""),
                       attempt_no=repo_meta.get("attempt_no", 1))
    repo_meta = dict(repo_meta, run_no=run_no)

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


def run_dir_for(arm, repo_meta, root=os.path.join("eval", "runs")):
    run_seg = str(repo_meta.get("run_no", 1))
    if repo_meta.get("attempt_no", 1) > 1:
        run_seg += f".a{repo_meta['attempt_no']}"
    return os.path.join(root, arm, repo_meta["id"], repo_meta["commit_sha"],
                        repo_meta.get("case_id") or "_", run_seg)


def _leak_guard(tree):
    d = os.path.dirname(tree)
    while True:
        for marker in ("CLAUDE.md", ".git"):
            if os.path.exists(os.path.join(d, marker)):
                raise RuntimeError(f"tree {tree} sits under {d}, which contains {marker}; "
                                   "agents would read it (answer leak). Use --tree-root outside any repo.")
        parent = os.path.dirname(d)
        if parent == d:
            return
        d = parent


def build_launcher(*, ollama_url, base_env, shim_dir, graph_cache,
                   _orion=_default_orion, _plain=_default_plain, _export=repo.export_tree, tree_root=None):
    tree_root = tree_root or os.path.join(tempfile.gettempdir(), "orion-eval-trees")
    def launcher(arm, repo_meta, model_tag, on_line):
        rid = repo_meta["id"]
        sha = repo_meta["commit_sha"]
        run_dir = os.path.abspath(run_dir_for(arm, repo_meta))
        tree = os.path.abspath(os.path.join(run_dir_for(arm, repo_meta, tree_root), "tree"))
        _leak_guard(tree)
        usage_log = os.path.join(run_dir, "usage.jsonl")
        name = "findings.orion.json" if arm.startswith("orion-") else "findings.json"
        json_out = os.path.join(run_dir, name)
        try:
            os.makedirs(run_dir, exist_ok=True)
            _export(repo_meta["mirror_dir"], sha, tree)
            if arm.startswith("orion-"):
                status, sid = _orion(repo_dir=tree, ollama_url=ollama_url,
                                     model_tag=model_tag, json_out=json_out, usage_log=usage_log,
                                     shim_dir=shim_dir, base_env=base_env, on_line=on_line,
                                     scan_id=graph_cache.get((rid, sha)))
                if sid:
                    graph_cache[(rid, sha)] = sid
            else:
                status, _ = _plain(arm=arm, repo_dir=tree, ollama_url=ollama_url,
                                   model_tag=model_tag, json_out=json_out, usage_log=usage_log,
                                   shim_dir=shim_dir, base_env=base_env, on_line=on_line)
            # anything an arm left inside the tree is copied out before the tree is deleted
            for f in glob.glob(os.path.join(tree, "findings*.json")) + \
                    glob.glob(os.path.join(tree, "usage.jsonl")):
                dst = os.path.join(run_dir, os.path.basename(f))
                if not os.path.exists(dst):
                    shutil.copy2(f, dst)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
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
    ap.add_argument("--tree-root", default=os.path.join(tempfile.gettempdir(), "orion-eval-trees"))
    ap.add_argument("--mirror-root", default="eval/mirrors/")
    ap.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    args = ap.parse_args(argv)
    arms = args.arm or ARMS
    repos = _json.loads(open(args.manifest).read())["repos"]  # [{id, repo_url, tier, ...}]
    good = []
    for r in repos:  # mirror once per repo, then pin the commit to check out
        try:
            r["mirror_dir"] = os.path.join(args.mirror_root, r["id"])
            if not (r.get("commit_sha") or r.get("vulnerable_commit") or r.get("patched_commit")):
                raise ValueError("manifest row has none of commit_sha/vulnerable_commit/patched_commit")
            repo.mirror(r["repo_url"], r["mirror_dir"])
            if not r.get("commit_sha"):
                r["commit_sha"] = r.get("vulnerable_commit") or repo.vulnerable_commit(
                    r["patched_commit"], r["mirror_dir"])
                r.setdefault("commit_kind", "vulnerable")
            good.append(r)
        except Exception as e:
            print(f"SKIPPING repo {r.get('id')}: {e}", flush=True)
    repos = good
    repo_ids = [r["id"] for r in repos]
    meta_by_id = {r["id"]: r for r in repos}
    conn = db.connect(args.db)
    versions = "; ".join(f"{r['tool']}={r['detail']}" for r in preflight.check())
    orion_commit = git_head()
    graph_cache = {}
    launcher = build_launcher(ollama_url=args.ollama_url, base_env=dict(os.environ),
                              shim_dir=_shim_dir(), graph_cache=graph_cache,
                              tree_root=args.tree_root)
    todo = queue.pending(conn, queue.plan(arms, repo_ids, args.runs))
    for arm, repo_id, n in todo:
        run_one(conn, arm=arm, repo_meta=meta_by_id[repo_id], run_no=n,
                model_tags=MODEL_TAGS, ollama_url=args.ollama_url, base_env=dict(os.environ),
                orion_commit=orion_commit, cli_versions=versions, launcher=launcher)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
