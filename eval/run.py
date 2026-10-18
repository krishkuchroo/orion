import argparse
import os
import shutil
import subprocess
import tempfile
import time

from . import db, queue, repo
from .resources import PhaseSampler

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

# Reasoning effort per arm (design: Claude Code arms run at xhigh). Arms absent here run
# at the CLI default and record effort='' -- Task A6 turns these into real CLI flags.
EFFORT = {
    "plain-sonnet5": "xhigh",
    "plain-opus5": "xhigh",
}


def git_head(path: str = ".") -> str:
    try:
        return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        return ""


def run_one(conn, *, arm, repo_meta, run_no, model_tags, base_env,
            orion_commit, cli_versions, launcher, efforts=EFFORT) -> str:
    model_tag = model_tags.get(arm, arm)
    effort = efforts.get(arm, "")
    rid = db.start_run(conn, arm=arm, repo=repo_meta["id"], tier=repo_meta.get("tier", ""),
                       run_no=run_no, model_tag=model_tag, cli_versions=cli_versions,
                       orion_commit=orion_commit,
                       commit_kind=repo_meta.get("commit_kind", ""),
                       commit_sha=repo_meta["commit_sha"],
                       case_id=repo_meta.get("case_id", ""),
                       attempt_no=repo_meta.get("attempt_no", 1), effort=effort)
    repo_meta = dict(repo_meta, run_no=run_no)

    def on_line(line):
        db.log_event(conn, rid, stage="run", level="info", message=line[:2000])

    sampler = {"s": None}  # attached once the arm's process exists (pid handoff)

    def on_start(proc):
        if sampler["s"] is not None:
            sampler["s"].__exit__(None, None, None)
        sampler["s"] = PhaseSampler(proc.pid).__enter__()

    t0 = time.monotonic()
    try:
        res = launcher(arm, repo_meta, model_tag, on_line, effort=effort, on_start=on_start)
    except Exception as e:
        _log_resource(conn, rid, sampler["s"], t0)
        db.log_event(conn, rid, stage="run", level="error", message=str(e)[:2000])
        db.finish_run(conn, rid, "error")
        return "error"
    # the run must never be left 'running': a failure while recording what the arm returned
    # becomes an error event + status "error", not a dangling row
    try:
        _log_resource(conn, rid, sampler["s"], t0)
        for block in res.usage:
            db.log_agent_call(conn, rid, session_id=None, stage="run",
                              input_tokens=block.get("uncached_in"), output_tokens=block.get("out"),
                              cache_read=block.get("cache_read"), cache_write=block.get("cache_write"),
                              turns_used=None, turn_limit=None, peak_context=None,
                              exit_reason=None, error_head=None)
        for step in res.steps or []:
            db.log_step(conn, rid, **step)
        if res.findings_path is None:
            db.log_event(conn, rid, stage="run", level="warn",
                         message="no valid findings file; scored as a miss")
    except Exception as e:
        db.log_event(conn, rid, stage="run", level="error",
                     message=f"recording run result failed: {e!r}"[:2000])
        db.finish_run(conn, rid, "error")
        return "error"
    db.finish_run(conn, rid, res.status)
    return res.status


def _log_resource(conn, rid, sampler, t0):
    """One resources row for the run phase. Peak RSS comes only from a sampler that was
    attached to a live process; otherwise it is recorded as missing (None), never 0.
    wall_seconds has two sources: with a sampler it is the arm's process lifetime as seen by
    the sampler (spawn -> launcher return, so it includes the findings copy and the tree
    rmtree); without one (no process was ever spawned) it is run_one's own clock around the
    launcher call."""
    if sampler is not None:
        sampler.__exit__(None, None, None)
        wall, rss = sampler.wall_seconds, sampler.peak_rss_mb
    else:
        wall, rss = time.monotonic() - t0, None
    db.log_resource(conn, rid, phase="run", wall_seconds=wall, peak_rss_mb=rss,
                    graph_nodes=None, graph_edges=None, loc=None)


def _default_plain(**kw):
    from .arms.plain import plain_arm  # runs Claude Code / Codex with TASK_PROMPT
    return plain_arm(**kw)


def _default_lm(**kw):
    raise NotImplementedError("orion-lm arms land in Task F3")


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


def build_launcher(*, base_env, shim_dir, graph_cache, _plain=_default_plain, _lm=_default_lm,
                   _export=repo.export_tree, tree_root=None):
    tree_root = tree_root or os.path.join(tempfile.gettempdir(), "orion-eval-trees")

    def launcher(arm, repo_meta, model_tag, on_line, *, effort, on_start):
        sha = repo_meta["commit_sha"]
        run_dir = os.path.abspath(run_dir_for(arm, repo_meta))
        tree = os.path.abspath(os.path.join(run_dir_for(arm, repo_meta, tree_root), "tree"))
        _leak_guard(tree)
        usage_log = os.path.join(run_dir, "usage.jsonl")
        json_out = os.path.join(run_dir, "findings.json")
        try:
            os.makedirs(run_dir, exist_ok=True)
            _export(repo_meta["mirror_dir"], sha, tree)
            common = dict(arm=arm, repo_dir=tree, model_tag=model_tag, effort=effort,
                          json_out=json_out, usage_log=usage_log, base_env=base_env,
                          on_line=on_line, on_start=on_start)
            if arm.startswith("orion-"):
                # in-process orion-lm arms (Task F3); default seam refuses so nothing
                # silently runs the deleted `orion scan` subprocess path
                res = _lm(graph_cache=graph_cache, **common)
            else:
                # the arm copies its findings.json out of the tree before it is deleted
                res = _plain(shim_dir=shim_dir, **common)
        finally:
            shutil.rmtree(tree, ignore_errors=True)
        return res
    return launcher


def main(argv=None):
    import json as _json
    from . import preflight
    from .shim_setup import shim_dir as _shim_dir
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", action="append", choices=ARMS)
    ap.add_argument("--manifest", default="eval/dataset/manifest.json")
    ap.add_argument("--db", default="eval/runs.db")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--tree-root", default=os.path.join(tempfile.gettempdir(), "orion-eval-trees"))
    ap.add_argument("--mirror-root", default="eval/mirrors/")
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
    launcher = build_launcher(base_env=dict(os.environ), shim_dir=_shim_dir(),
                              graph_cache=graph_cache, tree_root=args.tree_root)
    todo = queue.pending(conn, queue.plan(arms, repo_ids, args.runs))
    for arm, repo_id, n in todo:
        run_one(conn, arm=arm, repo_meta=meta_by_id[repo_id], run_no=n,
                model_tags=MODEL_TAGS, base_env=dict(os.environ),
                orion_commit=orion_commit, cli_versions=versions, launcher=launcher)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
