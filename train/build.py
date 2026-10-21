"""Dual-commit graph builds for training pairs (plan Task D2).

For every pair: bare-mirror the repo once, pick the (vulnerable, patched) commit pair, export each
commit as a .git-free tree, and build it into Orion's Neo4j with the streaming builder and the
lm-sink profile -- one side at a time, never two Joern processes at once.

Commit pair (``resolve_commits``):

* vulnerable = parent of the FIRST fix commit (earliest by ancestry, not by list order);
* patched = the LAST fix commit when the fix commits form one line of history (every pair is
  ancestor-related, checked with ``git merge-base --is-ancestor``);
* otherwise (e.g. backports on other branches) patched = the first fix commit, flagged
  ``multi_commit_nonlinear: true``;
* a root fix commit has no vulnerable side: ``status=no_parent`` (skipped).

The run (``build_all``) is resumable, watchable and stoppable: one JSON line per finished pair in the
ledger (a rerun skips every pair already there unless its status is in ``retry``), a
``[i/N] <id> <side> <status> <s>s`` line per side, every graph_build event appended to
``<work_root>/events.jsonl``, and Ctrl-C finishes the current side, writes the ledger line and returns.
Joern runs in its own session so the terminal's Ctrl-C reaches only this process; a second Ctrl-C
aborts the current side (still recorded, as ``interrupted``).

Measured per side (null when not reported, never estimated): graph_build's own stage timings, the
batch node/edge counts from its TOTAL line, the Neo4j node count for the scan, the cpg.bin size, and
the process RSS high-water marks.

Run (data stays outside the repo)::

    ORION_JOERN_HEAP_GB=8 ./.venv/bin/python -I train/build.py run --pairs train/data/pairs.json \\
        [--limit N] [--ids A,B] [--keep-cpg-dir DIR] [--order dataflow_first|as_given]
    ./.venv/bin/python -I train/build.py evict SCAN_ID [SCAN_ID ...]
"""
from __future__ import annotations

import contextlib
import functools
import glob
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

if __package__ in (None, ""):  # run as a script under `python -I`: put the repo root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import repo as erepo  # noqa: E402
from orion import graph_build  # noqa: E402
from orion.graph import joern_adapter, profiles  # noqa: E402
from train import fixmap  # noqa: E402

RESEARCH = os.path.expanduser("~/Documents/OrionLutherLeo/orion-lm-research")
DEFAULT_LEDGER = "train/data/builds.jsonl"
FRONTEND = {"js": "jssrc", "py": "pythonsrc", "java": "javasrc"}   # pair language -> Joern frontend
SIDES = ("vulnerable", "patched")

# graph_build's `_timed` labels -> ledger keys. Anything graph_build did not report stays None.
_STAGES = {"parse (cpg.bin)": "parse_s", "consume (stream envelope)": "stream_s",
           "normalize": "normalize_s", "reachability": "reachability_s",
           "centrality": "centrality_s", "pathfind": "pathfind_s", "persist": "persist_s"}
_TIMING_KEYS = ("export_s", *_STAGES.values(), "graph_total_s", "side_total_s")
_TIMING = re.compile(r"^(?P<label>[^:]+): (?P<s>\d+(?:\.\d+)?)s$")
_TOTAL = re.compile(r"^TOTAL graph build: (?P<s>\d+(?:\.\d+)?)s \((?P<n>\d+) nodes, (?P<e>\d+) edges\)$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_run(cmd: list[str]) -> str:
    """git/tar runner. GIT_TERMINAL_PROMPT=0: a deleted/private repo fails instead of waiting for a
    password on the terminal in the middle of an overnight run."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          check=True, env=env).stdout


def _err(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        tail = (exc.stderr or exc.stdout or "").strip()
        return f"{' '.join(map(str, exc.cmd))[:300]} (rc={exc.returncode}): {tail[-1500:]}"
    return f"{exc.__class__.__name__}: {str(exc)[-3000:]}"


def _safe(pair_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", pair_id)


# ───────────────────────────── mirrors + commit pair ─────────────────────────────

def _repo_name(pair: dict) -> str:
    return pair.get("repo_canonical") or pair["repo"]


def mirror_dir_for(mirror_root: str, pair: dict) -> str:
    """One bare clone per repo, reused by every pair of that repo (lowercased: GitHub names are
    case-insensitive and so is APFS)."""
    return os.path.join(mirror_root, _repo_name(pair).lower().replace("/", "__") + ".git")


def ensure_mirror(pair: dict, mirror_root: str, *, run=_default_run) -> str:
    """Bare-clone the pair's repo under `mirror_root` if it is not there yet (needs network)."""
    d = mirror_dir_for(mirror_root, pair)
    if not os.path.isdir(d):
        os.makedirs(mirror_root, exist_ok=True)
        url = pair.get("repo_url") or f"https://github.com/{_repo_name(pair)}.git"
        erepo.mirror(url, d, run=run)
    return d


def _git(mirror: str, *args: str) -> list[str]:
    return ["git", "-C", mirror, *args]


def _rev(mirror: str, sha: str, run) -> str | None:
    try:
        return run(_git(mirror, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}")).strip() or None
    except subprocess.CalledProcessError:
        return None


def _fetch(mirror: str, sha: str, run) -> bool:
    """A bare clone has branches and tags only; a fix commit reachable only from a PR/fork ref can still
    be fetched by full sha from GitHub."""
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return False
    try:
        run(_git(mirror, "fetch", "--quiet", "origin", sha))
        return True
    except subprocess.CalledProcessError:
        return False


def _ancestry(mirror: str, run):
    @functools.lru_cache(maxsize=None)
    def anc(a: str, b: str) -> bool:
        """True iff `a` is an ancestor of (or equal to) `b`."""
        if a == b:
            return True
        try:
            run(_git(mirror, "merge-base", "--is-ancestor", a, b))
            return True
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                return False
            raise
    return anc


def _earliest(cands: list[str], anc) -> str | None:
    """The candidate that is an ancestor of every other candidate, else None."""
    return next((c for c in cands if all(anc(c, o) for o in cands)), None)


def resolve_commits(pair: dict, mirror_dir: str, *, run=_default_run) -> dict:
    """Pick the (vulnerable, patched) commits for `pair` from its local mirror (rule in module doc).

    Returns {status, reason, vulnerable, patched, first_fix, fix_shas (full), multi_commit_nonlinear,
    vuln_sha_source, vuln_sha_matches}. status: ok | no_fix_commit | commit_missing | no_parent."""
    out = {"status": None, "reason": None, "vulnerable": None, "patched": None, "first_fix": None,
           "fix_shas": [], "multi_commit_nonlinear": False,
           "vuln_sha_source": pair.get("vuln_sha"), "vuln_sha_matches": None}
    listed = list(dict.fromkeys(s for s in (pair.get("fix_shas") or [pair.get("fix_sha")]) if s))
    if not listed:
        return {**out, "status": "no_fix_commit", "reason": "pair has no fix sha"}
    full, missing = [], []
    for s in listed:
        f = _rev(mirror_dir, s, run)
        if f is None and _fetch(mirror_dir, s, run):
            f = _rev(mirror_dir, s, run)
        (full.append(f) if f else missing.append(s))
    if missing:
        return {**out, "status": "commit_missing", "reason": "not in mirror: " + ", ".join(missing)}
    full = list(dict.fromkeys(full))
    anc = _ancestry(mirror_dir, run)
    chain = all(anc(a, b) or anc(b, a) for i, a in enumerate(full) for b in full[i + 1:])
    if chain:   # one line of history: earliest fix's parent .. latest fix
        first = _earliest(full, anc)
        patched = next(c for c in full if all(anc(o, c) for o in full))
        nonlinear = False
    else:       # backports etc.: (first^, first) on the line of the first-listed fix
        lead = full[0]
        first = _earliest([c for c in full if anc(c, lead)], anc) or lead
        patched, nonlinear = first, True
    parents = run(_git(mirror_dir, "rev-list", "--parents", "-n", "1", first)).split()[1:]
    out.update(fix_shas=full, first_fix=first, patched=patched, multi_commit_nonlinear=nonlinear)
    if not parents:
        return {**out, "status": "no_parent", "reason": f"first fix commit {first} is a root commit"}
    out.update(status="ok", vulnerable=parents[0])
    if out["vuln_sha_source"]:
        src = _rev(mirror_dir, out["vuln_sha_source"], run)
        out["vuln_sha_matches"] = None if src is None else src == parents[0]
    return out


# ───────────────────────────── one side ─────────────────────────────

def _export(mirror_dir: str, sha: str, dest: str, run) -> bool:
    """Export `sha` as a .git-free tree. A committed root cpg.bin is deleted (joern_adapter.ensure_cpg
    would otherwise reuse it instead of parsing this commit). Returns True if one was removed."""
    erepo.export_tree(mirror_dir, sha, dest, run=run)
    stray = os.path.join(dest, "cpg.bin")
    if os.path.lexists(stray):
        os.remove(stray)
        return True
    return False


@contextlib.contextmanager
def _children_detached():
    """Start every subprocess inside the block in its own session (joern-parse, the stream producer,
    git). The terminal sends Ctrl-C to its foreground process group; without this Joern would die with
    it and the side would be lost instead of finished."""
    orig = subprocess.Popen.__init__

    @functools.wraps(orig)
    def init(self, *args, **kw):
        if not kw.get("start_new_session") and kw.get("process_group") is None:
            kw["start_new_session"] = True
        orig(self, *args, **kw)

    subprocess.Popen.__init__ = init
    try:
        yield
    finally:
        subprocess.Popen.__init__ = orig


@contextlib.contextmanager
def _scoped_tempdir(path: str):
    """Point tempfile.mkdtemp (used by graph_build/joern_adapter for orion_cpg_*/orion_stream_*) at a
    per-side dir, so this side's temp files can be found, measured and removed without touching any
    other process's temp dirs."""
    os.makedirs(path, exist_ok=True)
    old = tempfile.tempdir
    tempfile.tempdir = path
    try:
        yield path
    finally:
        tempfile.tempdir = old


def _maxrss_mb() -> tuple[float, float]:
    """(this process, largest finished child) RSS high-water marks in MB. ru_maxrss is bytes on macOS,
    KiB on Linux."""
    div = 1024 * 1024 if sys.platform == "darwin" else 1024
    return (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / div,
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / div)


def _side_record(side: str, sha: str, scan_id: str) -> dict:
    return {"side": side, "sha": sha, "scan_id": scan_id, "status": None, "reason": None,
            "timings": dict.fromkeys(_TIMING_KEYS), "n_nodes": None, "n_edges": None,
            "neo4j_nodes": None, "cpg_bin_bytes": None, "cpg_bin_kept": None,
            "stray_cpg_removed": None, "peak_rss_python_mb": None, "peak_rss_children_mb": None,
            "maxrss_python_mb_hwm": None, "maxrss_children_mb_hwm": None,
            "started_at": _now(), "finished_at": None}


def _capture(rec: dict, events_path: str | None, pair_id: str, side: str):
    """on_event for graph_build: copy its timing events into `rec` and append every event to the
    watchable events log."""
    def on_event(ev) -> None:
        if isinstance(ev, dict) and ev.get("event") == "timing":
            detail = str(ev.get("detail") or "")
            m = _TOTAL.match(detail)
            if m:
                rec["timings"]["graph_total_s"] = float(m["s"])
                rec["n_nodes"], rec["n_edges"] = int(m["n"]), int(m["e"])
            else:
                m = _TIMING.match(detail)
                if m and m["label"] in _STAGES:
                    rec["timings"][_STAGES[m["label"]]] = float(m["s"])
        if events_path:
            with open(events_path, "a") as fh:
                fh.write(json.dumps({"pair": pair_id, "side": side, "ev": ev}, default=str) + "\n")
    return on_event


def _build_side(pair: dict, side: str, sha: str, mirror_dir: str, work_root: str, *, builder,
                frontend: str, display: str, keep_cpg_dir: str | None, db, run,
                events_path: str | None) -> dict:
    scan_id = f"{pair['id']}:{side}"
    rec = _side_record(side, sha, scan_id)
    name = f"{_safe(pair['id'])}.{side}"
    tree = os.path.join(work_root, "trees", name)
    tmp = os.path.join(work_root, "tmp", name)
    rss0 = _maxrss_mb()
    t0 = time.monotonic()
    try:
        with _children_detached():
            te = time.monotonic()
            try:
                rec["stray_cpg_removed"] = _export(mirror_dir, sha, tree, run)
            except (subprocess.CalledProcessError, OSError) as e:
                rec.update(status="export_failed", reason=_err(e))
                return rec
            rec["timings"]["export_s"] = round(time.monotonic() - te, 3)
            profile = profiles.with_lm_sinks(profiles.select_profile(tree, display))
            with _scoped_tempdir(tmp):
                try:
                    got = builder(tree, language=frontend, on_event=_capture(rec, events_path, pair["id"], side),
                                  stream=True, scan_id=scan_id, profile=profile)
                    if got != scan_id:
                        rec.update(status="build_failed", reason=f"builder returned scan_id {got!r}")
                    else:
                        rec["status"] = "ok"
                except Exception as e:  # noqa: BLE001 -- joern-parse RuntimeError & co: record, never crash the run
                    rec.update(status="build_failed", reason=_err(e), error_type=e.__class__.__name__)
    except KeyboardInterrupt:
        rec.update(status="interrupted", reason="KeyboardInterrupt during this side")
    finally:
        for cpg in sorted(glob.glob(os.path.join(tmp, "orion_cpg_*", "cpg.bin"))):
            rec["cpg_bin_bytes"] = os.path.getsize(cpg)
            if keep_cpg_dir:
                os.makedirs(keep_cpg_dir, exist_ok=True)
                dest = os.path.join(keep_cpg_dir, f"{name}.cpg.bin")
                shutil.move(cpg, dest)
                rec["cpg_bin_kept"] = dest
            break
        shutil.rmtree(tree, ignore_errors=True)
        shutil.rmtree(tmp, ignore_errors=True)
        rec["timings"]["side_total_s"] = round(time.monotonic() - t0, 3)
        rss1 = _maxrss_mb()
        rec["maxrss_python_mb_hwm"], rec["maxrss_children_mb_hwm"] = round(rss1[0], 1), round(rss1[1], 1)
        # Lifetime high-water marks: attributable to THIS side only if they rose during it.
        rec["peak_rss_python_mb"] = round(rss1[0], 1) if rss1[0] > rss0[0] else None
        rec["peak_rss_children_mb"] = round(rss1[1], 1) if rss1[1] > rss0[1] else None
        rec["finished_at"] = _now()
    if rec["status"] == "ok" and db is not None:
        try:
            rec["neo4j_nodes"] = int(db.node_count(scan_id))
        except Exception as e:  # noqa: BLE001 -- a count we could not read is missing, not zero
            rec["neo4j_nodes_error"] = _err(e)
    return rec


# ───────────────────────────── one pair ─────────────────────────────

def _not_built(side: str) -> dict:
    return {"side": side, "status": "not_built"}


def build_pair(pair: dict, mirror_dir: str, work_root: str, *, builder=None,
               keep_cpg_dir: str | None = None, db=None, run=_default_run, on_side=None,
               stop=None, events_path: str | None = None) -> dict:
    """Build the vulnerable then the patched commit of `pair` (sequentially) and return its ledger
    record {id, status, reason, vulnerable_scan_id, patched_scan_id, hunks, sides, ...}. `hunks` are the
    fix hunks (fixmap.fix_hunks) taken from the mirror before building.

    status: ok | build_failed | export_failed | interrupted | no_parent | commit_missing |
    no_fix_commit | language_unsupported | git_error. A failed vulnerable side skips the patched side
    (the pair is unusable either way). `stop()` true between the sides -> patched not built,
    status interrupted."""
    builder = builder or graph_build.build
    t0 = time.monotonic()
    rec = {"id": pair["id"], "repo": pair.get("repo"), "language": pair.get("language"),
           "cwe_class": pair.get("cwe_class"), "mirror": mirror_dir, "status": None, "reason": None,
           "vulnerable_sha": None, "patched_sha": None, "first_fix": None, "fix_shas": None,
           "multi_commit_nonlinear": None, "vuln_sha_source": pair.get("vuln_sha"),
           "vuln_sha_matches": None, "vulnerable_scan_id": None, "patched_scan_id": None,
           "hunks": None, "sides": {}, "started_at": _now(), "finished_at": None, "total_s": None}

    def done(**kw) -> dict:
        rec.update(kw, finished_at=_now(), total_s=round(time.monotonic() - t0, 3))
        return rec

    frontend = FRONTEND.get(pair.get("language"))
    if frontend is None:
        return done(status="language_unsupported", reason=f"no Joern frontend for {pair.get('language')!r}")
    try:
        c = resolve_commits(pair, mirror_dir, run=run)
    except (subprocess.CalledProcessError, OSError) as e:
        return done(status="git_error", reason=_err(e))
    rec.update(vulnerable_sha=c["vulnerable"], patched_sha=c["patched"], first_fix=c["first_fix"],
               fix_shas=c["fix_shas"], multi_commit_nonlinear=c["multi_commit_nonlinear"],
               vuln_sha_matches=c["vuln_sha_matches"])
    if c["status"] != "ok":
        return done(status=c["status"], reason=c["reason"])
    try:   # stored with the build so the yield step (D3) does not need the mirror later
        rec["hunks"] = fixmap.fix_hunks(mirror_dir, c["vulnerable"], c["patched"], run=run,
                                        fix_shas=None if c["multi_commit_nonlinear"] else c["fix_shas"])
    except (subprocess.CalledProcessError, OSError) as e:
        rec["hunks_error"] = _err(e)
    display = joern_adapter.resolve_language(work_root, frontend)[1]   # frontend given -> pure mapping
    for k, (side, sha) in enumerate(zip(SIDES, (c["vulnerable"], c["patched"]))):
        if stop is not None and stop():
            rec["sides"].update({s: _not_built(s) for s in SIDES[k:]})
            return done(status="interrupted", reason="stop requested before this side")
        s = _build_side(pair, side, sha, mirror_dir, work_root, builder=builder, frontend=frontend,
                        display=display, keep_cpg_dir=keep_cpg_dir, db=db, run=run,
                        events_path=events_path)
        rec["sides"][side] = s
        if on_side is not None:
            on_side(s)
        if s["status"] == "ok":
            rec[f"{side}_scan_id"] = s["scan_id"]
            continue
        rec["sides"].update({x: _not_built(x) for x in SIDES[k + 1:]})
        return done(status=s["status"], reason=s["reason"])
    return done(status="ok")


# ───────────────────────────── the run ─────────────────────────────

def _order(pairs: list[dict], order: str) -> list[dict]:
    if order == "dataflow_first":
        return ([p for p in pairs if p.get("cwe_class") == "dataflow"]
                + [p for p in pairs if p.get("cwe_class") != "dataflow"])
    if order == "as_given":
        return list(pairs)
    raise ValueError(f"unknown order {order!r} (dataflow_first | as_given)")


def read_ledger(path: str) -> list[dict]:
    """Every parseable line (a torn last line from a hard kill is skipped)."""
    rows = []
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("id"):
                    rows.append(r)
    return rows


def _append(path: str, rec: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(rec, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


@contextlib.contextmanager
def _run_lock(work_root: str):
    """One build_all per work_root (never two Joern runs at once). A lock left by a dead pid is stale."""
    os.makedirs(work_root, exist_ok=True)
    lock = os.path.join(work_root, ".build.lock")
    try:
        with open(lock) as fh:
            pid = int(fh.read().strip() or 0)
        if pid and pid != os.getpid():
            try:
                os.kill(pid, 0)
                raise RuntimeError(f"another build_all (pid {pid}) holds {lock}")
            except ProcessLookupError:
                pass
    except (FileNotFoundError, ValueError):
        pass
    with open(lock, "w") as fh:
        fh.write(str(os.getpid()))
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(lock)


def _capacity(db, work_root: str, n_done: int) -> dict:
    """Measured capacity snapshot: free disk, total Neo4j nodes, the Neo4j container's memory as
    `docker stats` prints it. A value that cannot be read is null."""
    snap = {"ts": _now(), "pairs_done_this_run": n_done,
            "free_disk_gb": round(shutil.disk_usage(work_root).free / 1e9, 2),
            "neo4j_total_nodes": None, "docker_neo4j_mem": None}
    try:
        r = db.run_cypher("", "MATCH (n) RETURN count(n) AS c")
        snap["neo4j_total_nodes"] = int(r["rows"][0]["c"]) if r.get("rows") else None
    except Exception:  # noqa: BLE001
        pass
    try:
        snap["docker_neo4j_mem"] = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", "orion-neo4j"],
            capture_output=True, text=True, timeout=30, check=True).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        pass
    return snap


def build_all(pairs: list[dict], mirror_root: str, work_root: str, *, ledger: str = DEFAULT_LEDGER,
              on_event=print, order: str = "dataflow_first", builder=None, db=None,
              keep_cpg_dir: str | None = None, run=_default_run, retry=("interrupted",),
              limit: int | None = None, capacity_every: int = 20,
              max_consecutive_failures: int = 5) -> dict:
    """Build every pair not already in `ledger` (resumable, watchable, stoppable; see module doc).

    `db` (a GraphDB) is optional: with it each side records its Neo4j node count and a capacity
    snapshot goes to `<ledger stem>.capacity.jsonl` at the start and every `capacity_every` pairs.
    The run stops itself after `max_consecutive_failures` build failures in a row (Neo4j down, Joern
    broken) instead of marking the whole list failed. Returns {built, skipped, stopped, reason}."""
    last = {r["id"]: r.get("status") for r in read_ledger(ledger)}
    done_ids = {i for i, st in last.items() if st not in set(retry)}
    ordered = _order(pairs, order)
    todo = [p for p in ordered if p["id"] not in done_ids]
    if limit is not None:
        todo = todo[:limit]
    n = len(todo)
    on_event(f"{sum(p['id'] in done_ids for p in ordered)} of {len(ordered)} pairs already in {ledger}; "
             f"building {n}")
    capacity_log = os.path.splitext(ledger)[0] + ".capacity.jsonl"
    events_path = os.path.join(work_root, "events.jsonl")
    stop = threading.Event()
    result = {"built": 0, "skipped": len(ordered) - n, "stopped": False, "reason": None}

    def on_sigint(signum, frame):
        if stop.is_set():
            raise KeyboardInterrupt
        stop.set()
        on_event("stop requested: finishing the current side, then exiting (Ctrl-C again aborts it)")

    in_main = threading.current_thread() is threading.main_thread()
    old_handler = signal.signal(signal.SIGINT, on_sigint) if in_main else None
    try:
        with _run_lock(work_root):
            for d in ("trees", "tmp"):   # leftovers from a hard-killed run
                shutil.rmtree(os.path.join(work_root, d), ignore_errors=True)
            if db is not None:
                _append(capacity_log, _capacity(db, work_root, 0))
            fails = 0
            for i, pair in enumerate(todo, 1):
                if stop.is_set():
                    break

                def on_side(s, i=i, pid=pair["id"]):
                    on_event(f"[{i}/{n}] {pid} {s['side']} {s['status']} {s['timings']['side_total_s']:.1f}s")

                t0 = time.monotonic()
                try:
                    mdir = ensure_mirror(pair, mirror_root, run=run)
                except (subprocess.CalledProcessError, OSError) as e:
                    rec = {"id": pair["id"], "repo": pair.get("repo"), "status": "mirror_failed",
                           "reason": _err(e), "finished_at": _now()}
                except KeyboardInterrupt:
                    rec = {"id": pair["id"], "repo": pair.get("repo"), "status": "interrupted",
                           "reason": "KeyboardInterrupt while mirroring", "finished_at": _now()}
                else:
                    try:
                        rec = build_pair(pair, mdir, work_root, builder=builder, keep_cpg_dir=keep_cpg_dir,
                                         db=db, run=run, on_side=on_side, stop=stop.is_set,
                                         events_path=events_path)
                    except KeyboardInterrupt:   # 2nd Ctrl-C during the git steps before any side
                        rec = {"id": pair["id"], "repo": pair.get("repo"), "status": "interrupted",
                               "reason": "KeyboardInterrupt before the build started", "finished_at": _now()}
                _append(ledger, rec)
                result["built"] += 1
                on_event(f"[{i}/{n}] {pair['id']} pair {rec['status']} {time.monotonic() - t0:.1f}s")
                if rec["status"] == "interrupted":
                    stop.set()
                fails = fails + 1 if rec["status"] == "build_failed" else (0 if rec["status"] == "ok" else fails)
                if fails >= max_consecutive_failures:
                    result["reason"] = f"{fails} consecutive build failures -- check Joern/Neo4j before resuming"
                    on_event("stopping: " + result["reason"])
                    break
                if db is not None and capacity_every and i % capacity_every == 0:
                    snap = _capacity(db, work_root, i)
                    _append(capacity_log, snap)
                    on_event(f"capacity: {snap}")
    finally:
        if in_main:
            signal.signal(signal.SIGINT, old_handler)
    result["stopped"] = stop.is_set() or result["reason"] is not None
    if stop.is_set():
        result["reason"] = result["reason"] or "stopped by Ctrl-C"
    return result


def evict(scan_ids, db) -> dict:
    """Delete built scans (capacity management) through GraphDB.clear_scan. {scan_id: evicted|error}."""
    out = {}
    for s in scan_ids:
        try:
            db.clear_scan(s)
            out[s] = "evicted"
        except Exception as e:  # noqa: BLE001
            out[s] = f"error: {_err(e)}"
    return out


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Orion-LM dual-commit graph builds")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="build pairs (resumable; Ctrl-C stops after the current side)")
    r.add_argument("--pairs", default="train/data/pairs.json")
    r.add_argument("--mirrors", default=os.path.join(RESEARCH, "mirrors"))
    r.add_argument("--work", default=os.path.join(RESEARCH, "build-work"))
    r.add_argument("--ledger", default=DEFAULT_LEDGER)
    r.add_argument("--keep-cpg-dir", default=None)
    r.add_argument("--order", default="dataflow_first", choices=("dataflow_first", "as_given"))
    r.add_argument("--ids", default=None, help="comma-separated pair ids to build (default: all)")
    r.add_argument("--limit", type=int, default=None, help="build at most N pairs this run")
    r.add_argument("--retry", default="interrupted", help="ledger statuses to rebuild (comma-separated)")
    r.add_argument("--no-db", action="store_true", help="skip Neo4j node counts / capacity snapshots")
    e = sub.add_parser("evict", help="delete built scans from Neo4j (WRITES)")
    e.add_argument("scan_ids", nargs="+")
    a = ap.parse_args(argv)

    from orion.graphdb import GraphDB
    if a.cmd == "evict":
        db = GraphDB()
        try:
            print(json.dumps(evict(a.scan_ids, db), indent=1))
        finally:
            db.close()
        return 0
    with open(a.pairs) as fh:
        pairs = json.load(fh)
    if a.ids:
        want = set(a.ids.split(","))
        pairs = [p for p in pairs if p["id"] in want]
    print(f"ORION_JOERN_HEAP_GB={os.environ.get('ORION_JOERN_HEAP_GB', '(unset: 75% of RAM)')}")
    db = None if a.no_db else GraphDB()
    try:
        res = build_all(pairs, a.mirrors, a.work, ledger=a.ledger, order=a.order, db=db,
                        keep_cpg_dir=a.keep_cpg_dir, retry=tuple(x for x in a.retry.split(",") if x),
                        limit=a.limit)
    finally:
        if db is not None:
            db.close()
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
