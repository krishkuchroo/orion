import json
import os
import re
import signal
import subprocess
import tempfile

import pytest

from orion.graph import profiles
from orion.graph_build import _event
from train import build
from train.tests._git import GitRepo, bare_mirror

pytestmark = pytest.mark.usefixtures("hermetic_git")

PKG = json.dumps({"name": "app", "dependencies": {"express": "^4.0.0"}})
VULN = "app.get('/', (req, res) => res.send(eval(req.query.x)));\n"
FIXED = "app.get('/', (req, res) => res.send(String(req.query.x)));\n"


# ───────────────────────────── resolve_commits (real git) ─────────────────────────────

def test_resolve_commits_linear_uses_parent_of_earliest_fix_and_latest_fix(tmp_path):
    """Linear multi-commit fix: vulnerable = parent of the EARLIEST fix (by ancestry), patched = the
    LATEST; guards against trusting the listed order or using only `fix_sha`, and against keeping an
    abbreviated sha."""
    r = GitRepo(tmp_path / "src")
    a = r.commit({"app.js": "v1\n"}, "base")
    b = r.commit({"app.js": "v2\n"}, "fix part 1")
    r.commit({"other.js": "x\n"}, "unrelated")
    d = r.commit({"app.js": "v3\n"}, "fix part 2")
    m = bare_mirror(r.path, tmp_path / "m.git")
    out = build.resolve_commits({"id": "X", "fix_sha": d[:10], "fix_shas": [d[:10], b]}, m)
    assert out["status"] == "ok"
    assert (out["vulnerable"], out["patched"]) == (a, d)
    assert out["multi_commit_nonlinear"] is False
    assert sorted(out["fix_shas"]) == sorted([b, d])


def test_resolve_commits_backport_falls_back_to_first_fix_with_flag(tmp_path):
    """Fix commits on two branches (a backport): no single patched commit contains all of them, so the
    pair becomes (first^, first) and is flagged multi_commit_nonlinear; guards against picking a
    'last' commit that is missing half the fix."""
    r = GitRepo(tmp_path / "src")
    a = r.commit({"app.js": "v1\n"}, "base")
    b = r.commit({"app.js": "fixed on main\n"}, "fix")
    r.checkout("-b", "release", a)
    c = r.commit({"app.js": "fixed on release\n"}, "backport")
    m = bare_mirror(r.path, tmp_path / "m.git")
    out = build.resolve_commits({"id": "X", "fix_sha": b, "fix_shas": [b, c]}, m)
    assert out["status"] == "ok"
    assert (out["vulnerable"], out["patched"]) == (a, b)
    assert out["multi_commit_nonlinear"] is True


def test_resolve_commits_root_commit_is_no_parent(tmp_path):
    """A fix that is the repo's root commit has no vulnerable side: status no_parent (skipped), never a
    crash or a made-up commit."""
    r = GitRepo(tmp_path / "src")
    a = r.commit({"app.js": "v1\n"}, "root")
    m = bare_mirror(r.path, tmp_path / "m.git")
    out = build.resolve_commits({"id": "X", "fix_sha": a, "fix_shas": [a]}, m)
    assert out["status"] == "no_parent" and out["vulnerable"] is None


def test_resolve_commits_unknown_sha_is_commit_missing(tmp_path):
    """A fix sha the mirror does not have (and cannot fetch) is recorded as commit_missing; guards
    against a git error aborting the whole run."""
    r = GitRepo(tmp_path / "src")
    r.commit({"app.js": "v1\n"}, "root")
    m = bare_mirror(r.path, tmp_path / "m.git")
    out = build.resolve_commits({"id": "X", "fix_sha": "f" * 40, "fix_shas": ["f" * 40]}, m)
    assert out["status"] == "commit_missing" and "f" * 40 in out["reason"]


# ───────────────────────────── build_pair (injected builder) ─────────────────────────────

@pytest.fixture
def js_repo(tmp_path):
    """Express app with a committed stray cpg.bin; one fix commit."""
    r = GitRepo(tmp_path / "src")
    vuln = r.commit({"package.json": PKG, "app.js": VULN, "cpg.bin": b"stale"}, "base")
    fix = r.commit({"app.js": FIXED}, "fix")
    return r, vuln, fix


def _pair(fix, **kw):
    p = {"id": "GHSA-abcd", "repo": "o/app", "language": "js", "cwe_class": "dataflow",
         "fix_sha": fix, "fix_shas": [fix]}
    p.update(kw)
    return p


def test_build_pair_forces_stream_explicit_language_and_lm_profile(tmp_path, js_repo):
    """Both commits are built in order, each with stream=True, the Joern frontend passed explicitly
    and the lm-sink profile, on a .git-free tree of the right commit with no stray cpg.bin; guards
    against build()'s stream=False default, language auto-detection, the default profile, and Joern
    silently reusing a committed cpg.bin."""
    r, _, fix = js_repo
    m = bare_mirror(r.path, tmp_path / "m.git")
    calls = []

    def builder(tree, language=None, on_event=None, *, stream=False, scan_id=None, profile=None, **kw):
        calls.append({"scan_id": scan_id, "language": language, "stream": stream, "profile": profile,
                      "app": open(os.path.join(tree, "app.js")).read(),
                      "git": os.path.exists(os.path.join(tree, ".git")),
                      "stray": os.path.exists(os.path.join(tree, "cpg.bin"))})
        return scan_id

    out = build.build_pair(_pair(fix), m, str(tmp_path / "work"), builder=builder)
    assert [c["scan_id"] for c in calls] == ["GHSA-abcd:vulnerable", "GHSA-abcd:patched"]
    assert all(c["stream"] is True and c["language"] == "jssrc" for c in calls)
    assert all(c["profile"] == profiles.with_lm_sinks(profiles.EXPRESS) for c in calls)
    assert [c["app"] for c in calls] == [VULN, FIXED]
    assert not any(c["git"] or c["stray"] for c in calls)
    assert out["status"] == "ok" and out["mirror"] == m
    # the fix hunks are stored with the build, so the yield step does not need the mirror any more
    assert [(h["file"], h["old_start"], h["new_start"]) for h in out["hunks"]] == [("app.js", 1, 1)]
    assert (out["vulnerable_scan_id"], out["patched_scan_id"]) == ("GHSA-abcd:vulnerable", "GHSA-abcd:patched")


def test_build_pair_records_joern_failure_instead_of_raising(tmp_path, js_repo):
    """A joern-parse RuntimeError becomes status=build_failed with the reason kept, and the patched
    side is not attempted; guards against one bad repo crashing an overnight run."""
    r, _, fix = js_repo
    m = bare_mirror(r.path, tmp_path / "m.git")
    calls = []

    def builder(tree, language=None, on_event=None, *, stream=False, scan_id=None, **kw):
        calls.append(scan_id)
        raise RuntimeError("joern-parse failed (rc=1):\nout of memory")

    out = build.build_pair(_pair(fix), m, str(tmp_path / "work"), builder=builder)
    assert out["status"] == "build_failed" and "joern-parse failed" in out["reason"]
    assert out["sides"]["vulnerable"]["status"] == "build_failed"
    assert calls == ["GHSA-abcd:vulnerable"]


def test_build_pair_cleans_temp_dirs_and_keeps_cpg_only_when_asked(tmp_path, js_repo):
    """orion_cpg_*/orion_stream_* temp dirs and exported trees are removed after each side; with
    keep_cpg_dir each commit's cpg.bin is moved there as <id>.<side>.cpg.bin and its real size is
    recorded; guards against filling the disk and against losing CPGs we chose to keep."""
    r, _, fix = js_repo
    m = bare_mirror(r.path, tmp_path / "m.git")
    made = []

    def builder(tree, language=None, on_event=None, *, stream=False, scan_id=None, **kw):
        cpg = tempfile.mkdtemp(prefix="orion_cpg_")
        with open(os.path.join(cpg, "cpg.bin"), "wb") as fh:
            fh.write(b"x" * 1234)
        made.extend([cpg, tempfile.mkdtemp(prefix="orion_stream_"), tree])
        return scan_id

    keep = tmp_path / "keep"
    out = build.build_pair(_pair(fix), m, str(tmp_path / "work"), builder=builder, keep_cpg_dir=str(keep))
    assert made and not any(os.path.exists(d) for d in made)
    assert sorted(os.listdir(keep)) == ["GHSA-abcd.patched.cpg.bin", "GHSA-abcd.vulnerable.cpg.bin"]
    assert (keep / "GHSA-abcd.vulnerable.cpg.bin").stat().st_size == 1234
    assert out["sides"]["vulnerable"]["cpg_bin_bytes"] == 1234

    made.clear()
    out = build.build_pair(_pair(fix), m, str(tmp_path / "work2"), builder=builder)
    assert not any(os.path.exists(d) for d in made)
    leftovers = [f for _, _, fs in os.walk(tmp_path / "work2") for f in fs if f == "cpg.bin"]
    assert leftovers == [] and out["sides"]["patched"]["cpg_bin_kept"] is None


class StubDB:
    def __init__(self, counts=None):
        self.counts, self.cleared = counts or {}, []

    def node_count(self, scan_id):
        return self.counts.get(scan_id, 0)

    def clear_scan(self, scan_id):
        self.cleared.append(scan_id)

    def run_cypher(self, scan_id, query, limit=50, **kw):
        return {"rows": [{"c": sum(self.counts.values())}], "row_count": 1, "query_type": "r"}


def test_build_pair_timings_come_from_builder_events_and_missing_ones_are_null(tmp_path, js_repo):
    """Stage timings, node/edge counts and the Neo4j node count are copied from what graph_build and
    the DB actually report; a stage the builder never reported is null; guards against estimating or
    defaulting numbers (research-data rule)."""
    r, _, fix = js_repo
    m = bare_mirror(r.path, tmp_path / "m.git")

    def builder(tree, language=None, on_event=None, *, stream=False, scan_id=None, **kw):
        for d in ("parse (cpg.bin): 2.5s", "consume (stream envelope): 7.0s", "reachability: 3/9 methods, "
                  "4/20 calls reachable from an entry point", "pathfind: 0.5s", "persist: 3.0s",
                  "TOTAL graph build: 14.0s (120 nodes, 300 edges)"):
            on_event(_event("build", "timing", detail=d))
        return scan_id

    db = StubDB({"GHSA-abcd:vulnerable": 118})
    out = build.build_pair(_pair(fix), m, str(tmp_path / "work"), builder=builder, db=db)
    v = out["sides"]["vulnerable"]
    t = v["timings"]
    assert (t["parse_s"], t["stream_s"], t["pathfind_s"], t["persist_s"], t["graph_total_s"]) == (2.5, 7.0, 0.5, 3.0, 14.0)
    assert t["normalize_s"] is None and t["reachability_s"] is None   # never reported -> null
    assert isinstance(t["export_s"], float) and isinstance(t["side_total_s"], float)
    assert (v["n_nodes"], v["n_edges"], v["neo4j_nodes"]) == (120, 300, 118)
    assert v["cpg_bin_bytes"] is None                                  # builder made no cpg.bin
    out2 = build.build_pair(_pair(fix), m, str(tmp_path / "w2"), builder=builder)
    assert out2["sides"]["vulnerable"]["neo4j_nodes"] is None          # no DB -> null, not 0


def test_children_run_outside_the_terminal_process_group():
    """Subprocesses started inside a build (joern-parse, the stream producer) get their own session,
    so a terminal Ctrl-C reaches only the orchestrator; guards against Ctrl-C killing Joern mid-side
    (which would then look like a build failure instead of a clean stop)."""
    probe = ["sh", "-c", "ps -o pgid= -p $$"]
    with build._children_detached():
        inside = int(subprocess.run(probe, capture_output=True, text=True).stdout)
    outside = int(subprocess.run(probe, capture_output=True, text=True).stdout)
    assert inside != os.getpgrp() and outside == os.getpgrp()


# ───────────────────────────── build_all (resumable / ordered / stoppable) ─────────────────────────────

@pytest.fixture
def multi(tmp_path):
    """One upstream repo with four independent fix commits, reachable only through a runner that maps
    the GitHub URL to the local path (stands in for the network)."""
    r = GitRepo(tmp_path / "src")
    r.commit({"package.json": PKG, "app.js": VULN}, "base")
    fixes = [r.commit({f"f{i}.js": f"fix {i}\n"}, f"fix {i}") for i in range(4)]
    local = {"https://github.com/o/app.git": r.path}

    def run(cmd):
        return subprocess.run([local.get(c, c) for c in cmd], capture_output=True, text=True, check=True).stdout

    classes = ["other", "dataflow", "unknown", "dataflow"]
    pairs = [_pair(f, id=f"P{i + 1}", cwe_class=c) for i, (f, c) in enumerate(zip(fixes, classes))]
    return pairs, run


def _ledger(path):
    return [json.loads(x) for x in open(path).read().splitlines()]


def _recorder(calls, fail=None, sigint_on=None, kbi_on=None):
    def builder(tree, language=None, on_event=None, *, stream=False, scan_id=None, **kw):
        calls.append(scan_id)
        if scan_id == fail:
            raise RuntimeError("joern-parse failed (rc=137)")
        if scan_id == sigint_on:
            os.kill(os.getpid(), signal.SIGINT)
        if scan_id == kbi_on:
            raise KeyboardInterrupt
        return scan_id
    return builder


def test_build_all_skips_pairs_already_in_ledger(tmp_path, multi):
    """A rerun skips every pair whose ledger line is final and appends exactly one line per newly
    finished pair; guards against redoing hours of Joern work after a restart."""
    pairs, run = multi
    ledger = tmp_path / "builds.jsonl"
    ledger.write_text(json.dumps({"id": "P2", "status": "ok"}) + "\n")
    calls = []
    build.build_all(pairs[:2], str(tmp_path / "mirrors"), str(tmp_path / "work"), ledger=str(ledger),
                    on_event=lambda *_: None, builder=_recorder(calls), run=run)
    assert calls == ["P1:vulnerable", "P1:patched"]
    rows = _ledger(ledger)
    assert [(x["id"], x["status"]) for x in rows] == [("P2", "ok"), ("P1", "ok")]


def test_build_all_dataflow_first_order_and_progress_lines(tmp_path, multi):
    """order='dataflow_first' (the default) builds cwe_class=dataflow pairs first, keeping the input
    order within each group, and prints '[i/N] <id> <side> ... <s>s' per side; guards against the
    most useful pairs waiting behind 'other'/'unknown' ones and against an unwatchable run."""
    pairs, run = multi
    calls, lines = [], []
    build.build_all(pairs, str(tmp_path / "mirrors"), str(tmp_path / "work"),
                    ledger=str(tmp_path / "b.jsonl"), on_event=lines.append, builder=_recorder(calls), run=run)
    assert [c.split(":")[0] for c in calls[::2]] == ["P2", "P4", "P1", "P3"]
    assert any(re.match(r"^\[1/4\] P2 vulnerable .* \d+\.\ds$", x) for x in lines)
    assert any(re.match(r"^\[4/4\] P3 patched .* \d+\.\ds$", x) for x in lines)


def test_build_all_keeps_going_after_a_build_failure(tmp_path, multi):
    """A pair whose Joern build fails is written to the ledger as build_failed and the run moves on to
    the next pair; guards against one failure stopping the batch."""
    pairs, run = multi
    calls = []
    build.build_all(pairs[:2], str(tmp_path / "mirrors"), str(tmp_path / "work"),
                    ledger=str(tmp_path / "b.jsonl"), on_event=lambda *_: None, order="as_given",
                    builder=_recorder(calls, fail="P1:vulnerable"), run=run)
    rows = _ledger(tmp_path / "b.jsonl")
    assert [(x["id"], x["status"]) for x in rows] == [("P1", "build_failed"), ("P2", "ok")]
    assert "rc=137" in rows[0]["reason"]


def test_build_all_sigint_finishes_current_side_writes_ledger_and_stops(tmp_path, multi):
    """Ctrl-C (SIGINT) mid-side lets that side finish, writes the pair's ledger line as 'interrupted',
    starts nothing else, returns normally and restores the old handler; the next run rebuilds that pair
    instead of skipping it; guards against a half-built pair being lost or mistaken for finished."""
    pairs, run = multi
    before = signal.getsignal(signal.SIGINT)
    calls = []
    res = build.build_all(pairs, str(tmp_path / "mirrors"), str(tmp_path / "work"),
                          ledger=str(tmp_path / "b.jsonl"), on_event=lambda *_: None,
                          builder=_recorder(calls, sigint_on="P2:vulnerable"), run=run)
    assert calls == ["P2:vulnerable"] and res["stopped"] is True
    (row,) = _ledger(tmp_path / "b.jsonl")
    assert row["id"] == "P2" and row["status"] == "interrupted"
    assert row["sides"]["vulnerable"]["status"] == "ok" and row["sides"]["patched"]["status"] == "not_built"
    assert signal.getsignal(signal.SIGINT) is before

    calls.clear()
    build.build_all(pairs[1:2], str(tmp_path / "mirrors"), str(tmp_path / "work"),
                    ledger=str(tmp_path / "b.jsonl"), on_event=lambda *_: None,
                    builder=_recorder(calls), run=run)
    assert calls == ["P2:vulnerable", "P2:patched"]
    assert _ledger(tmp_path / "b.jsonl")[-1]["status"] == "ok"


def test_build_all_keyboardinterrupt_still_writes_ledger_line(tmp_path, multi):
    """A KeyboardInterrupt raised inside a build (e.g. a second Ctrl-C) is caught: the side is
    'interrupted', the ledger line is still written and build_all returns cleanly; guards against
    losing the record of what was already measured."""
    pairs, run = multi
    calls = []
    res = build.build_all(pairs, str(tmp_path / "mirrors"), str(tmp_path / "work"),
                          ledger=str(tmp_path / "b.jsonl"), on_event=lambda *_: None,
                          builder=_recorder(calls, kbi_on="P2:patched"), run=run)
    assert res["stopped"] is True and calls == ["P2:vulnerable", "P2:patched"]
    (row,) = _ledger(tmp_path / "b.jsonl")
    assert row["status"] == "interrupted" and row["sides"]["patched"]["status"] == "interrupted"
    assert row["sides"]["vulnerable"]["status"] == "ok"


def test_evict_clears_exactly_the_named_scans():
    """evict() deletes each named scan through GraphDB.clear_scan and nothing else; guards against a
    capacity cleanup touching scans it was not asked to remove."""
    db = StubDB()
    out = build.evict(["P1:vulnerable", "P1:patched"], db)
    assert db.cleared == ["P1:vulnerable", "P1:patched"]
    assert out == {"P1:vulnerable": "evicted", "P1:patched": "evicted"}
