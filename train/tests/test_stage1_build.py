import json
import os
import signal

import pytest

from orion.lm import cases
from train import snapshot, stage1
from train.tests._git import GitRepo, git

VULN = ("def view(r):\n    q = 'SELECT ' + r\n    return db.execute(q)\n\n"
        "def other(a):\n    log(a)\n    x = a\n    y = x\n    return y\n\n"
        "def third(b):\n    x = f(b)\n    y = x\n    z = y\n    return z\n")
PATCHED = VULN.replace("    q = 'SELECT ' + r\n    return db.execute(q)\n", "    return db.execute('SELECT ?', [r])\n")


def _repo(path):
    src = GitRepo(path)
    git(src.path, "config", "uploadpack.allowFilter", "true")
    git(src.path, "config", "uploadpack.allowAnySHA1InWant", "true")
    src.commit({"app.py": VULN, "README.md": "r"}, "base")
    fix = src.commit({"app.py": PATCHED}, "fix")
    return src, fix


def _pair(i, src, fix, **kw):
    return {"id": i, "repo": f"o/{i}", "repo_url": f"file://{src}", "fix_sha": fix, "cwe": ["CWE-89"],
            "cwe_class": "dataflow", "language": "py", **kw}


def _run(pairs, splits, tmp_path, **kw):
    args = dict(work_root=str(tmp_path / "w"), out_jsonl=str(tmp_path / "out.jsonl"),
                ledger=str(tmp_path / "led.jsonl"), budget=cases.CaseBudget(), n_negatives=1, seed=0,
                on_event=lambda *_: None)
    args.update(kw)
    return stage1.build(pairs, splits, **args)


def _lines(p):
    return [json.loads(l) for l in open(p).read().splitlines()]


def test_build_writes_examples_ledger_and_resumes(tmp_path, hermetic_git):
    """Pair 1 builds examples; pair 2 (unreachable repo) is recorded as failed; a rerun skips both."""
    src, fix = _repo(tmp_path / "src")
    pairs = [_pair("CVE-1", src.path, fix), _pair("CVE-2", tmp_path / "nope", fix)]
    splits = {"CVE-1": "train", "CVE-2": "dev"}
    _run(pairs, splits, tmp_path)
    rows = _lines(tmp_path / "out.jsonl")
    assert {r["label"] for r in rows} >= {"vulnerable", "patched"} and all(r["split"] == "train" for r in rows)
    led = _lines(tmp_path / "led.jsonl")
    assert [l["status"] for l in led] == ["ok", "snapshot_failed"] and led[0]["seconds_network"] > 0
    assert led[0]["bytes_clone"] > 0 and led[0]["bytes_delta"] == led[0]["bytes_clone"] and led[0]["seconds_index"] is not None and led[0]["n_examples"] == len(rows)
    assert led[0]["n_files"] == 1 and led[1]["bytes_clone"] is None and led[1]["bytes_delta"] is None and led[1]["reason"]
    assert not any((tmp_path / "w").iterdir())          # snapshots deleted
    t = _run(pairs, splits, tmp_path)
    assert len(_lines(tmp_path / "led.jsonl")) == 2 and t["pairs"] == 0   # resumed, nothing redone


def test_one_snapshot_serves_all_pairs_of_a_repo_and_missing_fix_is_recorded(tmp_path, hermetic_git):
    src, fix = _repo(tmp_path / "src")
    pairs = [_pair("A", src.path, fix), _pair("B", src.path, fix), _pair("C", src.path, "1" * 40)]
    calls = []

    def fetch(*a, **k):
        calls.append(a[0])
        return snapshot.fetch(*a, **k)

    t = _run(pairs, {p["id"]: "train" for p in pairs}, tmp_path, fetch=fetch)
    assert len(calls) == 1
    led = {l["id"]: l for l in _lines(tmp_path / "led.jsonl")}
    assert led["A"]["status"] == led["B"]["status"] == "ok" and led["C"]["status"] == "commit_missing"
    assert led["B"]["seconds_network"] > 0 and led["B"]["bytes_clone"] >= led["A"]["bytes_clone"] and led["B"]["bytes_delta"] == led["B"]["bytes_clone"] - led["A"]["bytes_clone"] and t["status"] == {"ok": 2, "commit_missing": 1}


def test_unknown_cwe_is_skipped_without_fetching(tmp_path):
    p = {"id": "U", "repo": "o/u", "repo_url": "file:///x", "fix_sha": "a" * 40, "cwe": [], "cwe_class": "unknown"}
    _run([p], {"U": "train"}, tmp_path, fetch=lambda *a, **k: pytest.fail("fetched"))
    assert _lines(tmp_path / "led.jsonl")[0]["reason"] == "no_cwe"


def test_sigint_finishes_current_pair_then_stops(tmp_path, hermetic_git):
    """Stoppable: an interrupt during pair 1 still writes pair 1's ledger line, skips pair 2, exits cleanly."""
    src, fix = _repo(tmp_path / "src")
    src2, fix2 = _repo(tmp_path / "src2")
    pairs = [_pair("A", src.path, fix), _pair("B", src2.path, fix2)]
    events = []

    def on_event(msg):
        events.append(msg)
        if msg.startswith("[1/2]"):
            signal.raise_signal(signal.SIGINT)

    before = signal.getsignal(signal.SIGINT)
    t = _run(pairs, {"A": "train", "B": "train"}, tmp_path, on_event=on_event)
    assert [l["id"] for l in _lines(tmp_path / "led.jsonl")] == ["A"] and _lines(tmp_path / "led.jsonl")[0]["status"] == "ok"
    assert t["interrupted"] is True and signal.getsignal(signal.SIGINT) is before
    assert not any((tmp_path / "w").iterdir())


def test_select_pairs_filters_and_samples_per_language_deterministically():
    ps = [{"id": f"{l}{i}", "language": l, "cwe": ["CWE-89"], "cwe_class": "dataflow"} for l in ("js", "py") for i in range(5)]
    ps.append({"id": "u", "language": "js", "cwe": [], "cwe_class": "unknown"})
    a = stage1.select_pairs(ps, per_language=2, seed=1)
    assert a == stage1.select_pairs(ps, per_language=2, seed=1) and len(a) == 4
    assert sorted(p["language"] for p in a) == ["js", "js", "py", "py"] and all(p["id"] != "u" for p in a)
    assert {p["language"] for p in stage1.select_pairs(ps, languages=["py"])} == {"py"}
    assert len(stage1.select_pairs(ps, limit=3)) == 3


def test_main_refuses_without_frozen_splits(tmp_path, capsys):
    pairs = tmp_path / "pairs.json"
    pairs.write_text("[]")
    assert stage1.main(["--pairs", str(pairs), "--splits", str(tmp_path / "none.json")]) == 2


def test_resume_reconciles_out_jsonl_after_a_crash(tmp_path, hermetic_git):
    """Examples written but no ledger line (crash), plus a torn last line: rerun leaves one copy per pair."""
    src, fix = _repo(tmp_path / "src")
    pairs = [_pair("A", src.path, fix)]
    _run(pairs, {"A": "train"}, tmp_path)
    out, led = tmp_path / "out.jsonl", tmp_path / "led.jsonl"
    n = len(_lines(out))
    led.write_text("")                                   # crash: examples on disk, ledger line never written
    out.write_text(out.read_text() + '{"pair_id": "A", "lab')   # and a torn final line
    _run(pairs, {"A": "train"}, tmp_path)
    rows = _lines(out)
    assert len(rows) == n and len({(r["label"], r["case"]["snippets"][0]["function"]) for r in rows}) == n
    assert [l["id"] for l in _lines(led)] == ["A"]


def test_reconcile_keeps_rows_of_ledgered_pairs(tmp_path, hermetic_git):
    src, fix = _repo(tmp_path / "src")
    _run([_pair("A", src.path, fix)], {"A": "train"}, tmp_path)
    n = len(_lines(tmp_path / "out.jsonl"))
    _run([_pair("A", src.path, fix), _pair("B", src.path, fix)], {"A": "train", "B": "train"}, tmp_path)
    assert {r["pair_id"] for r in _lines(tmp_path / "out.jsonl")} == {"A", "B"}
    assert sum(r["pair_id"] == "A" for r in _lines(tmp_path / "out.jsonl")) == n
