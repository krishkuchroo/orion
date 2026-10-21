import json

from orion.lm.model import GenResult
from eval import bakeoff

CASE = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
        "snippets": [{"role": "target", "file": "a.py", "function": "f", "start": 1, "end": 2, "code": "x"}]}
LEAD = {"flow_id": "F0", "file": "a.py", "function": "f", "line": 1, "cwe": "CWE-89", "confidence": "HIGH"}
FIELDS = {"n", "vuln_recall", "patched_silence", "negative_silence", "pair_correct", "parse_fail_rate",
          "tokens", "tok_per_s", "model", "peak_rss_mb", "train_cutoff"}


def _dev(k):
    rows = []
    for i in range(k):
        rows.append({"pair_id": f"P{i}", "label": "vulnerable", "case": CASE, "lead": LEAD, "split": "dev"})
        rows.append({"pair_id": f"P{i}", "label": "patched", "case": CASE, "lead": None, "split": "dev"})
    rows.append({"pair_id": "X", "label": "vulnerable", "case": CASE, "lead": LEAD, "split": "train"})
    return rows


class Scripted:
    def __init__(self, log):
        self.log = log

    def generate(self, messages):
        self.log.append(messages[1]["content"])
        return GenResult(text=json.dumps({"action": "final", "leads": []}), prompt_tokens=5,
                         completion_tokens=1, cached_tokens=0)


def test_run_candidate_fields_and_loaded_path():
    log, paths = [], []

    def load(path):
        paths.append(path)
        return Scripted(log)

    out = bakeoff.run_candidate("m/a", _dev(3), schema_text="S", load=load, sample_n=4, seed=1,
                                train_cutoff="2025-01")
    assert FIELDS <= set(out) and out["model"] == "m/a" and paths == ["m/a"]
    assert out["train_cutoff"] == "2025-01" and out["n"] == 4 and len(log) == 4
    assert out["peak_rss_mb"] is None  # in-process: a whole-process high-water mark would mislead
    assert bakeoff.run_candidate("m/a", _dev(3), schema_text="S", load=load, sample_n=4)["train_cutoff"] is None


def test_sample_identical_across_candidates_and_seeded():
    la, lb, lc = [], [], []
    bakeoff.run_candidate("a", _dev(10), schema_text="S", load=lambda p: Scripted(la), sample_n=6, seed=0)
    bakeoff.run_candidate("b", _dev(10), schema_text="S", load=lambda p: Scripted(lb), sample_n=6, seed=0)
    bakeoff.run_candidate("c", _dev(10), schema_text="S", load=lambda p: Scripted(lc), sample_n=6, seed=5)
    assert la == lb and len(la) == 6


def test_table_names_every_model():
    rows = [{"model": "gemma-e4b", "n": 4, "vuln_recall": 0.5, "patched_silence": 1.0, "negative_silence": None,
             "pair_correct": 0.5, "parse_fail_rate": 0.0, "tokens": 10, "tok_per_s": None,
             "peak_rss_mb": None, "train_cutoff": None},
            {"model": "granite-8b", "n": 4, "vuln_recall": 0.25, "patched_silence": 0.5, "negative_silence": 1.0,
             "pair_correct": 0.25, "parse_fail_rate": 0.1, "tokens": 12, "tok_per_s": 3.5,
             "peak_rss_mb": 4096.0, "train_cutoff": "2025-06"}]
    t = bakeoff.table(rows)
    assert "gemma-e4b" in t and "granite-8b" in t and "n/a" in t and "4096" in t


def test_isolated_uses_ru_maxrss(monkeypatch):
    import resource
    import sys

    class RU:
        ru_maxrss = 3 * 1024 * 1024  # bytes on macOS, KB on Linux: both give 3 MB / 3072 MB below

    monkeypatch.setattr(resource, "getrusage", lambda who: RU)
    out = bakeoff.run_candidate("m", _dev(1), schema_text="S", load=lambda p: Scripted([]), isolated=True)
    assert out["peak_rss_mb"] == (3.0 if sys.platform == "darwin" else 3072.0)


def test_run_all_spawns_one_child_per_candidate_and_parses_json():
    cmds = []

    def runner(cmd):
        cmds.append(cmd)
        m = cmd[cmd.index("--one") + 1]
        return "noise line\n" + json.dumps({"model": m, "n": 1, "peak_rss_mb": 12.5})

    rows = bakeoff.run_all(["a", "b"], "dev.jsonl", sample_n=7, seed=3, train_cutoffs={"a": "2025-01"}, run=runner)
    assert [r["model"] for r in rows] == ["a", "b"] and len(cmds) == 2
    assert "eval.bakeoff" in cmds[0] and "--sample-n" in cmds[0] and "7" in cmds[0]
    assert "--train-cutoff" in cmds[0] and "--train-cutoff" not in cmds[1]


def _flaky(bad_output):
    def runner(cmd):
        m = cmd[cmd.index("--one") + 1]
        if m == "bad":
            if isinstance(bad_output, Exception):
                raise bad_output
            return bad_output
        return json.dumps({"model": m, "n": 1, "peak_rss_mb": 1.0})
    return runner


def _check_error_row(rows):
    assert [r["model"] for r in rows] == ["a", "bad", "c"]
    assert rows[0]["n"] == 1 and rows[2]["n"] == 1
    bad = rows[1]
    assert bad["error"] and set(bakeoff.COLUMNS) - {"model"} <= set(bad)
    assert all(bad[c] is None for c in bakeoff.COLUMNS if c != "model")


def test_run_all_child_crash_becomes_error_row():
    import subprocess
    exc = subprocess.CalledProcessError(1, ["x"], output="", stderr="Traceback\nOOM killed")
    _check_error_row(bakeoff.run_all(["a", "bad", "c"], "d.jsonl", run=_flaky(exc)))
    rows = bakeoff.run_all(["a", "bad", "c"], "d.jsonl", run=_flaky(exc))
    assert "OOM killed" in rows[1]["error"]


def test_run_all_empty_output_becomes_error_row():
    _check_error_row(bakeoff.run_all(["a", "bad", "c"], "d.jsonl", run=_flaky("  \n")))


def test_run_all_non_json_last_line_becomes_error_row():
    _check_error_row(bakeoff.run_all(["a", "bad", "c"], "d.jsonl", run=_flaky("ok\nnot json")))


def test_sample_dev_reads_stage2_traces_and_skips_train_traces():
    """Final review I5: traces carry pair_id/split/label under `meta`; a train trace is never dev."""
    import pytest

    def trace(pid, label, split):
        return {"case": CASE, "actions": [{"action": "final", "leads": [LEAD] if label == "vulnerable" else []}],
                "results": [], "meta": {"pair_id": pid, "split": split, "label": label}}

    rows = [trace("P", "vulnerable", "dev"), trace("P", "patched", "dev"), trace("T", "vulnerable", "train")]
    out = bakeoff.sample_dev(rows, sample_n=10, seed=0)
    assert [(r["meta"]["pair_id"], r["meta"]["label"]) for r in out] == [("P", "patched"), ("P", "vulnerable")]
    with pytest.raises(ValueError, match="split"):
        bakeoff.sample_dev([{"pair_id": "P", "label": "vulnerable", "case": CASE, "lead": LEAD}], sample_n=10, seed=0)
