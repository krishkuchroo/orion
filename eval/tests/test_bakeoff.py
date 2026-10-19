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
    assert out["peak_rss_mb"] is None or out["peak_rss_mb"] > 0
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
