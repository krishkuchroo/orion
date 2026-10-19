from types import SimpleNamespace

from orion.lm import format as fmt
from train import rounds

FIX = {"file": "a.js", "line": 10, "function": "f", "line_start": 10, "line_end": 10}


def test_pair_test_flag_vuln_silent_patched():
    assert rounds.pair_test([{"file": "a.js", "line": 10, "function": "f"}], [{"file": "b.js", "line": 99, "function": "o"}], FIX)
    assert not rounds.pair_test([{"file": "a.js", "line": 10, "function": "f"}], [{"file": "a.js", "line": 10, "function": "f"}], FIX)


def test_pair_test_rejects_spray():
    v = [{"file": "a.js", "line": 10, "function": "f"}, {"file": "z.js", "line": 1, "function": "g"}, {"file": "y.js", "line": 2, "function": "h"}]
    assert not rounds.pair_test(v, [], FIX)


def test_pair_test_one_hit_one_miss_passes_and_no_hit_fails():
    hit, miss = {"file": "a.js", "line": 10, "function": "f"}, {"file": "z.js", "line": 1, "function": "g"}
    assert rounds.pair_test([hit, miss], [], FIX)
    assert not rounds.pair_test([miss], [], FIX)
    assert not rounds.pair_test([], [], FIX)


def test_pick_shortest_passing_and_stop_rule():
    assert rounds._pick([{"trace": [1, 2, 3], "passes": True}, {"trace": [1, 2], "passes": True}, {"trace": [1], "passes": False}]) == [1, 2]
    assert rounds.should_stop([{"pair_correct": 0.3}, {"pair_correct": 0.3}]) and not rounds.should_stop([{"pair_correct": 0.1}, {"pair_correct": 0.2}])


def test_pick_none_and_should_stop_edges():
    assert rounds._pick([{"trace": [1], "passes": False}]) is None
    assert not rounds.should_stop([]) and not rounds.should_stop([{"pair_correct": 0.0}])
    assert rounds.should_stop([{"pair_correct": 0.1}, {"pair_correct": 0.2}, {"pair_correct": 0.3}])


# ---- rollout_round, with stubbed load / generate / db ----

LEAD = {"flow_id": "F0", "file": "a.js", "function": "f", "line": 10, "cwe": "CWE-89", "confidence": "HIGH"}
OTHER = {"flow_id": "F0", "file": "b.js", "function": "o", "line": 99, "cwe": "CWE-89", "confidence": "HIGH"}
CASE = {"flow_id": "F0", "rank": 0, "sink_category": None, "source_uid": None, "sink_uid": None, "nodes": [],
        "snippets": [{"role": "target", "file": "a.js", "function": "f", "start": 1, "end": 20, "code": "x"}]}
Q = "MATCH (c:CpgCall {scan_id:$scan_id}) RETURN c.code"


def _trace(pid, label, split="train"):
    final = {"action": "final", "leads": [LEAD] if label == "vulnerable" else []}
    return {"case": CASE, "actions": [{"action": "run_cypher", "query": Q}, final], "results": [{"row_count": 1}],
            "meta": {"pair_id": pid, "split": split, "label": label, "tier": "graph"}}


class FakeDB:
    def run_cypher(self, scan_id, query, limit=50, **kw):      # same contract as GraphDB.run_cypher(bounded=True)
        if query.startswith("EXPLAIN"):
            return {"row_count": 0, "rows": [], "query_type": "r"}
        return {"row_count": 1, "rows": [{"c.code": "exec(x)"}]}


def _res(text):
    return SimpleNamespace(text=text, prompt_tokens=1, completion_tokens=1, cached_tokens=0, spliced=False)


class FakeModel:
    """Replies per `script`: a list of lead-lists per session; each session = one run_cypher then a final."""
    def __init__(self, leads_by_session):
        self.sessions, self.n, self.turn = leads_by_session, -1, 0

    def reset_cache(self):
        self.n += 1
        self.turn = 0

    def generate(self, messages):
        self.turn += 1
        if self.turn == 1:
            return _res(fmt.dumps_action({"action": "run_cypher", "query": Q}))
        return _res(fmt.dumps_action({"action": "final", "leads": self.sessions[self.n]}))


def test_rollout_round_skips_non_train_seeds_and_drops_failures():
    seeds = []
    # sample 0 sprays nothing but misses the fix site; sample 1 hits it on the vulnerable scan, silent on patched
    plans = {10: FakeModel([[OTHER], []]), 11: FakeModel([[LEAD], []])}

    def load(path, *, seed):
        seeds.append((path, seed))
        return plans[seed]

    cases = [_trace("P1", "vulnerable"), _trace("P1", "patched"),
             _trace("T1", "vulnerable", split="test"), _trace("T1", "patched", split="test"),
             _trace("N1", "vulnerable")]            # no patched side: dropped
    out = rounds.rollout_round(cases, FakeDB(), load, "base", samples=2, seed=10)
    assert seeds == [("base", 10), ("base", 11)]
    assert [r["meta"]["pair_id"] for r in out] == ["P1"]
    assert out[0]["meta"]["rollout_seed"] == 11 and out[0]["meta"]["tier"] == "rollout"
    assert [a["action"] for a in out[0]["actions"]] == ["run_cypher", "final"] and len(out[0]["results"]) == 1


def test_rollout_round_no_passing_sample_yields_nothing():
    def load(path, *, seed):
        return FakeModel([[OTHER], []])

    assert rounds.rollout_round([_trace("P1", "vulnerable"), _trace("P1", "patched")], FakeDB(), load, "base",
                                samples=2, seed=0) == []
