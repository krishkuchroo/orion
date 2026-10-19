"""Pair test and ReST-EM rollout-round helpers for Stage 2 graph traces.

`pair_test` is the acceptance rule for a sampled session pair: the model flags the fix site on the
vulnerable scan, stays silent there on the patched scan, and does not spray. `rollout_round` only
SAMPLES and filters; it never trains.

Caller's contract (ReST-EM): every round retrains from the BASE model on the kept rows plus the original
data, never from the previous round's checkpoint, so `model_path` is the base model each round or the
adapter trained from it. Rounds run only when Stage 2 has multi-step traces (templates exist).
"""
from __future__ import annotations

from eval import match
from orion.lm import format as fmt
from orion.lm import tools

MAX_ROUNDS = 3


def pair_test(vuln_leads: list[dict], patched_leads: list[dict], fix_site: dict) -> bool:
    """True iff a vulnerable lead matches the fix site, no patched lead does, and at most one vulnerable
    lead misses it (anti-spray). Matching is `eval.match.l1_fix_site`: the Stage 2 fix site is the
    vulnerable trace's final lead, a single {file, line, function}."""
    hits = sum(1 for ld in vuln_leads if match.l1_fix_site(ld, fix_site))
    if hits == 0 or any(match.l1_fix_site(ld, fix_site) for ld in patched_leads):
        return False
    return len(vuln_leads) - hits <= 1


def _best(candidates: list[dict]) -> dict | None:
    passing = [c for c in candidates if c.get("passes")]
    return min(passing, key=lambda c: len(c["trace"])) if passing else None


def _pick(candidates: list[dict]) -> list | None:
    """The shortest passing trace (first wins a tie), or None when no candidate passes."""
    best = _best(candidates)
    return None if best is None else best["trace"]


def should_stop(dev_scores: list[dict]) -> bool:
    """Stop after 3 rounds, or when `pair_correct` did not improve on the previous round."""
    if len(dev_scores) >= MAX_ROUNDS:
        return True
    return len(dev_scores) >= 2 and dev_scores[-1]["pair_correct"] <= dev_scores[-2]["pair_correct"]


def _pairs(stage2_cases: list[dict], on_event=None) -> list[dict]:
    """Train-split (vulnerable trace, patched trace) pairs, grouped by `meta.pair_id`. A pair missing a
    side (`unpaired`) or whose vulnerable trace has no final lead (`no_lead`) is dropped with a skip event:
    no pair test is possible."""
    sides: dict[str, dict] = {}
    for tr in stage2_cases:
        meta = tr.get("meta") or {}
        if meta.get("split") != "train" or meta.get("label") not in ("vulnerable", "patched"):
            continue
        sides.setdefault(meta["pair_id"], {})[meta["label"]] = tr
    out = []
    for pid, s in sides.items():
        if "vulnerable" not in s or "patched" not in s:
            _emit(on_event, kind="skip", pair_id=pid, reason="unpaired")
            continue
        leads = s["vulnerable"].get("actions", [{}])[-1].get("leads") or []
        if not leads:
            _emit(on_event, kind="skip", pair_id=pid, reason="no_lead")
            continue
        # The gold flow's sink (`stage2._lead`): from the data, not model output, and the same lead the
        # Stage 2 SFT targets teach, so the rounds reward exactly what SFT trains.
        out.append({"pair_id": pid, "vulnerable": s["vulnerable"], "patched": s["patched"],
                    "fix_site": leads[0]})
    return out


def _emit(on_event, **event) -> None:
    if on_event is not None:
        on_event(event)


def _session(model, db, trace: dict, scan_id: str, repo: str):
    """(leads, actions, results, clean) of one sampled session. `clean` = only run_cypher steps that ran,
    then a valid final: the actions are replayed through `tools.run_cypher` to rebuild the results, so a
    kept trace has the same shape as a templated one (`examples.cut`)."""
    from orion.lm import prompter
    if hasattr(model, "reset_cache"):
        model.reset_cache()
    seen: list[str] = []

    def generate(messages):
        res = model.generate(messages)
        seen.append(res.text)
        return res

    leads, steps = prompter.run_session(generate, db, repo, scan_id, [trace["case"]])
    actions = [fmt.parse_action(t) for t in seen]
    clean = (bool(steps) and steps[-1]["kind"] == "final" and steps[-1]["error"] is None
             and all(s["kind"] == "run_cypher" and s["error"] is None for s in steps[:-1])
             and all(a is not None for a in actions) and len(actions) == len(steps))
    results = []
    if clean:
        for a in actions[:-1]:
            res = tools.run_cypher(db, scan_id, a["query"])
            if "error" in res:
                clean = False
                break
            results.append(res)
    return leads, actions, results, clean


def rollout_round(stage2_cases, db, load, model_path, *, samples: int, seed: int, repo_for,
                  on_event=None) -> list[dict]:
    """Sample `samples` sessions per train-split pair, keep each pair's shortest passing trace.

    `stage2_cases` are Stage 2 trace rows (`stage2.trace_for`): the vulnerable and patched trace of a
    pair share `meta.pair_id`; non-train rows are skipped. Sample i loads the model once with `seed + i`
    and uses it for both sides (`reset_cache()` between sessions re-seeds). Scan ids are
    `<pair_id>:vulnerable|patched` (`build._side_record`); `stage2.build` EVICTS them after each pair, so
    the caller must rebuild the Stage 2 scans first. A pair whose scans are missing is skipped
    (`scan_missing`, via `db.node_count`). `repo_for(pair_id, side)` returns the source tree for `read_code`
    (side is "vulnerable" or "patched"). A sample passes when `pair_test` holds and both sessions are
    clean (see `_session`). Only the vulnerable side is emitted: one trace row per pair with a passing
    sample, `{case, actions, results, meta}` with `meta.rollout_seed`, ready for `examples.cut`.
    `on_event(dict)` gets `{"kind": "skip", "pair_id", "reason"}` (unpaired, no_lead, scan_missing,
    no_pass) and a final `{"kind": "summary", ...counts}`. It does not train: see the module docstring
    for the caller's retrain-from-base contract."""
    counts = {"pairs": 0, "unpaired": 0, "no_lead": 0, "scan_missing": 0, "no_pass": 0, "kept": 0}

    def tally(event):
        if event["kind"] == "skip":
            counts[event["reason"]] += 1
        _emit(on_event, **event)

    pairs = _pairs(stage2_cases, tally)
    live = []
    for p in pairs:
        if all(db.node_count(f"{p['pair_id']}:{side}") > 0 for side in ("vulnerable", "patched")):
            live.append(p)
        else:
            tally({"kind": "skip", "pair_id": p["pair_id"], "reason": "scan_missing"})
    cands: dict[str, list[dict]] = {p["pair_id"]: [] for p in live}
    for i in range(samples if live else 0):
        model = None                # free the previous sample's model before loading the next (16 GB)
        model = load(model_path, seed=seed + i)
        for p in live:
            pid = p["pair_id"]
            v, p_ = p["vulnerable"], p["patched"]
            vl, va, vr, vok = _session(model, db, v, f"{pid}:vulnerable", repo_for(pid, "vulnerable"))
            pl, _, _, pok = _session(model, db, p_, f"{pid}:patched", repo_for(pid, "patched"))
            passes = vok and pok and pair_test(vl, pl, p["fix_site"])
            cands[pid].append({"trace": va, "results": vr, "passes": passes, "seed": seed + i})
    out = []
    for p in live:
        best = _best(cands[p["pair_id"]])
        if best is None:
            tally({"kind": "skip", "pair_id": p["pair_id"], "reason": "no_pass"})
            continue
        v = p["vulnerable"]
        out.append({"case": v["case"], "actions": best["trace"], "results": best["results"],
                    "meta": {**(v.get("meta") or {}), "tier": "rollout", "rollout_seed": best["seed"]}})
    counts["pairs"] = len(pairs)
    counts["kept"] = len(out)
    _emit(on_event, kind="summary", **counts)
    return out
