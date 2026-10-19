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


def _pairs(stage2_cases: list[dict]) -> list[dict]:
    """Train-split (vulnerable trace, patched trace) pairs, grouped by `meta.pair_id`; a pair missing
    either side, or whose vulnerable trace has no final lead, is dropped (no pair test is possible)."""
    sides: dict[str, dict] = {}
    for tr in stage2_cases:
        meta = tr.get("meta") or {}
        if meta.get("split") != "train" or meta.get("label") not in ("vulnerable", "patched"):
            continue
        sides.setdefault(meta["pair_id"], {})[meta["label"]] = tr
    out = []
    for pid, s in sides.items():
        leads = (s.get("vulnerable") or {}).get("actions", [{}])[-1].get("leads") or []
        if "patched" in s and leads:
            out.append({"pair_id": pid, "vulnerable": s["vulnerable"], "patched": s["patched"],
                        "fix_site": leads[0]})
    return out


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


def rollout_round(stage2_cases, db, load, model_path, *, samples: int, seed: int) -> list[dict]:
    """Sample `samples` sessions per train-split pair, keep each pair's shortest passing trace.

    `stage2_cases` are Stage 2 trace rows (`stage2.trace_for`): the vulnerable and patched trace of a
    pair share `meta.pair_id`; non-train rows are skipped. Sample i loads the model with `seed + i`; the
    scan ids are `<pair_id>:vulnerable|patched` (`build._side_record`) and the repo trees come from
    `meta.vulnerable_repo` / `meta.patched_repo` (read_code is the only user). A sample passes when
    `pair_test` holds and both sessions are clean (see `_session`). Returns one trace row per pair with a
    passing sample: `{case, actions, results, meta}` with `meta.rollout_seed`, ready for `examples.cut`.
    It does not train: see the module docstring for the caller's retrain-from-base contract."""
    pairs = _pairs(stage2_cases)
    cands: dict[str, list[dict]] = {p["pair_id"]: [] for p in pairs}
    for i in range(samples):
        model = load(model_path, seed=seed + i)
        for p in pairs:
            v, p_ = p["vulnerable"], p["patched"]
            vm, pm = v.get("meta") or {}, p_.get("meta") or {}
            vl, va, vr, vok = _session(model, db, v, f"{p['pair_id']}:vulnerable", vm.get("vulnerable_repo") or "")
            pl, _, _, pok = _session(model, db, p_, f"{p['pair_id']}:patched", pm.get("patched_repo") or "")
            passes = vok and pok and pair_test(vl, pl, p["fix_site"])
            cands[p["pair_id"]].append({"trace": va, "results": vr, "passes": passes, "seed": seed + i})
    out = []
    for p in pairs:
        best = _best(cands[p["pair_id"]])
        if best is not None:
            v = p["vulnerable"]
            out.append({"case": v["case"], "actions": best["trace"], "results": best["results"],
                        "meta": {**(v.get("meta") or {}), "tier": "rollout", "rollout_seed": best["seed"]}})
    return out
