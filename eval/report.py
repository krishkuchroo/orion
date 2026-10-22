"""Scoring tables for the Orion-LM study (design spec section 6). NOT `orion/report.py`.

Reads `runs` / `matches` / `steps` / `agent_calls` / `resources` written by the harness, plus the
manifest (eval/dataset/manifest.json) and the OWASP sample, and computes the pre-registered metrics:

  primary    efficiency E_a = 1e6 * sum caught_L1 / sum T   (vulnerable-commit runs)
             false-alarm rate FAR_a = sum 1[any L1 match on patched_v] / (N*R)   (patched runs)
  decision   paired cluster bootstrap (cluster = repo) of log(E_lm / E_X), B = 10_000, 95% CI;
             Holm step-down over the frontier comparators; FAR_lm <= FAR_X + margin
  secondary  recall L1 / L2, pair-correct, pass@3 / pass^3, path levels, wall time, peak RSS,
             MLX peak, graph-build compute, list-price dollars (only with a caller-supplied price
             table), Youden J on OWASP (with the OWASP sample)

The manifest decides two things (spec 5.4 / 6), per row id (= runs.repo):
  * PARTITIONS. A table covers one partition (`partition_of`): "headline" = tier headline, kind
    dataflow (the PRIMARY analysis and the decision rule); "access_control" = tier headline, kind
    access_control; "scale" = tier scale (the pre-check moved it); each reported separately. Other
    tiers report under their own name. A run whose row id is not in the manifest is in no partition
    and is listed by `unknown_rows`, never dropped silently.
  * CLUSTERS. The bootstrap resamples REPOS (`manifest_index`: repo_canonical, else repo, else the
    owner/name of repo_url, lowercased), so two CVE rows of one repo are one cluster and `n_repos`
    counts repos. `runs.repo` stays the row id (it keeps two CVEs that share a commit distinct).
  Without a manifest (manifest=None: tests, dev DBs) every CVE run is in scope and each row id is its
  own cluster; that is NOT the pre-registered analysis (render() says so).

Which runs count (never changes anywhere in this module):
  * status in ('ok','crashed','hung','error') is terminal and SCORED; 'aborted' (a usage limit, or a
    machine failure under an orion-lm run) and 'running' rows are excluded from every sum.
    Every n is reported with the per-status counts of its run slots (`status_counts`: the latest
    attempt of each slot, ok / hung / crashed / error / aborted), so what a failure does to a rate
    is visible. Which statuses count toward FAR is a pre-registration decision (KRISH CHECK), not
    changed here: a crashed/hung/error patched run is scored with no false alarm.
  * case_id == '' only: OWASP Benchmark rows (case_id != '') feed Youden J (`youden_detail`, from
    each run's findings.json via eval.owasp.score / youden) and are NOT part of efficiency / FAR /
    recall.
  * T for a run comes from `steps` (orion-lm arms: prompt + completion; cached tokens are already
    inside prompt_tokens) or else from `agent_calls` (frontier arms: usage.total over
    uncached_in + cache_read + cache_write + out; reasoning is already inside out). A run with
    neither has T = None: it is left out of BOTH efficiency sums and reported in
    `n_no_token_data`, never counted as 0 tokens.
  * caught_L1 for (vuln, run) = any `matches` row for that vuln in that run (L1 or L2);
    caught_L2 = a row with level == 'L2'. Each run is matched against its OWN row's key
    (eval.manifest.answer_keys), so a run's caught count is 0/1.
  * One scored row per run slot: the highest attempt_no of (arm, repo, commit_sha, case_id, run_no).
  * The bootstrap is PAIRED: its clusters are the repos with token-bearing vulnerable runs in both
    arms; a repo seen in one arm only is excluded and listed (`unmatched_repos`).
  * pair-correct pairs a row's vulnerable and patched runs by (row id, sha), so a commit that serves
    two rows (a chain: one row's patched commit is another's vulnerable commit, or two CVEs share a
    vulnerable commit) is scored once per row, against that row's own runs.

Nothing here estimates a missing value. Dollars are None without a price table; `mde` is a stub.
This file is the analysis script the spec says to commit and hash into the prereg tag
(`script_hash()`).
"""
import hashlib
import json
import math
import os
import re
import statistics
import sys
from collections import Counter

import numpy as np

from eval import match as _match
from eval import usage as _usage

SCORED = ("ok", "crashed", "hung", "error")
_SCORED_SQL = "status IN ('ok','crashed','hung','error')"
STATUSES = ("ok", "hung", "crashed", "error", "aborted")   # always present in status_counts
PRIMARY = "headline"                                     # the partition of the decision rule
PARTITIONS = ("headline", "access_control", "scale")      # reported separately (spec 5.4)
_Z95 = 1.959963984540054
_GH = re.compile(r"github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", re.I)


# ---- the manifest: partitions and clusters ---------------------------------------------------------

def partition_of(row: dict) -> str:
    """The table a manifest row is reported in (module doc). A row without `kind` is dataflow."""
    tier, kind = row.get("tier"), row.get("kind") or "dataflow"
    if tier == "scale":
        return "scale"
    if tier == "headline":
        return {"dataflow": "headline", "access_control": "access_control"}.get(kind, f"headline/{kind}")
    return str(tier)


def _canonical_repo(row: dict):
    for k in ("repo_canonical", "repo"):
        if isinstance(row.get(k), str) and row[k]:
            return row[k].lower()
    m = _GH.search(row.get("repo_url") or "") if isinstance(row.get("repo_url"), str) else None
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def manifest_index(manifest) -> dict:
    """{row id: {"repo": the cluster (canonical repo, lowercased; the row id only when the row names
    no repo at all), "tier", "kind", "partition"}} from a loaded manifest {"repos": [...]}."""
    return {r["id"]: {"repo": _canonical_repo(r) or r["id"], "tier": r.get("tier"), "kind": r.get("kind"),
                      "partition": partition_of(r)}
            for r in manifest["repos"] if isinstance(r, dict) and r.get("id")}


def manifest_pairs(manifest, partition=PRIMARY) -> list:
    """[(row id, vulnerable_commit, patched_commit)] of the partition's rows (for pair_correct)."""
    return [(r["id"], r.get("vulnerable_commit"), r.get("patched_commit")) for r in manifest["repos"]
            if isinstance(r, dict) and r.get("id") and (partition is None or partition_of(r) == partition)]


def _scope(manifest, partition):
    """(cluster of a row id, the row ids in scope or None = all)."""
    if manifest is None:
        return (lambda rid: rid), None
    idx = manifest_index(manifest)
    rows = None if partition is None else {rid for rid, v in idx.items() if v["partition"] == partition}
    return (lambda rid: idx[rid]["repo"] if rid in idx else rid), rows


def unknown_rows(conn, manifest) -> list:
    """Row ids that have CVE runs but no manifest row: in no partition, so listed, never dropped."""
    known = set(manifest_index(manifest))
    return sorted({r for r, in conn.execute("SELECT DISTINCT repo FROM runs WHERE case_id=''")} - known)


# ---- reading the tables --------------------------------------------------------------------------

_LATEST_ATTEMPT_SQL = ("attempt_no = (SELECT MAX(r2.attempt_no) FROM runs r2 WHERE r2.arm = runs.arm"
                       " AND r2.repo = runs.repo AND r2.commit_sha IS runs.commit_sha"
                       " AND r2.case_id IS runs.case_id AND r2.run_no = runs.run_no)")


def _runs(conn, arm, commit_kind, *, manifest=None, partition=PRIMARY):
    """Scored CVE runs (case_id == '') of one arm and commit kind in scope, oldest first; each with
    its row id ("repo") and cluster ("cluster").

    Attempts: a run slot (arm, repo, commit_sha, case_id, run_no) is scored at most once, by its
    HIGHEST attempt_no. Invariant from the harness (eval/queue.py): only an `aborted` run (usage
    limit or machine failure, not the model's miss) gets a fresh attempt_no, so every other terminal
    status is already the slot's last attempt; the filter makes that explicit and defensive. A slot
    whose latest attempt is aborted/running contributes nothing.
    """
    cluster, rows = _scope(manifest, partition)
    cur = conn.execute(
        f"SELECT id, repo, run_no, commit_sha FROM runs WHERE arm=? AND commit_kind=? AND case_id=''"
        f" AND {_SCORED_SQL} AND {_LATEST_ATTEMPT_SQL} ORDER BY id", (arm, commit_kind))
    return [{"id": i, "repo": r, "cluster": cluster(r), "run_no": n, "sha": s} for i, r, n, s in cur.fetchall()
            if rows is None or r in rows]


def status_counts(conn, arm, commit_kind, *, manifest=None, partition=PRIMARY) -> dict:
    """Per status, the run slots (latest attempt) of one arm and commit kind in scope: {ok, hung,
    crashed, error, aborted} always, plus any other status seen (e.g. running)."""
    _, rows = _scope(manifest, partition)
    cur = conn.execute(f"SELECT repo, status FROM runs WHERE arm=? AND commit_kind=? AND case_id=''"
                       f" AND {_LATEST_ATTEMPT_SQL}", (arm, commit_kind))
    c = Counter(st for r, st in cur.fetchall() if rows is None or r in rows)
    return {**{k: 0 for k in STATUSES}, **dict(c)}


def _arms(conn):
    cur = conn.execute(f"SELECT DISTINCT arm FROM runs WHERE {_SCORED_SQL} ORDER BY arm")
    return [a for a, in cur.fetchall()]


def _tokens(conn, run_id):
    """Total tokens T for one run, or None when the run logged no token data at all."""
    steps = conn.execute("SELECT prompt_tokens, completion_tokens FROM steps WHERE run_id=?",
                         (run_id,)).fetchall()
    if steps:
        present = [v for row in steps for v in row if v is not None]
        return sum(present) if present else None
    calls = conn.execute("SELECT input_tokens, output_tokens, cache_read, cache_write FROM agent_calls"
                         " WHERE run_id=?", (run_id,)).fetchall()
    if calls:
        if not any(v is not None for row in calls for v in row):
            return None
        return sum(_usage.total({"uncached_in": i, "cache_read": cr, "cache_write": cw, "out": o,
                                 "reasoning": None}) for i, o, cr, cw in calls)
    return None


def _token_fields(conn, run_id):
    """Per-field token totals for pricing: {uncached_in, cache_read, cache_write, out}, or None."""
    steps = conn.execute("SELECT prompt_tokens, completion_tokens FROM steps WHERE run_id=?",
                         (run_id,)).fetchall()
    if steps:
        if not any(v is not None for row in steps for v in row):
            return None
        return {"uncached_in": sum(p or 0 for p, _ in steps), "cache_read": 0, "cache_write": 0,
                "out": sum(c or 0 for _, c in steps)}
    calls = conn.execute("SELECT input_tokens, output_tokens, cache_read, cache_write FROM agent_calls"
                         " WHERE run_id=?", (run_id,)).fetchall()
    if calls and any(v is not None for row in calls for v in row):
        return {"uncached_in": sum(i or 0 for i, _, _, _ in calls),
                "cache_read": sum(cr or 0 for _, _, cr, _ in calls),
                "cache_write": sum(cw or 0 for _, _, _, cw in calls),
                "out": sum(o or 0 for _, o, _, _ in calls)}
    return None


def _caught(conn, run_id):
    rows = _match.read_matches(conn, run_id)
    return {"l1": {r["vuln_id"] for r in rows},
            "l2": {r["vuln_id"] for r in rows if r["level"] == "L2"},
            "path_levels": [json.loads(r["path_level"]) for r in rows if r["path_level"]]}


# ---- primary metrics -----------------------------------------------------------------------------

def _cells(conn, arm, **scope):
    """Per vulnerable run: (cluster, caught count, tokens or None)."""
    return [(r["cluster"], len(_caught(conn, r["id"])["l1"]), _tokens(conn, r["id"]))
            for r in _runs(conn, arm, "vulnerable", **scope)]


def efficiency_detail(conn, arm, *, manifest=None, partition=PRIMARY):
    """{E, caught, tokens, n_runs, n_no_token_data, n_repos (clusters), n_rows, status_counts}."""
    scope = dict(manifest=manifest, partition=partition)
    runs = _runs(conn, arm, "vulnerable", **scope)
    cells = [(r["cluster"], len(_caught(conn, r["id"])["l1"]), _tokens(conn, r["id"])) for r in runs]
    with_t = [(c, t) for _, c, t in cells if t is not None]
    caught, tokens = sum(c for c, _ in with_t), sum(t for _, t in with_t)
    return {"E": (1e6 * caught / tokens) if tokens else None, "caught": caught, "tokens": tokens,
            "n_runs": len(cells), "n_no_token_data": len(cells) - len(with_t),
            "n_repos": len({cl for cl, _, _ in cells}), "n_rows": len({r["repo"] for r in runs}),
            "status_counts": status_counts(conn, arm, "vulnerable", **scope)}


def efficiency(conn, arm, *, manifest=None, partition=PRIMARY):
    """E_a = 1e6 * sum caught_L1 / sum T over scored vulnerable-commit runs; None without token data."""
    return efficiency_detail(conn, arm, manifest=manifest, partition=partition)["E"]


def far_detail(conn, arm, *, manifest=None, partition=PRIMARY):
    """{FAR, false_alarms, n_runs, status_counts}: n_runs = scored patched-commit runs (the spec's N*R
    when every slot was run). A crashed/hung/error patched run is scored and, having no matches,
    counts as NO false alarm, so failures lower FAR; status_counts discloses how many there are
    (whether they should count is the pre-registration's KRISH CHECK, not decided here)."""
    scope = dict(manifest=manifest, partition=partition)
    runs = _runs(conn, arm, "patched", **scope)
    fa = sum(1 for r in runs if _caught(conn, r["id"])["l1"])
    return {"FAR": (fa / len(runs)) if runs else None, "false_alarms": fa, "n_runs": len(runs),
            "status_counts": status_counts(conn, arm, "patched", **scope)}


def far(conn, arm, *, manifest=None, partition=PRIMARY):
    """FAR_a = sum 1[any L1 match on patched_v] / n over the n scored patched-commit runs
    (spec: N*R; a non-ok patched run counts as no false alarm, see far_detail)."""
    return far_detail(conn, arm, manifest=manifest, partition=partition)["FAR"]


# ---- paired cluster bootstrap --------------------------------------------------------------------

def _repo_sums(conn, arm, **scope):
    out = {}
    for cluster, c, t in _cells(conn, arm, **scope):
        if t is None:
            continue                         # same exclusion as efficiency(); counted there
        cur = out.setdefault(cluster, [0, 0])
        cur[0] += c
        cur[1] += t
    return out


def _log_ratio(ca, ta, cb, tb):
    """log((ca/ta) / (cb/tb)) as log(ca*tb / (ta*cb)); +-inf when one arm caught nothing, nan when
    both did (or an arm has no tokens). Works on scalars and numpy arrays."""
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.log((np.asarray(ca, float) * np.asarray(tb, float))
                      / (np.asarray(ta, float) * np.asarray(cb, float)))


def _draws(conn, arm_a, arm_b, *, B, seed, manifest=None, partition=PRIMARY):
    """Paired design: the clusters are the REPOS (manifest_index; row ids without a manifest) with
    scored vulnerable runs (with token data) in BOTH arms. A repo present in only one arm is not a
    pair; it is left out of the point estimate and the resampling and listed in `unmatched_repos`."""
    scope = dict(manifest=manifest, partition=partition)
    sa, sb = _repo_sums(conn, arm_a, **scope), _repo_sums(conn, arm_b, **scope)
    repos = sorted(set(sa) & set(sb))
    unmatched = sorted(set(sa) ^ set(sb))
    n = len(repos)
    ca = np.array([sa[r][0] for r in repos], float)
    ta = np.array([sa[r][1] for r in repos], float)
    cb = np.array([sb[r][0] for r in repos], float)
    tb = np.array([sb[r][1] for r in repos], float)
    point = float(_log_ratio(ca.sum(), ta.sum(), cb.sum(), tb.sum())) if n else math.nan
    draws = None
    if n >= 2:
        idx = np.random.default_rng(seed).integers(0, n, size=(B, n))
        draws = _log_ratio(ca[idx].sum(axis=1), ta[idx].sum(axis=1), cb[idx].sum(axis=1), tb[idx].sum(axis=1))
    return {"draws": draws, "point": point, "n_repos": n, "unmatched_repos": unmatched,
            "n_unmatched_repos": len(unmatched)}


def _ci(draws, alpha):
    """Percentile CI; +-inf draws stay in the ranking (they are real resamples), nan draws are left
    out of the ranking but counted by the caller. 'lower'/'higher' avoid interpolating with inf."""
    kept = draws[~np.isnan(draws)]
    if kept.size == 0:
        return None, None
    lo = float(np.quantile(kept, alpha / 2, method="lower"))
    hi = float(np.quantile(kept, 1 - alpha / 2, method="higher"))
    return lo, hi


def _p_value(draws):
    """Two-sided percentile-bootstrap p for H0: log ratio = 0. nan draws count in both tails
    (conservative). Floored at 1/B, the resolution of B draws."""
    nan = np.isnan(draws)
    le = float(np.mean((draws <= 0) | nan))
    ge = float(np.mean((draws >= 0) | nan))
    return max(min(1.0, 2 * min(le, ge)), 1.0 / draws.size)


def paired_bootstrap(conn, arm_a, arm_b, *, B=10_000, seed=0, alpha=0.05, manifest=None, partition=PRIMARY):
    """Paired cluster bootstrap of log(E_a / E_b): repos are resampled with replacement and both
    arms' runs for a repo move together; E is recomputed per arm from the resampled runs.

    Returns {"low","high","point","B","seed","n_repos","n_unmatched_repos","unmatched_repos",
    "alpha","n_undefined","frac_undefined","p_value"}. n_repos counts PAIRED repos (scored
    vulnerable runs with token data in both arms; with a manifest, a repo is a canonical repo, so
    two CVE rows of one repo are one cluster); repos seen in only one arm are excluded from the
    point estimate and the resampling and listed in unmatched_repos. A draw where an arm caught
    nothing has an undefined ratio: it is kept as +-inf (both arms -> nan) and counted in
    n_undefined, never dropped silently. low/high are None when fewer than two paired repos exist.
    """
    d = _draws(conn, arm_a, arm_b, B=B, seed=seed, manifest=manifest, partition=partition)
    draws = d["draws"]
    out = {"point": d["point"], "B": B, "seed": seed, "n_repos": d["n_repos"],
           "n_unmatched_repos": d["n_unmatched_repos"], "unmatched_repos": d["unmatched_repos"],
           "alpha": alpha}
    if draws is None:
        out.update({"low": None, "high": None, "n_undefined": None, "frac_undefined": None,
                    "p_value": None, "note": "fewer than two paired repos with token data"})
        return out
    undefined = int(np.sum(~np.isfinite(draws)))
    lo, hi = _ci(draws, alpha)
    out.update({"low": lo, "high": hi, "n_undefined": undefined, "frac_undefined": undefined / B,
                "p_value": _p_value(draws)})
    return out


# ---- Holm, decision rule -------------------------------------------------------------------------

def holm(pvalues):
    """Holm step-down adjusted p-values: sort ascending, adj_i = max_{j<=i} (m-j) * p_j, cap at 1."""
    items = sorted(pvalues.items(), key=lambda kv: kv[1])
    m, running, out = len(items), 0.0, {}
    for i, (name, p) in enumerate(items):
        running = max(running, (m - i) * p)
        out[name] = min(1.0, running)
    return out


def decisions(conn, lm_arm, others, *, far_margin=0.05, B=10_000, seed=0, alpha=0.05, manifest=None,
              partition=PRIMARY):
    """Spec section 6 decision rule against every frontier comparator at once (on `partition`, the
    headline dataflow rows by default).

    Efficiency: Holm step-down on the bootstrap p-values; comparator at Holm rank i gets its CI at
    level alpha/(m-i) (the Holm-adjusted CI), and a win requires that CI above 0 with every
    earlier-ranked comparator also winning (step-down stops at the first failure).
    False alarms: FAR_lm <= FAR_other + far_margin; None when either arm has no patched runs,
    in which case `beats` is False (not established, not fabricated).
    Each comparison carries both arms' per-status counts (vulnerable and patched run slots).
    """
    scope = dict(manifest=manifest, partition=partition)
    far_lm = far_detail(conn, lm_arm, **scope)
    comps, raw = {}, {}
    for other in others:
        comps[other] = _draws(conn, lm_arm, other, B=B, seed=seed, **scope)
        raw[other] = _p_value(comps[other]["draws"]) if comps[other]["draws"] is not None else 1.0
    adj = holm(raw)
    order = sorted(others, key=lambda o: raw[o])
    m, still_rejecting, out = len(others), True, {}
    for i, other in enumerate(order):
        c = comps[other]
        step_alpha = alpha / (m - i)
        draws = c["draws"]
        lo, hi = _ci(draws, step_alpha) if draws is not None else (None, None)
        above = still_rejecting and lo is not None and lo > 0
        still_rejecting = above
        fo = far_detail(conn, other, **scope)
        far_ok = (None if far_lm["FAR"] is None or fo["FAR"] is None
                  else far_lm["FAR"] <= fo["FAR"] + far_margin)
        out[other] = {
            "efficiency_ci": {"low": lo, "high": hi, "point": c["point"], "alpha": step_alpha,
                              "n_repos": c["n_repos"], "n_unmatched_repos": c["n_unmatched_repos"],
                              "unmatched_repos": c["unmatched_repos"], "B": B, "seed": seed,
                              "n_undefined": int(np.sum(~np.isfinite(draws))) if draws is not None else None},
            "efficiency_ci_above_zero": above,
            "p_value": raw[other] if draws is not None else None,
            "holm_p": adj[other], "holm_alpha": step_alpha,
            "far_lm": far_lm["FAR"], "far_other": fo["FAR"], "far_margin": far_margin,
            "far_ok": far_ok,
            "beats": bool(above and far_ok),
            "status_counts": {
                arm: {kind: status_counts(conn, arm, kind, **scope) for kind in ("vulnerable", "patched")}
                for arm in (lm_arm, other)},
        }
    return {"lm_arm": lm_arm, "alpha": alpha, "B": B, "seed": seed, "far_margin": far_margin,
            "partition": partition if manifest is not None else None, "comparisons": out}


def beats(conn, lm_arm, other_arm, *, far_margin=0.05, B=10_000, seed=0, alpha=0.05, manifest=None,
          partition=PRIMARY):
    """One comparator: CI of log(E_lm/E_other) above 0 AND FAR_lm <= FAR_other + far_margin.
    Use `decisions` for the Holm-adjusted multi-comparator rule."""
    return decisions(conn, lm_arm, [other_arm], far_margin=far_margin, B=B, seed=seed,
                     alpha=alpha, manifest=manifest, partition=partition)["comparisons"][other_arm]


# ---- proportions, pass@k -------------------------------------------------------------------------

def wilson(k, n, z=_Z95):
    """Wilson score interval for k successes in n trials; (None, None) when n == 0."""
    if not n:
        return None, None
    p, z2 = k / n, z * z
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def pass_at_k(hits, k):
    """Unbiased pass@k over n >= k runs: 1 - C(n-c, k) / C(n, k). None when n < k."""
    n, c = len(hits), sum(1 for h in hits if h)
    if n < k:
        return None
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


def pass_pow_k(hits, k):
    """tau-bench pass^k over n >= k runs: C(c, k) / C(n, k) (all k sampled runs succeed). None when n < k."""
    n, c = len(hits), sum(1 for h in hits if h)
    if n < k:
        return None
    return math.comb(c, k) / math.comb(n, k)


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return (sum(xs) / len(xs)) if xs else None


# ---- secondary metrics ---------------------------------------------------------------------------

def _resource_stats(conn, run_ids):
    """wall time, psutil peak RSS and MLX peak (resources.mlx_peak_mb, Metal buffers psutil does not
    see) of the given runs' non-build rows; each {mean, median, max, n, n_missing}."""
    walls, rss, mlx = [], [], []
    for rid in run_ids:
        rows = conn.execute("SELECT wall_seconds, peak_rss_mb, mlx_peak_mb FROM resources"
                            " WHERE run_id=? AND phase!='build'", (rid,)).fetchall()
        w = [x for x, _, _ in rows if x is not None]
        r = [x for _, x, _ in rows if x is not None]
        m = [x for _, _, x in rows if x is not None]
        if w:
            walls.append(sum(w))
        if r:
            rss.append(max(r))
        if m:
            mlx.append(max(m))

    def stats(xs):
        return {"mean": _mean(xs), "median": statistics.median(xs) if xs else None,
                "max": max(xs) if xs else None, "n": len(xs), "n_missing": len(run_ids) - len(xs)}
    return stats(walls), stats(rss), stats(mlx)


def _graph_build(conn, run_ids):
    rows = [r for rid in run_ids for r in conn.execute(
        "SELECT wall_seconds, peak_rss_mb FROM resources WHERE run_id=? AND phase='build'", (rid,)).fetchall()]
    w = [x for x, _ in rows if x is not None]
    r = [x for _, x in rows if x is not None]
    return {"wall_seconds_total": sum(w) if w else None, "wall_seconds_mean": _mean(w),
            "peak_rss_mb": max(r) if r else None, "n": len(rows)}


def _dollars(fields, price):
    """List-price dollars from per-field tokens and a {field: $ per 1M tokens} table; None when the
    table lacks a field that carries tokens (never priced at 0 by default)."""
    if fields is None or not price:
        return None
    total = 0.0
    for k, tok in fields.items():
        if tok and k not in price:
            return None
        total += tok * price.get(k, 0.0) / 1e6
    return total


def _path_levels(dicts):
    n = len(dicts)
    out = {"n": n}
    for key in ("fix_traversal", "entry_hit", "edge_validity", "waypoint_f1"):
        vals = [d.get(key) for d in dicts if d.get(key) is not None]
        out[key] = (sum(float(v) for v in vals) / len(vals)) if vals else None
    return out


def pair_correct(conn, arm, pairs, *, manifest=None, partition=PRIMARY):
    """Pair-correct per (vuln, run_no), from the manifest's commit pairs
    `pairs = [(vuln_id, vulnerable_sha, patched_sha), ...]` (`manifest_pairs`; vuln_id = row id).

    Runs are keyed by (row id, sha), never by sha alone: a commit that serves two rows (a chain, or
    two CVEs on one vulnerable commit) has one set of runs PER ROW, and each row is scored on its own.
    caught      = a `matches` row with THAT vuln_id on the arm's scored run of row vuln_id with
                  commit_sha == vulnerable_sha and this run_no;
    false alarm = any L1 match on the arm's scored run of row vuln_id with commit_sha == patched_sha
                  and this run_no;
    pair-correct = caught AND NOT false alarm.
    Returns {pair_correct (mean over vulns of the mean over their paired run_nos), n_vulns,
    n_pairs, n_unpaired (run_nos where either side has no scored run), n_vulns_without_runs}.
    """
    scope = dict(manifest=manifest, partition=partition)
    vsha, psha = {}, {}
    for r in _runs(conn, arm, "vulnerable", **scope):
        vsha.setdefault((r["repo"], r["sha"]), {})[r["run_no"]] = r["id"]
    for r in _runs(conn, arm, "patched", **scope):
        psha.setdefault((r["repo"], r["sha"]), {})[r["run_no"]] = r["id"]
    per_vuln, n_pairs, n_unpaired, no_runs = [], 0, 0, 0
    for vuln_id, v_sha, p_sha in pairs:
        vr, pr = vsha.get((str(vuln_id), v_sha), {}), psha.get((str(vuln_id), p_sha), {})
        run_nos = sorted(set(vr) | set(pr))
        if not run_nos:
            no_runs += 1
            continue
        vals = []
        for rn in run_nos:
            if rn not in vr or rn not in pr:
                n_unpaired += 1
                continue
            caught = str(vuln_id) in _caught(conn, vr[rn])["l1"]
            fa = bool(_caught(conn, pr[rn])["l1"])
            vals.append(caught and not fa)
            n_pairs += 1
        if vals:
            per_vuln.append(_mean(vals))
    return {"pair_correct": _mean(per_vuln), "n_vulns": len(per_vuln), "n_pairs": n_pairs,
            "n_unpaired": n_unpaired, "n_vulns_without_runs": no_runs}


def youden_detail(conn, arm, owasp_sample, *, runs_root=os.path.join("eval", "runs")):
    """Youden J = TPR - FPR on the OWASP Benchmark runs (case_id != '') of `arm`.

    For each scored run (latest attempt per slot, status in SCORED), its case is looked up in
    `owasp_sample` (eval/dataset/owasp_sample.json: benchmark id = runs.repo, case_id), its
    findings.json is read from the run dir (eval.run.run_dir_for under `runs_root`) through
    eval.normalize, and eval.owasp.score gives the confusion row; J via eval.owasp.youden, which is
    None when J is undefined (no real or no trap case) -- never a made-up 0. A run with no findings
    file (crashed, or an invalid file was never copied) is scored with no findings, like a CVE miss,
    and counted in n_no_findings_file; a run whose case is not in the sample is left out and counted
    in n_unknown_case. Returns {youden_j, tpr, fpr, tp, fp, tn, fn, n_cases, n_runs, by_benchmark:
    {id: {youden_j, tp, fp, tn, fn, n_cases}}, n_no_findings_file, n_unknown_case, status_counts}."""
    from eval import normalize, owasp
    from eval.run import run_dir_for
    cases = {(b.get("id"), c.get("case_id")): c for b in owasp_sample.get("benchmarks") or []
             for c in b.get("cases") or []}
    cur = conn.execute(f"SELECT repo, commit_sha, case_id, run_no, attempt_no, status FROM runs"
                       f" WHERE arm=? AND case_id!='' AND {_LATEST_ATTEMPT_SQL} ORDER BY id", (arm,))
    slots = cur.fetchall()
    statuses = {**{k: 0 for k in STATUSES}, **dict(Counter(st for *_, st in slots))}
    rows, by_bench, no_file, unknown = [], {}, 0, 0
    for bench, sha, case_id, run_no, attempt_no, st in slots:
        if st not in SCORED:
            continue
        case = cases.get((bench, case_id))
        if case is None:
            unknown += 1
            continue
        meta = {"id": bench, "commit_sha": sha, "case_id": case_id, "run_no": run_no, "attempt_no": attempt_no}
        path = os.path.join(run_dir_for(arm, meta, root=runs_root), "findings.json")
        if os.path.exists(path):
            findings = normalize.load_arm(path, arm=arm)
        else:
            findings, no_file = [], no_file + 1
        row = owasp.score(findings, case)
        rows.append(row)
        by_bench.setdefault(bench, []).append(row)

    def confusion(rs):
        tp, fp = sum(r["tp"] for r in rs), sum(r["fp"] for r in rs)
        tn, fn = sum(r["tn"] for r in rs), sum(r["fn"] for r in rs)
        return {"youden_j": owasp.youden(rs), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "n_cases": len(rs),
                "tpr": tp / (tp + fn) if tp + fn else None, "fpr": fp / (fp + tn) if fp + tn else None}
    return {**confusion(rows), "n_runs": len(slots),
            "by_benchmark": {b: confusion(rs) for b, rs in sorted(by_bench.items())},
            "n_no_findings_file": no_file, "n_unknown_case": unknown, "status_counts": statuses}


def _arm_secondary(conn, arm, *, k, prices, pairs, manifest=None, partition=PRIMARY):
    scope = dict(manifest=manifest, partition=partition)
    vruns, pruns = _runs(conn, arm, "vulnerable", **scope), _runs(conn, arm, "patched", **scope)
    vulns, paths, fields, no_tok = {}, [], [], 0
    for r in vruns:
        c = _caught(conn, r["id"])
        paths.extend(c["path_levels"])
        f = _token_fields(conn, r["id"])
        if f is None:
            no_tok += 1
        else:
            fields.append(f)
        vulns.setdefault((r["repo"], r["sha"]), []).append({"l1": bool(c["l1"]), "l2": bool(c["l2"])})
    per_vuln = list(vulns.values())
    if pairs is None and manifest is not None:
        pairs = manifest_pairs(manifest, partition)
    pc = pair_correct(conn, arm, pairs, **scope) if pairs is not None else None
    tok_fields = ({key: sum(f[key] for f in fields) for key in fields[0]} if fields else None)
    walls, rss, mlx = _resource_stats(conn, [r["id"] for r in vruns + pruns])
    return {
        "efficiency": efficiency_detail(conn, arm, **scope),
        "far": far_detail(conn, arm, **scope),
        "n_vulns": len(per_vuln), "n_vuln_runs": len(vruns), "n_patched_runs": len(pruns),
        "status_counts": {"vulnerable": status_counts(conn, arm, "vulnerable", **scope),
                          "patched": status_counts(conn, arm, "patched", **scope)},
        "recall_l1": _mean([_mean([x["l1"] for x in rs]) for rs in per_vuln]),
        "recall_l2": _mean([_mean([x["l2"] for x in rs]) for rs in per_vuln]),
        "pair_correct": pc["pair_correct"] if pc else None,     # None (not 0) without commit pairs
        "pair_correct_detail": pc,
        f"pass_at_{k}": _mean([pass_at_k([x["l1"] for x in rs], k) for rs in per_vuln]),
        f"pass_pow_{k}": _mean([pass_pow_k([x["l1"] for x in rs], k) for rs in per_vuln]),
        "n_vulns_under_k_runs": sum(1 for rs in per_vuln if len(rs) < k),
        "path_levels": _path_levels(paths),
        "wall_seconds": walls, "peak_rss_mb": rss, "mlx_peak_mb": mlx,
        "graph_build": _graph_build(conn, [r["id"] for r in vruns + pruns]),
        "tokens": tok_fields, "n_no_token_data": no_tok,
        "dollars": _dollars(tok_fields, (prices or {}).get(arm)),
        "ppi_precision": None,     # labeled false alarms: eval/judge.py (E4) + human labels
    }


def secondary(conn, *, prices=None, pairs=None, k=3, seed=0, manifest=None, partition=PRIMARY,
              owasp_sample=None, runs_root=os.path.join("eval", "runs")):
    """Secondary (reported, not confirmatory) metrics per arm, on one partition. `prices` = {arm:
    {field: $/1M tokens}} with fields uncached_in / cache_read / cache_write / out; without it
    dollars is None. `pairs` = [(vuln_id, vulnerable_sha, patched_sha), ...]; with a manifest they
    default to `manifest_pairs`, and without either pair_correct is None (see pair_correct).
    `owasp_sample` (the loaded OWASP sample) adds youden_j / youden_detail per arm (None without it)."""
    arms = {}
    for arm in _arms(conn):
        a = _arm_secondary(conn, arm, k=k, prices=prices, pairs=pairs, manifest=manifest, partition=partition)
        yd = youden_detail(conn, arm, owasp_sample, runs_root=runs_root) if owasp_sample is not None else None
        a.update(youden_j=yd["youden_j"] if yd else None, youden_detail=yd)
        arms[arm] = a
    return {"arms": arms, "k": k, "seed": seed, "partition": partition if manifest is not None else None,
            "notes": ["recall/pair-correct/pass@k: unit = vulnerability (mean of its runs), then mean over vulns",
                      "pair-correct pairs a row's runs by (row id, sha); each CVE is scored against its own patched commit",
                      "youden_j needs the OWASP sample (owasp_sample=); ppi_precision is filled by eval/judge.py",
                      "efficiency and tokens leave out runs with no token data (n_no_token_data)",
                      "status_counts: latest attempt per run slot; aborted slots are not scored"]}


def mde(*args, **kwargs):
    """Minimum detectable effect from dev variance (Miller 2024, 'Adding Error Bars to Evals',
    arXiv:2411.00640, eq. 9). NOT IMPLEMENTED: it needs the dev-set per-repo variance measured
    before the test run; returns None rather than a made-up number."""
    return None


# ---- Pareto ---------------------------------------------------------------------------------------

def pareto_frontier(rows):
    """Arms on the cost-vs-accuracy frontier (lower cost, higher accuracy), sorted by cost.
    Rows with a None cost or accuracy are not placed."""
    pts = [r for r in rows if r.get("cost") is not None and r.get("accuracy") is not None]
    front = []
    for r in pts:
        dominated = any((o["cost"] <= r["cost"] and o["accuracy"] >= r["accuracy"])
                        and (o["cost"] < r["cost"] or o["accuracy"] > r["accuracy"]) for o in pts)
        if not dominated:
            front.append(r)
    return [r["arm"] for r in sorted(front, key=lambda r: (r["cost"], -r["accuracy"]))]


def _ticks(lo, hi, n=5):
    if hi <= lo:
        hi = lo + 1.0
    raw = (hi - lo) / n
    mag = 10 ** math.floor(math.log10(raw))
    step = min((s for s in (1, 2, 2.5, 5, 10) if s * mag >= raw), key=lambda s: s) * mag
    start = math.floor(lo / step) * step
    ticks = []
    t = start
    while True:                          # the last tick sits at or above hi (never clips a point)
        ticks.append(round(t, 10))
        if t >= hi - step * 1e-9:
            return ticks
        t += step


def _fmt(x):
    if x is None:
        return "missing"
    if isinstance(x, float):
        return f"{x:.4g}"
    return str(x)


def _fmt_tick(x):
    """Axis tick text: 0.2, 12, 450k, 1.2M (never 4e+05)."""
    for div, suf in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if abs(x) >= div:
            return f"{x / div:.3g}{suf}"
    return f"{x:.3g}"


def _svg(rows, front, *, cost_label, acc_label):
    pts = [r for r in rows if r.get("cost") is not None and r.get("accuracy") is not None]
    W, H, L, R_, T, Bm = 640, 400, 64, 24, 24, 56
    xs, ys = [r["cost"] for r in pts], [r["accuracy"] for r in pts]
    xt = _ticks(0.0, max(xs) * 1.05 if xs else 1.0)      # 5% headroom so a point never sits on the edge
    yt = _ticks(0.0, max(ys) * 1.05 if ys else 1.0)
    x0, x1, y0, y1 = xt[0], xt[-1], yt[0], yt[-1]

    def X(v):
        return L + (v - x0) / (x1 - x0) * (W - L - R_)

    def Y(v):
        return H - Bm - (v - y0) / (y1 - y0) * (H - T - Bm)

    esc = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
         f'role="img" aria-label="Cost versus accuracy Pareto plot">',
         "<style>.bg{fill:#fcfcfb}.grid{stroke:#e6e5e2;stroke-width:1}.axis{stroke:#9b9a95;stroke-width:1}"
         ".t{font:12px system-ui,sans-serif;fill:#52514e}.lbl{font:12px system-ui,sans-serif;fill:#0b0b0b}"
         ".front{fill:#2a78d6;stroke:#fcfcfb;stroke-width:2}.dom{fill:#9b9a95;stroke:#fcfcfb;stroke-width:2}"
         ".line{stroke:#2a78d6;stroke-width:2;fill:none}"
         "@media (prefers-color-scheme:dark){.bg{fill:#1a1a19}.grid{stroke:#333330}.axis{stroke:#6f6e69}"
         ".t{fill:#c3c2b7}.lbl{fill:#f0efec}.front{fill:#3987e5;stroke:#1a1a19}.dom{stroke:#1a1a19}.line{stroke:#3987e5}}"
         "</style>",
         f'<rect class="bg" width="{W}" height="{H}"/>']
    for t in yt:
        o.append(f'<line class="grid" x1="{L}" x2="{W - R_}" y1="{Y(t):.1f}" y2="{Y(t):.1f}"/>')
        o.append(f'<text class="t" x="{L - 8}" y="{Y(t) + 4:.1f}" text-anchor="end">{_fmt_tick(float(t))}</text>')
    for t in xt:
        o.append(f'<text class="t" x="{X(t):.1f}" y="{H - Bm + 18}" text-anchor="middle">{_fmt_tick(float(t))}</text>')
    o.append(f'<line class="axis" x1="{L}" x2="{W - R_}" y1="{H - Bm}" y2="{H - Bm}"/>')
    o.append(f'<line class="axis" x1="{L}" x2="{L}" y1="{T}" y2="{H - Bm}"/>')
    o.append(f'<text class="t" x="{(L + W - R_) / 2:.1f}" y="{H - 12}" text-anchor="middle">{esc(cost_label)}</text>')
    o.append(f'<text class="t" transform="translate(16,{(T + H - Bm) / 2:.1f}) rotate(-90)" '
             f'text-anchor="middle">{esc(acc_label)}</text>')
    fp = sorted((r for r in pts if r["arm"] in front), key=lambda r: r["cost"])
    if len(fp) > 1:
        o.append('<polyline class="line" points="' + " ".join(f"{X(r['cost']):.1f},{Y(r['accuracy']):.1f}" for r in fp) + '"/>')
    for r in pts:
        cls = "front" if r["arm"] in front else "dom"
        cx, cy = X(r["cost"]), Y(r["accuracy"])
        o.append(f'<circle class="{cls}" cx="{cx:.1f}" cy="{cy:.1f}" r="5"><title>{esc(r["arm"])}: '
                 f'{_fmt(r["cost"])}, {_fmt(r["accuracy"])}</title></circle>')
        if cx > W - R_ - 110:                         # label to the left near the right edge
            o.append(f'<text class="lbl" x="{cx - 8:.1f}" y="{cy - 6:.1f}" text-anchor="end">{esc(r["arm"])}</text>')
        else:
            o.append(f'<text class="lbl" x="{cx + 8:.1f}" y="{cy - 6:.1f}">{esc(r["arm"])}</text>')
    o.append("</svg>")
    return "\n".join(o)


def pareto(rows, *, svg_path=None, cost_label="cost (tokens per vulnerable run)", accuracy_label="recall (L1)"):
    """Cost-vs-accuracy Pareto table (markdown) + hand-built SVG, from rows of
    {"arm", "cost", "accuracy"} (lower cost / higher accuracy is better; None = missing, listed in the
    table but not plotted). Writes the SVG to `svg_path` when given; returns table + SVG text."""
    front = set(pareto_frontier(rows))
    lines = [f"| arm | {cost_label} | {accuracy_label} | frontier |", "|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (r.get("cost") is None, r.get("cost") or 0)):
        lines.append(f"| {r['arm']} | {_fmt(r.get('cost'))} | {_fmt(r.get('accuracy'))} | "
                     f"{'yes' if r['arm'] in front else ('-' if r.get('cost') is None or r.get('accuracy') is None else 'no')} |")
    svg = _svg(rows, front, cost_label=cost_label, acc_label=accuracy_label)
    if svg_path:
        with open(svg_path, "w") as fh:
            fh.write(svg)
    return "\n".join(lines) + "\n\n" + svg


# ---- whole report ----------------------------------------------------------------------------------

def script_hash():
    """sha256 of this file (spec section 6: the analysis script's hash goes into the prereg tag)."""
    with open(__file__, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _statuses(c) -> str:
    """'ok 10 / hung 1 / crashed 0 / error 2 / aborted 0' (+ any other status seen)."""
    extra = [k for k in c if k not in STATUSES]
    return " / ".join(f"{k} {c.get(k, 0)}" for k in (*STATUSES, *extra))


def _partition_tables(sec, title) -> list:
    """Efficiency, FAR and the secondary metrics of one partition, each n with its statuses."""
    out = [f"## {title}", "",
           "| arm | E (caught per 1M tokens) | caught | tokens | vulnerable runs | repos | statuses (vulnerable) "
           "| FAR | patched runs | statuses (patched) |", "|---|---|---|---|---|---|---|---|---|---|"]
    for arm, s in sec["arms"].items():
        e, f = s["efficiency"], s["far"]
        out.append(f"| {arm} | {_fmt(e['E'])} | {e['caught']} | {e['tokens']} | {e['n_runs']} | {e['n_repos']} | "
                   f"{_statuses(e['status_counts'])} | {_fmt(f['FAR'])} | {f['n_runs']} | {_statuses(f['status_counts'])} |")
    out += ["", "| arm | recall L1 | recall L2 | pair-correct (pairs) | pass@3 | pass^3 | no token data | "
            "wall s (mean) | peak RSS MB (max) | MLX peak MB (max) | graph builds (wall s total) | dollars |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for arm, s in sec["arms"].items():
        pc = s["pair_correct_detail"]
        gb = s["graph_build"]
        out.append(f"| {arm} | {_fmt(s['recall_l1'])} | {_fmt(s['recall_l2'])} | {_fmt(s['pair_correct'])} "
                   f"({pc['n_pairs'] if pc else 'no pairs'}) | {_fmt(s['pass_at_3'])} | {_fmt(s['pass_pow_3'])} | "
                   f"{s['n_no_token_data']} | {_fmt(s['wall_seconds']['mean'])} | {_fmt(s['peak_rss_mb']['max'])} | "
                   f"{_fmt(s['mlx_peak_mb']['max'])} | {gb['n']} ({_fmt(gb['wall_seconds_total'])}) | {_fmt(s['dollars'])} |")
    return out


def render(conn, lm_arm, others, *, manifest=None, owasp_sample=None, prices=None, pairs=None, B=10_000,
           seed=0, far_margin=0.05, svg_path=None, runs_root=os.path.join("eval", "runs")):
    """The whole report. With the manifest: the PRIMARY tables and the decision rule on the headline
    dataflow rows (clusters = repos), then access-control and scale-tier rows in their own tables;
    with the OWASP sample: Youden J. Without a manifest every CVE run is pooled and each row id is a
    cluster -- the report says so (not the pre-registered analysis)."""
    sec = secondary(conn, prices=prices, pairs=pairs, seed=seed, manifest=manifest, partition=PRIMARY,
                    owasp_sample=owasp_sample, runs_root=runs_root)
    dec = decisions(conn, lm_arm, [o for o in others if o in sec["arms"]], far_margin=far_margin, B=B,
                    seed=seed, manifest=manifest, partition=PRIMARY)
    out = [f"# Orion-LM scoring report (report.py sha256 {script_hash()[:12]}, B={B}, seed={seed})", ""]
    if manifest is None:
        out += ["**No manifest: every CVE run pooled, each row id its own cluster. NOT the pre-registered "
                "analysis (pass the manifest).**", ""]
    else:
        idx = manifest_index(manifest)
        parts = Counter(v["partition"] for v in idx.values())
        repos = {p: len({v["repo"] for v in idx.values() if v["partition"] == p}) for p in parts}
        out += ["Manifest: " + "; ".join(f"{p} {n} rows in {repos[p]} repos" for p, n in sorted(parts.items())), ""]
        unknown = unknown_rows(conn, manifest)
        if unknown:
            out += [f"**{len(unknown)} row id(s) have runs but no manifest row (in no table):** "
                    + ", ".join(unknown[:20]) + (" ..." if len(unknown) > 20 else ""), ""]
    out += _partition_tables(sec, "Primary: headline dataflow rows" if manifest is not None else "Primary (all CVE runs)")
    out += ["", f"## Decision rule: {lm_arm} vs frontier (Holm step-down, alpha={dec['alpha']}, FAR margin {far_margin})", "",
            "| vs | log(E_lm/E_X) | CI (percentile) | CI level (Holm alpha/(m-i)) | Holm p | paired repos | unmatched repos | undefined draws | FAR_lm | FAR_X | beats |",
            "|---|---|---|---|---|---|---|---|---|---|---|"]
    for other, c in dec["comparisons"].items():
        ci = c["efficiency_ci"]
        out.append(f"| {other} | {_fmt(ci['point'])} | [{_fmt(ci['low'])}, {_fmt(ci['high'])}] | "
                   f"{1 - ci['alpha']:.4g} (alpha {_fmt(ci['alpha'])}) | {_fmt(c['holm_p'])} | {ci['n_repos']} | "
                   f"{ci['n_unmatched_repos']} | {ci['n_undefined']} | {_fmt(c['far_lm'])} | {_fmt(c['far_other'])} | {c['beats']} |")
    out += ["", "Coverage behind the rule (a run with no token data is in neither efficiency sum; a vuln with "
            f"fewer than {sec['k']} runs has no pass@{sec['k']}; aborted slots are not scored):", "",
            f"| arm | vulnerable runs | no token data | vulns | vulns under {sec['k']} runs | patched runs |", "|---|---|---|---|---|---|"]
    for arm, s in sec["arms"].items():
        out.append(f"| {arm} | {s['n_vuln_runs']} | {s['n_no_token_data']} | {s['n_vulns']} | "
                   f"{s['n_vulns_under_k_runs']} | {s['n_patched_runs']} |")
    if manifest is not None:
        for part, title in (("access_control", "Access-control rows (reported separately)"),
                            ("scale", "Scale tier (reported separately)")):
            psec = secondary(conn, prices=prices, pairs=None, seed=seed, manifest=manifest, partition=part)
            out += [""] + _partition_tables(psec, title)
    if owasp_sample is not None:
        out += ["", "## OWASP Benchmark: Youden J = TPR - FPR (targeted judgement, R = 1)", "",
                "| arm | J | TPR | FPR | cases | per benchmark (J, cases) | no findings file | case not in sample | statuses |",
                "|---|---|---|---|---|---|---|---|---|"]
        for arm, s in sec["arms"].items():
            y = s["youden_detail"]
            per = "; ".join(f"{b} {_fmt(v['youden_j'])} ({v['n_cases']})" for b, v in y["by_benchmark"].items())
            out.append(f"| {arm} | {_fmt(y['youden_j'])} | {_fmt(y['tpr'])} | {_fmt(y['fpr'])} | {y['n_cases']} | "
                       f"{per or '-'} | {y['n_no_findings_file']} | {y['n_unknown_case']} | {_statuses(y['status_counts'])} |")
    rows = [{"arm": arm, "accuracy": s["recall_l1"],
             "cost": (s["efficiency"]["tokens"] / (s["efficiency"]["n_runs"] - s["efficiency"]["n_no_token_data"])
                      if s["efficiency"]["n_runs"] - s["efficiency"]["n_no_token_data"] else None)}
            for arm, s in sec["arms"].items()]
    out += ["", "## Pareto (primary rows)", "", pareto(rows, svg_path=svg_path)]
    return "\n".join(out)


def open_readonly(path):
    """Open an existing runs DB read-only (sqlite URI mode=ro). The report never creates or migrates
    a database: a missing file is an error, not an empty report."""
    import sqlite3
    from urllib.request import pathname2url
    if not os.path.isfile(path):
        raise FileNotFoundError(f"runs DB not found: {path}")
    return sqlite3.connect(f"file:{pathname2url(os.path.abspath(path))}?mode=ro", uri=True)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Orion-LM scoring report (reads the runs DB read-only)")
    ap.add_argument("db", nargs="?", default="eval/runs.db")
    ap.add_argument("--manifest", default="eval/dataset/manifest.json",
                    help="the manifest: partitions (tier/kind per row id), repo clusters and commit pairs")
    ap.add_argument("--owasp", metavar="PATH", help="the OWASP sample (eval/dataset/owasp_sample.json): Youden J")
    ap.add_argument("--runs-root", default=os.path.join("eval", "runs"),
                    help="where the per-run findings.json files are (OWASP scoring)")
    ap.add_argument("--lm", default="orion-lm")
    ap.add_argument("--vs", nargs="*", default=["plain-sonnet5", "plain-opus5", "plain-gpt"])
    ap.add_argument("--B", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--prices", help="JSON file {arm: {uncached_in, cache_read, cache_write, out}} in $/1M tokens")
    ap.add_argument("--pairs", help="JSON file [[vuln_id, vulnerable_sha, patched_sha], ...] for pair-correct "
                                    "(default: the manifest's own pairs)")
    ap.add_argument("--svg", help="write the Pareto SVG here")
    a = ap.parse_args(argv)
    from eval import manifest as _manifest
    from eval import owasp as _owasp
    man = _manifest.load(a.manifest)          # required: without it there are no partitions or clusters
    sample = _owasp.load_sample(a.owasp) if a.owasp else None
    prices = pairs = None
    if a.prices:
        with open(a.prices) as fh:
            prices = json.load(fh)
    if a.pairs:
        with open(a.pairs) as fh:
            pairs = [tuple(p) for p in json.load(fh)]
    conn = open_readonly(a.db)
    print(render(conn, a.lm, a.vs, manifest=man, owasp_sample=sample, prices=prices, pairs=pairs, B=a.B,
                 seed=a.seed, svg_path=a.svg, runs_root=a.runs_root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
