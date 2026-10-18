"""Scoring tables for the Orion-LM study (design spec section 6). NOT `orion/report.py`.

Reads `runs` / `matches` / `steps` / `agent_calls` / `resources` written by the harness and
computes the pre-registered metrics:

  primary    efficiency E_a = 1e6 * sum caught_L1 / sum T   (vulnerable-commit runs)
             false-alarm rate FAR_a = sum 1[any L1 match on patched_v] / (N*R)   (patched runs)
  decision   paired cluster bootstrap (cluster = repo) of log(E_lm / E_X), B = 10_000, 95% CI;
             Holm step-down over the frontier comparators; FAR_lm <= FAR_X + margin
  secondary  recall L1 / L2, pair-correct, pass@3 / pass^3, path levels, wall time, peak RSS,
             graph-build compute, list-price dollars (only with a caller-supplied price table)

Which runs count (never changes anywhere in this module):
  * status in ('ok','crashed','hung','error') is terminal and SCORED; 'aborted' and 'running'
    rows are excluded from every sum.
  * case_id == '' only: OWASP Benchmark rows (case_id != '') feed Youden J via eval/owasp.py
    (later task) and are NOT part of efficiency / FAR / recall.
  * T for a run comes from `steps` (orion-lm arms: prompt + completion; cached tokens are already
    inside prompt_tokens) or else from `agent_calls` (frontier arms: usage.total over
    uncached_in + cache_read + cache_write + out; reasoning is already inside out). A run with
    neither has T = None: it is left out of BOTH efficiency sums and reported in
    `n_no_token_data`, never counted as 0 tokens.
  * caught_L1 for (vuln, run) = any `matches` row for that vuln in that run (L1 or L2);
    caught_L2 = a row with level == 'L2'. A run's caught count = number of distinct matched
    vuln_ids (0/1 for the one-bug-per-commit dataset).

Nothing here estimates a missing value. Dollars are None without a price table; `mde` is a stub.
This file is the analysis script the spec says to commit and hash into the prereg tag
(`script_hash()`).
"""
import hashlib
import json
import math
import statistics
import sys

import numpy as np

from eval import match as _match
from eval import usage as _usage

SCORED = ("ok", "crashed", "hung", "error")
_SCORED_SQL = "status IN ('ok','crashed','hung','error')"
_Z95 = 1.959963984540054


# ---- reading the tables --------------------------------------------------------------------------

def _runs(conn, arm, commit_kind):
    """Scored CVE runs (case_id == '') of one arm and commit kind, oldest first."""
    cur = conn.execute(
        f"SELECT id, repo, run_no, commit_sha FROM runs WHERE arm=? AND commit_kind=? AND case_id=''"
        f" AND {_SCORED_SQL} ORDER BY id", (arm, commit_kind))
    return [{"id": i, "repo": r, "run_no": n, "sha": s} for i, r, n, s in cur.fetchall()]


def _arms(conn):
    cur = conn.execute(f"SELECT DISTINCT arm FROM runs WHERE case_id='' AND {_SCORED_SQL} ORDER BY arm")
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

def _cells(conn, arm):
    """Per vulnerable run: (repo, caught count, tokens or None)."""
    return [(r["repo"], len(_caught(conn, r["id"])["l1"]), _tokens(conn, r["id"]))
            for r in _runs(conn, arm, "vulnerable")]


def efficiency_detail(conn, arm):
    cells = _cells(conn, arm)
    with_t = [(c, t) for _, c, t in cells if t is not None]
    caught, tokens = sum(c for c, _ in with_t), sum(t for _, t in with_t)
    return {"E": (1e6 * caught / tokens) if tokens else None, "caught": caught, "tokens": tokens,
            "n_runs": len(cells), "n_no_token_data": len(cells) - len(with_t),
            "n_repos": len({repo for repo, _, _ in cells})}


def efficiency(conn, arm):
    """E_a = 1e6 * sum caught_L1 / sum T over scored vulnerable-commit runs; None without token data."""
    return efficiency_detail(conn, arm)["E"]


def far_detail(conn, arm):
    runs = _runs(conn, arm, "patched")
    fa = sum(1 for r in runs if _caught(conn, r["id"])["l1"])
    return {"FAR": (fa / len(runs)) if runs else None, "false_alarms": fa, "n_runs": len(runs)}


def far(conn, arm):
    """FAR_a = sum 1[any L1 match on patched_v] / (N*R) over scored patched-commit runs."""
    return far_detail(conn, arm)["FAR"]


# ---- paired cluster bootstrap --------------------------------------------------------------------

def _repo_sums(conn, arm):
    out = {}
    for repo, c, t in _cells(conn, arm):
        if t is None:
            continue                         # same exclusion as efficiency(); counted there
        cur = out.setdefault(repo, [0, 0])
        cur[0] += c
        cur[1] += t
    return out


def _log_ratio(ca, ta, cb, tb):
    """log((ca/ta) / (cb/tb)) as log(ca*tb / (ta*cb)); +-inf when one arm caught nothing, nan when
    both did (or an arm has no tokens). Works on scalars and numpy arrays."""
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.log((np.asarray(ca, float) * np.asarray(tb, float))
                      / (np.asarray(ta, float) * np.asarray(cb, float)))


def _draws(conn, arm_a, arm_b, *, B, seed):
    sa, sb = _repo_sums(conn, arm_a), _repo_sums(conn, arm_b)
    repos = sorted(set(sa) | set(sb))
    n = len(repos)
    ca = np.array([sa.get(r, (0, 0))[0] for r in repos], float)
    ta = np.array([sa.get(r, (0, 0))[1] for r in repos], float)
    cb = np.array([sb.get(r, (0, 0))[0] for r in repos], float)
    tb = np.array([sb.get(r, (0, 0))[1] for r in repos], float)
    point = float(_log_ratio(ca.sum(), ta.sum(), cb.sum(), tb.sum())) if n else math.nan
    if n < 2:
        return None, point, n
    idx = np.random.default_rng(seed).integers(0, n, size=(B, n))
    draws = _log_ratio(ca[idx].sum(axis=1), ta[idx].sum(axis=1), cb[idx].sum(axis=1), tb[idx].sum(axis=1))
    return draws, point, n


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


def paired_bootstrap(conn, arm_a, arm_b, *, B=10_000, seed=0, alpha=0.05):
    """Paired cluster bootstrap of log(E_a / E_b): repos are resampled with replacement and both
    arms' runs for a repo move together; E is recomputed per arm from the resampled runs.

    Returns {"low","high","point","B","seed","n_repos","alpha","n_undefined","frac_undefined",
    "p_value"}. A draw where an arm caught nothing has an undefined ratio: it is kept as +-inf
    (both arms -> nan) and counted in n_undefined, never dropped silently. low/high are None when
    fewer than two repos are available (nothing to resample).
    """
    draws, point, n = _draws(conn, arm_a, arm_b, B=B, seed=seed)
    out = {"point": point, "B": B, "seed": seed, "n_repos": n, "alpha": alpha}
    if draws is None:
        out.update({"low": None, "high": None, "n_undefined": None, "frac_undefined": None,
                    "p_value": None, "note": "fewer than two repos with token data in either arm"})
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


def decisions(conn, lm_arm, others, *, far_margin=0.05, B=10_000, seed=0, alpha=0.05):
    """Spec section 6 decision rule against every frontier comparator at once.

    Efficiency: Holm step-down on the bootstrap p-values; comparator at Holm rank i gets its CI at
    level alpha/(m-i) (the Holm-adjusted CI), and a win requires that CI above 0 with every
    earlier-ranked comparator also winning (step-down stops at the first failure).
    False alarms: FAR_lm <= FAR_other + far_margin; None when either arm has no patched runs,
    in which case `beats` is False (not established, not fabricated).
    """
    far_lm = far_detail(conn, lm_arm)
    comps, raw = {}, {}
    for other in others:
        draws, point, n = _draws(conn, lm_arm, other, B=B, seed=seed)
        comps[other] = {"draws": draws, "point": point, "n_repos": n}
        raw[other] = _p_value(draws) if draws is not None else 1.0
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
        fo = far_detail(conn, other)
        far_ok = (None if far_lm["FAR"] is None or fo["FAR"] is None
                  else far_lm["FAR"] <= fo["FAR"] + far_margin)
        out[other] = {
            "efficiency_ci": {"low": lo, "high": hi, "point": c["point"], "alpha": step_alpha,
                              "n_repos": c["n_repos"], "B": B, "seed": seed,
                              "n_undefined": int(np.sum(~np.isfinite(draws))) if draws is not None else None},
            "efficiency_ci_above_zero": above,
            "p_value": raw[other] if draws is not None else None,
            "holm_p": adj[other], "holm_alpha": step_alpha,
            "far_lm": far_lm["FAR"], "far_other": fo["FAR"], "far_margin": far_margin,
            "far_ok": far_ok,
            "beats": bool(above and far_ok),
        }
    return {"lm_arm": lm_arm, "alpha": alpha, "B": B, "seed": seed, "far_margin": far_margin,
            "comparisons": out}


def beats(conn, lm_arm, other_arm, *, far_margin=0.05, B=10_000, seed=0, alpha=0.05):
    """One comparator: CI of log(E_lm/E_other) above 0 AND FAR_lm <= FAR_other + far_margin.
    Use `decisions` for the Holm-adjusted multi-comparator rule."""
    return decisions(conn, lm_arm, [other_arm], far_margin=far_margin, B=B, seed=seed,
                     alpha=alpha)["comparisons"][other_arm]


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
    walls, rss = [], []
    for rid in run_ids:
        rows = conn.execute("SELECT wall_seconds, peak_rss_mb FROM resources WHERE run_id=? AND phase!='build'",
                            (rid,)).fetchall()
        w = [x for x, _ in rows if x is not None]
        r = [x for _, x in rows if x is not None]
        if w:
            walls.append(sum(w))
        if r:
            rss.append(max(r))

    def stats(xs):
        return {"mean": _mean(xs), "median": statistics.median(xs) if xs else None,
                "max": max(xs) if xs else None, "n": len(xs), "n_missing": len(run_ids) - len(xs)}
    return stats(walls), stats(rss)


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


def _arm_secondary(conn, arm, *, k, prices):
    vruns, pruns = _runs(conn, arm, "vulnerable"), _runs(conn, arm, "patched")
    patched_fa = {}
    for r in pruns:
        key = (r["repo"], r["run_no"])
        patched_fa[key] = patched_fa.get(key, False) or bool(_caught(conn, r["id"])["l1"])
    vulns, paths, fields, no_tok = {}, [], [], 0
    for r in vruns:
        c = _caught(conn, r["id"])
        paths.extend(c["path_levels"])
        f = _token_fields(conn, r["id"])
        if f is None:
            no_tok += 1
        else:
            fields.append(f)
        pc_key = (r["repo"], r["run_no"])
        vulns.setdefault((r["repo"], r["sha"]), []).append({
            "l1": bool(c["l1"]), "l2": bool(c["l2"]),
            "pair": (bool(c["l1"]) and not patched_fa[pc_key]) if pc_key in patched_fa else None})
    per_vuln = list(vulns.values())
    pair_vals = [_mean([x["pair"] for x in rs]) for rs in per_vuln]
    tok_fields = ({key: sum(f[key] for f in fields) for key in fields[0]} if fields else None)
    walls, rss = _resource_stats(conn, [r["id"] for r in vruns + pruns])
    return {
        "efficiency": efficiency_detail(conn, arm),
        "far": far_detail(conn, arm),
        "n_vulns": len(per_vuln), "n_vuln_runs": len(vruns), "n_patched_runs": len(pruns),
        "recall_l1": _mean([_mean([x["l1"] for x in rs]) for rs in per_vuln]),
        "recall_l2": _mean([_mean([x["l2"] for x in rs]) for rs in per_vuln]),
        "pair_correct": _mean(pair_vals),
        "n_unpaired_runs": sum(1 for rs in per_vuln for x in rs if x["pair"] is None),
        f"pass_at_{k}": _mean([pass_at_k([x["l1"] for x in rs], k) for rs in per_vuln]),
        f"pass_pow_{k}": _mean([pass_pow_k([x["l1"] for x in rs], k) for rs in per_vuln]),
        "n_vulns_under_k_runs": sum(1 for rs in per_vuln if len(rs) < k),
        "path_levels": _path_levels(paths),
        "wall_seconds": walls, "peak_rss_mb": rss,
        "graph_build": _graph_build(conn, [r["id"] for r in vruns + pruns]),
        "tokens": tok_fields, "n_no_token_data": no_tok,
        "dollars": _dollars(tok_fields, (prices or {}).get(arm)),
        "youden_j": None,          # OWASP rows: eval/owasp.py (later task)
        "ppi_precision": None,     # labeled false alarms: eval/judge.py (E4) + human labels
    }


def secondary(conn, *, prices=None, k=3, seed=0):
    """Secondary (reported, not confirmatory) metrics per arm. `prices` = {arm: {field: $/1M tokens}}
    with fields uncached_in / cache_read / cache_write / out; without it dollars is None."""
    return {"arms": {arm: _arm_secondary(conn, arm, k=k, prices=prices) for arm in _arms(conn)},
            "k": k, "seed": seed,
            "notes": ["recall/pair-correct/pass@k: unit = vulnerability (mean of its runs), then mean over vulns",
                      "pair-correct pairs a vulnerable run with the patched run(s) of the same (repo, run_no)",
                      "youden_j and ppi_precision are filled by eval/owasp.py and eval/judge.py",
                      "efficiency and tokens leave out runs with no token data (n_no_token_data)"]}


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


def render(conn, lm_arm, others, *, prices=None, B=10_000, seed=0, far_margin=0.05, svg_path=None):
    sec = secondary(conn, prices=prices, seed=seed)
    dec = decisions(conn, lm_arm, [o for o in others if o in sec["arms"]], far_margin=far_margin, B=B, seed=seed)
    out = [f"# Orion-LM scoring report (report.py sha256 {script_hash()[:12]}, B={B}, seed={seed})", "",
           "## Primary", "", "| arm | E (caught per 1M tokens) | caught | tokens | runs | no token data | FAR | patched runs |",
           "|---|---|---|---|---|---|---|---|"]
    for arm, s in sec["arms"].items():
        e, f = s["efficiency"], s["far"]
        out.append(f"| {arm} | {_fmt(e['E'])} | {e['caught']} | {e['tokens']} | {e['n_runs']} | "
                   f"{e['n_no_token_data']} | {_fmt(f['FAR'])} | {f['n_runs']} |")
    out += ["", f"## Decision rule: {lm_arm} vs frontier (Holm step-down, alpha={dec['alpha']}, FAR margin {far_margin})", "",
            "| vs | log(E_lm/E_X) | Holm CI | Holm p | undefined draws | FAR_lm | FAR_X | beats |", "|---|---|---|---|---|---|---|---|"]
    for other, c in dec["comparisons"].items():
        ci = c["efficiency_ci"]
        out.append(f"| {other} | {_fmt(ci['point'])} | [{_fmt(ci['low'])}, {_fmt(ci['high'])}] @{_fmt(ci['alpha'])} | "
                   f"{_fmt(c['holm_p'])} | {ci['n_undefined']} | {_fmt(c['far_lm'])} | {_fmt(c['far_other'])} | {c['beats']} |")
    out += ["", "## Secondary", "", "| arm | recall L1 | recall L2 | pair-correct | pass@3 | pass^3 | wall s (mean) | peak RSS MB (max) | dollars |",
            "|---|---|---|---|---|---|---|---|---|"]
    for arm, s in sec["arms"].items():
        out.append(f"| {arm} | {_fmt(s['recall_l1'])} | {_fmt(s['recall_l2'])} | {_fmt(s['pair_correct'])} | "
                   f"{_fmt(s['pass_at_3'])} | {_fmt(s['pass_pow_3'])} | {_fmt(s['wall_seconds']['mean'])} | "
                   f"{_fmt(s['peak_rss_mb']['max'])} | {_fmt(s['dollars'])} |")
    rows = [{"arm": arm, "accuracy": s["recall_l1"],
             "cost": (s["efficiency"]["tokens"] / (s["efficiency"]["n_runs"] - s["efficiency"]["n_no_token_data"])
                      if s["efficiency"]["n_runs"] - s["efficiency"]["n_no_token_data"] else None)}
            for arm, s in sec["arms"].items()]
    out += ["", "## Pareto", "", pareto(rows, svg_path=svg_path)]
    return "\n".join(out)


def main(argv=None):
    import argparse
    from eval import db
    ap = argparse.ArgumentParser(description="Orion-LM scoring report")
    ap.add_argument("db", nargs="?", default="eval/runs.db")
    ap.add_argument("--lm", default="orion-lm")
    ap.add_argument("--vs", nargs="*", default=["plain-sonnet5", "plain-opus5", "plain-gpt"])
    ap.add_argument("--B", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--prices", help="JSON file {arm: {uncached_in, cache_read, cache_write, out}} in $/1M tokens")
    ap.add_argument("--svg", help="write the Pareto SVG here")
    a = ap.parse_args(argv)
    prices = None
    if a.prices:
        with open(a.prices) as fh:
            prices = json.load(fh)
    conn = db.connect(a.db)
    print(render(conn, a.lm, a.vs, prices=prices, B=a.B, seed=a.seed, svg_path=a.svg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
