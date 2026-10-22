"""LLM judge for final scoring only: classify, calibration (kappa / AC1), PPI precision.

SCOPE GUARD: this module is for the report / final-scoring path ONLY. Nothing under `train/` and not
`eval.bakeoff` may import it, so no judge output can reach training selection or dev scoring (spec
5.4 "LLM judge scope"). `eval/tests/test_judge.py` checks this in a fresh interpreter.

Undefined statistics are returned as None, never 0 or NaN: kappa/AC1 when chance agreement is 1 (or
fewer than two categories, or no labels), a CI when too few human labels exist, precision when there
are no findings. A missing value stays missing.
"""
import hashlib
import math
import re
from collections import Counter

LABELS = ("real_other_bug", "false_alarm", "unsure")

# Krish freezes the judge model id and the prompt text at the pre-registration tag (Task F4); both are
# recorded for that gate. None = not yet chosen; nothing is guessed.
JUDGE_MODEL = None

# Draft. Blinded to arm identity: the prompt is built only from the finding's own content.
JUDGE_PROMPT = """You are reviewing one security finding reported against a code repository.
The finding did not match any known vulnerability in the answer key. Decide what it is.

Finding:
{finding}

Answer with exactly one label and nothing else:
- real_other_bug: a genuine security bug, just not one in the answer key
- false_alarm: not a real vulnerability (safe code, guarded, or unreachable)
- unsure: the finding gives too little to decide
"""


def prompt_sha256() -> str:
    return hashlib.sha256(JUDGE_PROMPT.encode("utf-8")).hexdigest()


def _render(finding: dict) -> str:
    # Only content fields: never `arm` (blinding), never the path/run metadata.
    parts = []
    for key in ("file", "function", "line", "cwe"):
        v = finding.get(key)
        if v not in (None, ""):
            parts.append(f"{key}: {v}")
    parts.append(f"description: {finding.get('raw_text') or ''}")
    return "\n".join(parts)


def _parse_label(reply):
    if not isinstance(reply, str):
        return None
    for cand in (reply, reply.strip().splitlines()[0] if reply.strip() else ""):
        c = re.sub(r"[\s\-]+", "_", cand.strip().strip("`'\".*").lower())
        if c in LABELS:
            return c
    return None


def classify(finding: dict, *, ask) -> dict:
    """Label one finding via the injected `ask(prompt) -> str`. Any reply that is not exactly one of
    the three labels becomes `unsure`; the raw reply is always kept. Exceptions from `ask` propagate."""
    prompt = JUDGE_PROMPT.format(finding=_render(finding))
    reply = ask(prompt)
    label = _parse_label(reply)
    return {"label": label or "unsure", "raw_reply": reply, "parsed": label is not None}


def _agreement(a, b) -> dict:
    n = len(a)
    if n == 0:
        return {"n": 0, "agreement": None, "kappa": None, "ac1": None}
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    cats = set(ca) | set(cb)
    pe_k = sum((ca[k] / n) * (cb[k] / n) for k in cats)
    kappa = None if pe_k >= 1 else (po - pe_k) / (1 - pe_k)
    ac1 = None
    if len(cats) >= 2:
        pi = {k: (ca[k] + cb[k]) / (2 * n) for k in cats}
        pe_g = sum(p * (1 - p) for p in pi.values()) / (len(cats) - 1)
        ac1 = None if pe_g >= 1 else (po - pe_g) / (1 - pe_g)
    return {"n": n, "agreement": po, "kappa": kappa, "ac1": ac1}


def calibrate(judge_labels, human_labels, arms=None) -> dict:
    """Cohen's kappa and Gwet's AC1 between judge and human labels (>=100 blinded findings in the real
    run; `min_n_met` says whether that holds). `arms`, if given, is aligned with the labels and adds a
    `per_arm` breakdown (self-preference check). Undefined values are None."""
    j, h = list(judge_labels), list(human_labels)
    if len(j) != len(h):
        raise ValueError(f"label length mismatch: {len(j)} judge vs {len(h)} human")
    out = _agreement(j, h)
    out["min_n_met"] = out["n"] >= 100
    if arms is not None:
        arms = list(arms)
        if len(arms) != len(j):
            raise ValueError(f"arms length {len(arms)} != labels length {len(j)}")
        per = {}
        for arm in sorted(set(arms), key=str):
            idx = [i for i, x in enumerate(arms) if x == arm]
            per[arm] = _agreement([j[i] for i in idx], [h[i] for i in idx])
        out["per_arm"] = per
    return out


def _is_real(label) -> float:
    # `unsure` and anything else count as NOT a real bug (conservative for precision).
    return 1.0 if label == "real_other_bug" else 0.0


def _var(xs):
    n = len(xs)
    if n < 2:
        return None
    m = sum(xs) / n
    return sum((x - m) ** 2 for x in xs) / (n - 1)


def ppi_precision(matched, judged, human, z: float = 1.96) -> dict:
    """Prediction-powered precision (Angelopoulos et al. 2023, mean estimation).

    matched: count (or list) of findings matched by the deterministic matcher; treated as true.
    judged:  judge label for EVERY unmatched finding.
    human:   sequence aligned with `judged`; a human label, or None where no human label exists.
    theta_unmatched = mean(f over all unmatched) + mean(y - f over human-labelled), f/y = 1 iff
    `real_other_bug`. Precision = (M + N*theta) / (M + N). CI is normal-approx, 95% by default; None
    when fewer than 2 labelled findings. `classical` is the human-labels-only estimate (same CI).
    """
    m = len(matched) if not isinstance(matched, int) else matched
    f_all = [_is_real(x) for x in judged]
    human = list(human)
    if len(human) != len(f_all):
        raise ValueError("human must align with judged (use None for unlabelled)")
    big_n = len(f_all)
    total = m + big_n
    lab = [(f_all[i], _is_real(y)) for i, y in enumerate(human) if y is not None]
    n = len(lab)
    res = {"matched": m, "unmatched": big_n, "n_labeled": n, "precision": None, "ci": None,
           "classical": None, "classical_ci": None}
    if total == 0:
        return res
    if big_n == 0:
        res["precision"] = 1.0 if m else None
        return res
    if n == 0:
        return res
    rect = [y - f for f, y in lab]
    theta = sum(f_all) / big_n + sum(rect) / n
    w = big_n / total
    res["precision"] = (m + big_n * theta) / total
    vf, vr = _var(f_all), _var(rect)
    if vr is not None and vf is not None:
        se = w * math.sqrt(vf / big_n + vr / n)
        res["ci"] = [res["precision"] - z * se, res["precision"] + z * se]
    ys = [y for _, y in lab]
    cl = sum(ys) / n
    res["classical"] = (m + big_n * cl) / total
    vy = _var(ys)
    if vy is not None:
        se = w * math.sqrt(vy / n)
        res["classical_ci"] = [res["classical"] - z * se, res["classical"] + z * se]
    return res


def judge_record() -> dict:
    """What the report must print about the judge: model id (None if unfrozen) and prompt hash."""
    return {"model": JUDGE_MODEL, "prompt_sha256": prompt_sha256()}
