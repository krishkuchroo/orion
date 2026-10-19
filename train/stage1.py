"""Stage 1 labelling (pure part): turn one real fix into vulnerable / patched / negative examples.

Targets, in priority order:
  annotated  the pair's own annotations resolve to function spans in the vulnerable checkout.
             Handled fields (all resolved against `vuln_idx`; test files are never indexed, so they never resolve):
               vuln_methods  {file, method, start_line, end_line, vulnerable_lines}: the span named `method` in `file`
                             nearest `start_line`; anchor = first `vulnerable_lines` entry.
               sink_location "path:line:col" (path may be a basename: matched by exact path, else unique suffix);
                             anchor = line.
               locations     [{sink:{file,lineno}}, {block:{file,start_lineno}}]; anchor = that line.
               source_sink   [{file, sink_line}] (string or int line); anchor = sink_line.
               fix_methods   [{file, method}] names a function in the PATCHED tree; used only as a name hint, resolved to
                             the same-named span in the vulnerable file when exactly one exists (no anchor of its own).
             Lines that fall in no function (a module-level `<module>` window) never become targets. Resolved spans are
             de-duplicated, kept in the order above, and capped at MAX_MULTI.
  single     exactly one changed non-test function.
  multi      2..MAX_MULTI changed functions.
More than MAX_MULTI changed functions is "sprawling"; nothing changed outside tests (or nothing resolves) is "no_target".

The patched example is built on a copy of `vuln_idx` with the patched text of the changed files applied, so the caller's
index is never mutated (a later `cases_from` sees the pristine vulnerable tree).
"""
from __future__ import annotations

import posixpath
import random
from collections import Counter

from orion.lm import cases as _cases
from orion.lm.codeindex import MODULE, RepoIndex, Span, is_test_path, parse_text
from train.sources import DATAFLOW_CWES, cwe_class, norm_cwe

MAX_MULTI = 3
MIN_NEG_LINES = 5


def primary_cwe(pair: dict) -> str | None:
    cwes = [c for c in (norm_cwe(x) for x in pair.get("cwe") or []) if c]
    for c in cwes:
        if int(c[4:]) in DATAFLOW_CWES:
            return c
    return cwes[0] if cwes else None


# ---- annotation resolution -------------------------------------------------------------------

def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _file(idx: RepoIndex, name) -> str | None:
    if not isinstance(name, str) or not name:
        return None
    name = name.replace("\\", "/")
    if name.startswith("./"):
        name = name[2:]
    if name in idx.files:
        return name
    hits = [f for f in idx.files if f.endswith("/" + name)]
    return hits[0] if len(hits) == 1 else None


def _function_at(idx: RepoIndex, file: str, line: int | None) -> Span | None:
    if line is None:
        return None
    s = idx.enclosing(file, line)
    return None if s is None or s.name == MODULE else s


def _by_name(idx: RepoIndex, file: str, name, near: int | None) -> Span | None:
    cands = [s for s in idx.files.get(file, ()) if s.name == name]
    if not cands:
        return None
    if near is None:
        return cands[0] if len(cands) == 1 else None
    return min(cands, key=lambda s: (abs(s.start - near), s.start))


def _annotated(pair: dict, idx: RepoIndex) -> list[tuple[Span, int | None]]:
    """(span, anchor_or_None) in priority order, de-duplicated by span."""
    out: list[tuple[Span, int | None]] = []

    def add(span, anchor):
        if span is not None and all(span != s for s, _ in out):
            out.append((span, anchor))

    for m in pair.get("vuln_methods") or []:
        f = _file(idx, m.get("file"))
        if f is None:
            continue
        span = _by_name(idx, f, m.get("method"), _int(m.get("start_line")))
        vl = [n for n in (_int(x) for x in m.get("vulnerable_lines") or []) if n is not None]
        add(span, vl[0] if vl else None)
    sl = pair.get("sink_location")
    if isinstance(sl, str):
        parts = sl.rsplit(":", 2)
        f, line = (_file(idx, parts[0]), _int(parts[1])) if len(parts) == 3 else (None, None)
        if f is not None:
            add(_function_at(idx, f, line), line)
    for loc in pair.get("locations") or []:
        if not isinstance(loc, dict):
            continue
        end = loc.get("sink") if isinstance(loc.get("sink"), dict) else loc.get("block")
        if not isinstance(end, dict):
            continue
        f, line = _file(idx, end.get("file")), _int(end.get("lineno", end.get("start_lineno")))
        if f is not None:
            add(_function_at(idx, f, line), line)
    for ss in pair.get("source_sink") or []:
        if not isinstance(ss, dict):
            continue
        f, line = _file(idx, ss.get("file")), _int(ss.get("sink_line"))
        if f is not None:
            add(_function_at(idx, f, line), line)
    for fm in pair.get("fix_methods") or []:
        f = _file(idx, fm.get("file")) if isinstance(fm, dict) else None
        if f is not None:
            add(_by_name(idx, f, fm.get("method"), None), None)
    return out


# ---- changed functions -----------------------------------------------------------------------

def _changed_old_lines(h: dict) -> tuple[list[int], bool]:
    """Old-side lines a hunk touches (add-only: the insertion line) and whether it is add-only."""
    a, b = h["old_start"], h["old_end"]
    if b >= a:
        return list(range(a, b + 1)), False
    return [max(a, 1)], True


def _changed_functions(hunks: list[dict], idx: RepoIndex) -> dict[tuple, dict]:
    found: dict[tuple, dict] = {}
    for h in hunks:
        of = h.get("old_file")
        if not of or is_test_path(of) or of not in idx.files:
            continue
        lines, add_only = _changed_old_lines(h)
        spans = idx.files[of]
        for ln in lines:
            if add_only:
                # an insertion after line `ln`: the function must hold both neighbours, or (python) end exactly at `ln`
                inner = [s for s in spans if s.start <= ln and ln + 1 <= s.end]
                if not inner:
                    inner = [s for s in spans if s.start <= ln == s.end and of.endswith(".py")]
            else:
                inner = [s for s in spans if s.start <= ln <= s.end]
            if not inner:
                continue
            s = min(inner, key=lambda x: (x.end - x.start, -x.start))
            ent = found.setdefault((s.file, s.start, s.end), {"span": s, "lines": [], "hunks": []})
            ent["lines"].append(ln)
            if h not in ent["hunks"]:
                ent["hunks"].append(h)
    return found


# ---- targets ---------------------------------------------------------------------------------

def _patched_for(span: Span, hunks: list[dict], patched_text: dict) -> tuple[Span | None, int | None, str | None]:
    """(patched span, anchor_new, why-missing). Only functions in a file some hunk touches have a patched version."""
    touching = [h for h in hunks if h.get("old_file") == span.file]
    if not touching:
        return None, None, "patched_unchanged"
    new_file = touching[0].get("file")
    text = patched_text.get(new_file) if new_file else None
    if not new_file or text is None:
        return None, None, "patched_missing"
    try:
        spans = parse_text(new_file, text) or []
    except Exception:
        return None, None, "patched_missing"
    same = [s for s in spans if s.name == span.name]
    if not same:
        return None, None, "patched_missing"
    ps = min(same, key=lambda s: (abs(s.start - span.start), s.start))
    anchor = next((h["new_start"] for h in touching if ps.start <= h["new_start"] <= ps.end), ps.start)
    return ps, anchor, None


def _anchor_old(span: Span, annotated_anchor: int | None, ent: dict | None) -> int:
    if annotated_anchor is not None and span.start <= annotated_anchor <= span.end:
        return annotated_anchor
    if ent and ent["lines"]:
        return min(ent["lines"])
    return span.start


def targets(pair: dict, hunks: list[dict], vuln_idx: RepoIndex,
            patched_text: dict[str, str | None]) -> tuple[list[dict], str | None]:
    changed = _changed_functions(hunks, vuln_idx)
    ann = _annotated(pair, vuln_idx)[:MAX_MULTI]
    if ann:
        picked = [(s, a, "annotated") for s, a in ann]
    elif not changed:
        return [], "no_target"
    elif len(changed) > MAX_MULTI:
        return [], "sprawling"
    else:
        tier = "single" if len(changed) == 1 else "multi"
        picked = [(e["span"], None, tier) for e in changed.values()]
    out = []
    for span, ann_anchor, tier in picked:
        ent = changed.get((span.file, span.start, span.end))
        ps, anchor_new, missing = _patched_for(span, hunks, patched_text)
        out.append({"file": span.file, "name": span.name, "vuln_span": span, "patched_span": ps,
                    "anchor_old": _anchor_old(span, ann_anchor, ent), "anchor_new": anchor_new,
                    "tier": tier, "patched_reason": missing})
    return out, None


# ---- examples --------------------------------------------------------------------------------

def _patched_index(vuln_idx: RepoIndex, patched_text: dict) -> RepoIndex:
    """A copy of the vulnerable index with the patched text applied (the original is left untouched)."""
    cp = RepoIndex.__new__(RepoIndex)
    cp.root = vuln_idx.root
    cp.files = dict(vuln_idx.files)
    cp.skipped = dict(vuln_idx.skipped)
    cp._lines = dict(vuln_idx._lines)
    cp._text = dict(vuln_idx._text)
    cp._by_name = None
    for rel, text in patched_text.items():
        if is_test_path(rel):
            continue
        if text is None:
            cp.files.pop(rel, None)
            cp._lines.pop(rel, None)
            cp._text.pop(rel, None)
        else:
            cp.update(rel, text)
    return cp


def _overlaps_hunk(span: Span, hunks: list[dict]) -> bool:
    for h in hunks:
        if h.get("old_file") != span.file:
            continue
        lo, hi = (h["old_start"], h["old_end"]) if h["old_end"] >= h["old_start"] else (h["old_start"], h["old_start"] + 1)
        if lo <= span.end and hi >= span.start:
            return True
    return False


def _negative_spans(vuln_idx: RepoIndex, hunks: list[dict], tgts: list[dict]) -> list[Span]:
    taken = {(t["vuln_span"].file, t["vuln_span"].start, t["vuln_span"].end) for t in tgts}
    out = []
    for rel in sorted(vuln_idx.files):
        if is_test_path(rel):
            continue
        for s in vuln_idx.files[rel]:
            if (s.end - s.start + 1 >= MIN_NEG_LINES and s.calls and s.name != MODULE
                    and (s.file, s.start, s.end) not in taken and not _overlaps_hunk(s, hunks)):
                out.append(s)
    return out


def cases_from(pair: dict, hunks: list[dict], vuln_idx: RepoIndex, patched_text: dict[str, str | None], *,
               budget: _cases.CaseBudget, n_negatives: int, seed: int) -> tuple[list[dict], dict]:
    rec = {"id": pair["id"], "status": "skipped", "reason": None, "n_targets": 0, "tiers": {}, "n_negatives": 0}
    cwe = primary_cwe(pair)
    klass = pair.get("cwe_class") or cwe_class(pair.get("cwe"))
    if cwe is None or klass == "unknown":
        rec["reason"] = "no_cwe"
        return [], rec
    tgts, reason = targets(pair, hunks, vuln_idx, patched_text)
    if not tgts:
        rec["reason"] = reason
        return [], rec

    def ex(label, tier, case, lead):
        return {"pair_id": pair["id"], "label": label, "tier": tier, "cwe_class": klass, "case": case, "lead": lead}

    examples, reasons, used = [], [], []
    patched_idx = None
    for t in tgts:
        vs = t["vuln_span"]
        vcase = _cases.case_from_function(vuln_idx, vs.file, vs, anchor=t["anchor_old"], budget=budget)
        if not vcase["snippets"]:
            reasons.append("no_snippet")
            continue
        used.append(t)
        examples.append(ex("vulnerable", t["tier"], vcase,
                           {"flow_id": "F0", "file": vs.file, "function": vs.name, "line": t["anchor_old"],
                            "cwe": cwe, "confidence": "HIGH"}))
        ps = t["patched_span"]
        if ps is None:
            reasons.append(t["patched_reason"] or "patched_missing")
            continue
        if patched_idx is None:
            patched_idx = _patched_index(vuln_idx, patched_text)
        pcase = _cases.case_from_function(patched_idx, ps.file, ps, anchor=t["anchor_new"] or ps.start, budget=budget)
        if not pcase["snippets"]:
            reasons.append("no_snippet")
        elif pcase["snippets"][0]["code"] == vcase["snippets"][0]["code"]:
            reasons.append("patched_unchanged")
        else:
            examples.append(ex("patched", t["tier"], pcase, None))
    if not used:
        rec["reason"] = ",".join(dict.fromkeys(reasons)) or "no_target"
        return [], rec

    pool = _negative_spans(vuln_idx, hunks, used)
    rng = random.Random(f"{seed}:{pair['id']}")
    n_neg = 0
    for s in rng.sample(pool, min(max(n_negatives, 0), len(pool))):
        case = _cases.case_from_function(vuln_idx, s.file, s, anchor=rng.randint(s.start, s.end), budget=budget)
        if case["snippets"]:
            examples.append(ex("negative", "negative", case, None))
            n_neg += 1
    rec.update(status="ok", reason=",".join(dict.fromkeys(reasons)) or None, n_targets=len(used),
               tiers=dict(Counter(t["tier"] for t in used)), n_negatives=n_neg)
    return examples, rec
