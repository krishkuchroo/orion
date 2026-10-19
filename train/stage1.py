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

import argparse
import json
import os
import posixpath
import random
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter

from orion.lm import cases as _cases
from orion.lm.codeindex import LANG_BY_EXT, MODULE, RepoIndex, Span, is_test_path, parse_text
from train import snapshot
from train.build import _children_detached, _safe, resolve_commits
from train.fixmap import fix_hunks, map_line
from train.snapshot import LANG_GLOBS, SnapshotError, _dir_bytes, show
from train.splits import load as load_splits
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
    return [a], True


def _is_new_function_hunk(h: dict, patched_text: dict) -> bool:
    """True when the hunk's new lines are entirely one function that exists only in the patched text."""
    text = patched_text.get(h.get("file"))
    if not text:
        return False
    try:
        spans = parse_text(h["file"], text) or []
    except Exception:
        return False
    lo, hi = h["new_start"], h["new_end"]
    lines = text.split("\n")
    for p in spans:
        if lo <= p.start and p.end <= hi:
            rest = [l for i, l in enumerate(lines[lo - 1:hi], lo) if not p.start <= i <= p.end]
            if all(not l.strip() for l in rest):
                return True
    return False


def _changed_functions(hunks: list[dict], idx: RepoIndex, patched_text: dict) -> dict[tuple, dict]:
    found: dict[tuple, dict] = {}
    for h in hunks:
        of = h.get("old_file")
        if not of or is_test_path(of) or of not in idx.files:
            continue
        lines, add_only = _changed_old_lines(h)
        a_only_new_fn = None
        spans = idx.files[of]
        for ln in lines:
            if add_only:
                # insertion AFTER old line `ln` (0 = top of file): it belongs to a function only when that function
                # holds both neighbours, i.e. the insertion is strictly inside the body (not at/after its last line)
                if a_only_new_fn is None:
                    a_only_new_fn = _is_new_function_hunk(h, patched_text)
                if a_only_new_fn:
                    continue
                inner = [s for s in spans if s.start <= ln and ln + 1 <= s.end]
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
    # map the vulnerable span's ends through the hunks (D3's map_line), then take the same-named span holding
    # a mapped line, else the nearest one
    mapped = [ln for edge in (span.start, span.end) for ln in map_line(hunks, span.file, edge)[1]]
    ps = min(same, key=lambda s: (not any(s.start <= m <= s.end for m in mapped),
                                  min((abs(s.start - m) for m in mapped), default=0), s.start))
    anchor = next((h["new_start"] for h in touching if ps.start <= h["new_start"] <= ps.end), ps.start)
    return ps, anchor, None


def _anchor_old(span: Span, annotated_anchor: int | None, ent: dict | None) -> int:
    if annotated_anchor is not None and span.start <= annotated_anchor <= span.end:
        return annotated_anchor
    if ent and ent["lines"]:
        return min(ent["lines"])
    return span.start


def _src(idx: RepoIndex, span: Span) -> str:
    return idx.source(span.file, span.start, span.end)


def targets(pair: dict, hunks: list[dict], vuln_idx: RepoIndex,
            patched_text: dict[str, str | None]) -> tuple[list[dict], str | None]:
    changed = _changed_functions(hunks, vuln_idx, patched_text)
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


def _negative_spans(vuln_idx: RepoIndex, hunks: list[dict], tgts: list[dict], annotated: list[Span]) -> list[Span]:
    taken = [t["vuln_span"] for t in tgts] + list(annotated)   # every target and every resolved annotation
    out = []
    for rel in sorted(vuln_idx.files):
        if is_test_path(rel):
            continue
        for s in vuln_idx.files[rel]:
            if (s.end - s.start + 1 >= MIN_NEG_LINES and s.calls and s.name != MODULE
                    and not any(t.file == s.file and t.start <= s.end and s.start <= t.end for t in taken)
                    and not _overlaps_hunk(s, hunks)):
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
        elif _src(vuln_idx, vs) == _src(patched_idx, ps):
            reasons.append("patched_unchanged")
        else:
            examples.append(ex("patched", t["tier"], pcase, None))
    if not used:
        rec["reason"] = ",".join(dict.fromkeys(reasons)) or "no_target"
        return [], rec

    pool = _negative_spans(vuln_idx, hunks, tgts, [a for a, _ in _annotated(pair, vuln_idx)])
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


# ───────────────────────────── runner ─────────────────────────────

def _repo_url(pair: dict) -> str:
    return pair.get("repo_url") or f"https://github.com/{pair.get('repo_canonical') or pair['repo']}.git"


def _globs(pairs: list[dict]) -> list[str]:
    """Union of the language globs of a repo's pairs (a mixed / unknown language gets every language)."""
    langs = {p.get("language") for p in pairs}
    keys = [k for k in LANG_GLOBS if k in langs] if langs <= set(LANG_GLOBS) else list(LANG_GLOBS)
    return list(dict.fromkeys(g for k in keys for g in LANG_GLOBS[k]))


def _done_ids(ledger: str) -> set[str]:
    done: set[str] = set()
    if os.path.exists(ledger):
        with open(ledger) as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["id"])
                except (ValueError, KeyError, TypeError):
                    continue   # a torn last line: that pair is redone
    return done


def _append(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
        fh.flush()


def _skip_checkout(run):
    """`snapshot.fetch` checks out the sha it is given, but the vulnerable sha is only known after
    `resolve_commits` (fix commit's parent). Run the clone + sparse-checkout steps, swallow the final
    checkout, and let `_one_pair` check out the resolved vulnerable commit itself."""
    def r(cmd, timeout=None):
        return "" if cmd[3:4] == ["checkout"] else run(cmd, timeout=timeout)
    return r


def _ledger_row(pair_id: str, status: str, reason=None, **kw) -> dict:
    row = {"id": pair_id, "status": status, "reason": reason, "seconds_fetch": None, "bytes": None,
           "seconds_index": None, "n_files": None, "n_skipped": None, "n_examples": None, "tiers": None}
    row.update(kw)
    return row


def _one_pair(pair: dict, split: str, dest: str, fetch_s: float | None, *, budget, n_negatives, seed, r1, run
              ) -> tuple[list[dict], dict]:
    """Resolve, check out the vulnerable commit, index, label. Raises SnapshotError/CalledProcessError for
    git failures (the caller records snapshot_failed)."""
    res = resolve_commits(pair, dest, run=r1)
    if res["status"] != "ok":
        return [], _ledger_row(pair["id"], res["status"], res["reason"], seconds_fetch=fetch_s)
    t0 = time.monotonic()
    r1(["git", "-C", dest, "checkout", "--quiet", "--force", res["vulnerable"]])
    fetch_s = (fetch_s or 0.0) + (time.monotonic() - t0)
    size = _dir_bytes(dest)
    hunks = fix_hunks(dest, res["vulnerable"], res["patched"], fix_shas=res["fix_shas"], run=r1)
    t0 = time.monotonic()
    idx = RepoIndex(dest)
    seconds_index = time.monotonic() - t0
    patched_text = {}
    for h in hunks:
        f = h["file"]
        if f and f not in patched_text and posixpath.splitext(f)[1].lower() in LANG_BY_EXT:
            patched_text[f] = show(dest, res["patched"], f, run=run)
    examples, rec = cases_from(pair, hunks, idx, patched_text, budget=budget, n_negatives=n_negatives, seed=seed)
    for e in examples:
        e["split"] = split
    return examples, _ledger_row(pair["id"], rec["status"], rec["reason"], seconds_fetch=fetch_s, bytes=size,
                                 seconds_index=seconds_index, n_files=len(idx.files),
                                 n_skipped=len(idx.skipped), n_examples=len(examples), tiers=rec["tiers"])


def build(pairs: list[dict], splits: dict[str, str], *, work_root: str, out_jsonl: str, ledger: str,
          budget: _cases.CaseBudget, n_negatives: int, seed: int, on_event=print, fetch=snapshot.fetch,
          run=None) -> dict:
    """Label every pair not yet in `ledger`; append examples to `out_jsonl` and one line per pair to `ledger`.

    One partial snapshot per repo serves all of its pairs and is deleted after the repo's last pair. Ctrl-C
    (SIGINT) finishes the current pair, then stops. Examples are written before the ledger line, so a crash
    between the two re-does that pair (duplicate examples) rather than losing it."""
    run = run or snapshot._default_run
    r1 = lambda cmd: run(cmd, timeout=snapshot.CLONE_TIMEOUT_S)  # noqa: E731 - build/fixmap runners take (cmd)
    done = _done_ids(ledger)
    todo = [p for p in pairs if p["id"] not in done]
    groups: dict[str, list[dict]] = {}
    for p in todo:
        groups.setdefault(_repo_url(p), []).append(p)
    totals = {"pairs": len(todo), "done": 0, "interrupted": False, "examples": 0, "status": Counter()}
    stop = {"flag": False}

    def on_sigint(_sig, _frame):
        stop["flag"] = True
        on_event("interrupt: finishing the current pair, then stopping")

    try:
        old = signal.signal(signal.SIGINT, on_sigint)
    except ValueError:      # not the main thread
        old = None
    i = 0

    def record(pair, row, examples):
        if examples:
            _append(out_jsonl, examples)
        _append(ledger, [row])
        totals["done"] += 1
        totals["examples"] += len(examples)
        totals["status"][row["status"]] += 1
        on_event(f"    -> {row['status']}" + (f" ({row['reason']})" if row["reason"] else "")
                 + f", {len(examples)} examples")

    try:
        with _children_detached():
            for url, group in groups.items():
                dest = os.path.join(work_root, _safe(url))
                snap = None     # fetch result, once tried
                try:
                    for pair in group:
                        if stop["flag"]:
                            break
                        i += 1
                        on_event(f"[{i}/{len(todo)}] {pair['id']} {url}")
                        split = splits[pair["id"]]
                        klass = pair.get("cwe_class") or cwe_class(pair.get("cwe"))
                        if primary_cwe(pair) is None or klass == "unknown":
                            record(pair, _ledger_row(pair["id"], "skipped", "no_cwe", n_examples=0), [])
                            continue
                        if snap is None:
                            os.makedirs(work_root, exist_ok=True)
                            snap = fetch(url, "HEAD", dest, globs=_globs(group), run=_skip_checkout(run))
                            first_fetch = snap["seconds"]
                        else:
                            first_fetch = None
                        if not snap["ok"]:
                            record(pair, _ledger_row(pair["id"], "snapshot_failed", snap["error"],
                                                     seconds_fetch=first_fetch), [])
                            continue
                        try:
                            examples, row = _one_pair(pair, split, dest, first_fetch, budget=budget,
                                                      n_negatives=n_negatives, seed=seed, r1=r1, run=run)
                        except (SnapshotError, subprocess.SubprocessError, OSError) as exc:
                            examples, row = [], _ledger_row(pair["id"], "snapshot_failed",
                                                            snapshot._head(exc), seconds_fetch=first_fetch)
                        except Exception as exc:  # noqa: BLE001 - one bad pair must not stop an overnight run
                            examples, row = [], _ledger_row(pair["id"], "error", f"{type(exc).__name__}: {exc}"[:1500],
                                                            seconds_fetch=first_fetch)
                        record(pair, row, examples)
                finally:
                    shutil.rmtree(dest, ignore_errors=True)
                if stop["flag"]:
                    break
    except KeyboardInterrupt:   # no handler installed (non-main thread) or raised outside a pair
        stop["flag"] = True
    finally:
        if old is not None:
            signal.signal(signal.SIGINT, old)
    totals["interrupted"] = stop["flag"]
    totals["status"] = dict(totals["status"])
    return totals


def select_pairs(pairs: list[dict], *, languages=None, classes=None, per_language: int | None = None,
                 limit: int | None = None, seed: int = 0) -> list[dict]:
    """Stage-1 eligible pairs: no `unknown` cwe_class, optional language / class filters, then a seeded sample of
    `per_language` pairs per language, then `limit`."""
    out = [p for p in pairs if (p.get("cwe_class") or cwe_class(p.get("cwe"))) != "unknown"]
    if languages:
        out = [p for p in out if p.get("language") in languages]
    if classes:
        out = [p for p in out if (p.get("cwe_class") or cwe_class(p.get("cwe"))) in classes]
    if per_language is not None:
        picked = []
        for lang in sorted({p.get("language") or "" for p in out}):
            grp = sorted((p for p in out if (p.get("language") or "") == lang), key=lambda p: p["id"])
            picked += random.Random(f"{seed}:{lang}").sample(grp, min(per_language, len(grp)))
        out = picked
    return out[:limit] if limit is not None else out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m train.stage1", description=__doc__.splitlines()[0])
    ap.add_argument("--pairs", default="train/data/pairs.json")
    ap.add_argument("--splits", default="train/data/splits.json")
    ap.add_argument("--out", default="train/data/stage1.jsonl")
    ap.add_argument("--ledger", default="train/data/stage1_ledger.jsonl")
    ap.add_argument("--work-root", default="train/data/work")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--per-language", type=int, help="seeded sample of N pairs per language")
    ap.add_argument("--languages", help="comma list, e.g. js,py,java")
    ap.add_argument("--classes", help="comma list of cwe_class, e.g. dataflow,other")
    ap.add_argument("--n-negatives", type=int, default=2)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    with open(a.pairs) as f:
        all_pairs = json.load(f)
    if not os.path.exists(a.splits):
        print(f"{a.splits} not found: freeze the splits first (train.splits.write)", file=sys.stderr)
        return 2
    splits = load_splits(a.splits, all_pairs)   # checked against the full pair set, before any filtering
    sel = select_pairs(all_pairs, languages=a.languages.split(",") if a.languages else None,
                       classes=a.classes.split(",") if a.classes else None,
                       per_language=a.per_language, limit=a.limit, seed=a.seed)
    totals = build(sel, splits, work_root=a.work_root, out_jsonl=a.out, ledger=a.ledger,
                   budget=_cases.CaseBudget(), n_negatives=a.n_negatives, seed=a.seed)
    print(json.dumps(totals))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
