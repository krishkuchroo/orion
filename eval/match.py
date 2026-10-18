"""Deterministic matcher: L1 (frozen location rule), L2 (+CWE family), path levels, one-to-one.

L1 (frozen 2026-09-17, CLAUDE.md): same file AND (function-name match OR a reported line within the
patched range +/-10). Path metrics never change an L1 result.
"""
import json
import re

from eval import cwe as _cwe

_WINDOW = 10
_SEG = re.compile(r"\.|::")


def _norm_file(p):
    if not p:
        return None
    p = str(p)
    while p.startswith("./"):
        p = p[2:]
    return p or None


def _same_file(a, b) -> bool:
    a, b = _norm_file(a), _norm_file(b)
    if a is None or b is None:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _strip_fn(f):
    if not f:
        return None
    f = str(f).strip()
    if f.endswith("()"):
        f = f[:-2]
    return f or None


def _last_seg(f):
    f = _strip_fn(f)
    return _SEG.split(f)[-1] if f else None


def _func_match(finding_fn, key_fn) -> bool:
    k, f = _strip_fn(key_fn), _strip_fn(finding_fn)
    if k is None or f is None:
        return False
    return f == k or _last_seg(f) == k


def _loc(finding, key_file, key_fn, lo, hi) -> bool:
    if not _same_file(finding.get("file"), key_file):
        return False
    if _func_match(finding.get("function"), key_fn):
        return True
    line = finding.get("line")
    return line is not None and lo is not None and hi is not None and lo - _WINDOW <= line <= hi + _WINDOW


def l1(finding: dict, answer_key: dict) -> bool:
    return _loc(finding, answer_key.get("file"), answer_key.get("function"),
                answer_key.get("line_start"), answer_key.get("line_end"))


def l1_fix_site(lead: dict, fix_site: dict) -> bool:
    """The L1 rule against a single {file, line, function} fix site."""
    ln = fix_site.get("line")
    return _loc(lead, fix_site.get("file"), fix_site.get("function"), ln, ln)


def l2(finding: dict, answer_key: dict) -> bool:
    return l1(finding, answer_key) and _cwe.same_family(finding.get("cwe"), answer_key.get("cwe"))


def _f1(a: set, b: set):
    if not a or not b:
        return None
    tp = len(a & b)
    if tp == 0:
        return 0.0
    p, r = tp / len(a), tp / len(b)
    return 2 * p * r / (p + r)


def path_levels(finding: dict, answer_key: dict) -> dict:
    """Secondary path metrics (spec section 6).

    edge_validity is None for now: it needs the code graph to check each hop is a real edge.
    """
    path = finding.get("path") or []
    fixes = answer_key.get("fix_sites") or []
    entries = answer_key.get("accepted_entry_points") or []

    fix_traversal = any(
        _same_file(n.get("file"), fs.get("file")) and n.get("line") is not None
        and fs.get("line") is not None and abs(n["line"] - fs["line"]) <= _WINDOW
        for n in path for fs in fixes)

    entry_hit = False
    if path:
        first = path[0]
        for e in entries:
            fn_ok = _func_match(first.get("function"), _last_seg(e.get("method_full_name")))
            file_ok = e.get("file") is None or _same_file(first.get("file"), e.get("file"))
            if fn_ok and file_ok:
                entry_hit = True
                break

    waypoint_f1 = None
    if path:
        got = {(_norm_file(n.get("file")), _last_seg(n.get("function"))) for n in path}
        want = {(_norm_file(fs.get("file")), _last_seg(fs.get("function"))) for fs in fixes}
        want |= {(_norm_file(e.get("file")), _last_seg(e.get("method_full_name"))) for e in entries}
        waypoint_f1 = _f1(got, want)

    return {"fix_traversal": fix_traversal, "entry_hit": entry_hit,
            "edge_validity": None, "waypoint_f1": waypoint_f1}


def match_run(findings: list, answer_keys: list) -> list:
    """Greedy one-to-one assignment: L2 pairs first, then L1; ties by lowest finding index.

    A finding credits at most one vuln and a vuln is credited by at most one finding.
    """
    vid = [str(k["id"]) if k.get("id") is not None else str(i) for i, k in enumerate(answer_keys)]
    used_f, used_v, rows = set(), set(), []
    for level, test in (("L2", l2), ("L1", l1)):
        for fi, f in enumerate(findings):
            if fi in used_f:
                continue
            for vi, k in enumerate(answer_keys):
                if vi in used_v or not test(f, k):
                    continue
                used_f.add(fi)
                used_v.add(vi)
                rows.append({"finding_idx": fi, "vuln_id": vid[vi], "level": level,
                             "cwe_family": level == "L2",
                             "path_level": json.dumps(path_levels(f, k)) if f.get("path") else None})
                break
    rows.sort(key=lambda r: r["finding_idx"])
    return rows


def write_matches(conn, run_id, rows) -> None:
    conn.executemany(
        "INSERT INTO matches(run_id, vuln_id, finding_idx, level, cwe_family, path_level) "
        "VALUES (?,?,?,?,?,?)",
        [(run_id, r["vuln_id"], r["finding_idx"], r["level"], int(bool(r["cwe_family"])),
          r["path_level"]) for r in rows])
    conn.commit()
