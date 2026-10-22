"""Deterministic matcher: L1 (frozen location rule), L2 (+CWE family), path levels, one-to-one.

L1 (frozen 2026-09-17, CLAUDE.md): same file AND (function-name match OR a reported line within the
patched range +/-10). Path metrics never change an L1 result.

Answer keys. A manifest row's key comes from eval.manifest.answer_keys(row, side): it carries the
row's fix sites for that side (`fix_sites` for a run on the vulnerable commit, `fix_sites_patched`
for a run on the patched commit, whose line numbers differ), and L1 credits it when ANY one site
matches: same file AND (function match OR line in [line - 10, end_line + 10]) for that site
(l1_fix_site). "Any site" is a MATCHING-RULE EXTENSION (a fix with several sites, n_files up to 10):
log it in eval/CHANGELOG.md at the tag (orion-lm-prereg-v1) with the other extensions. A key without
`fix_sites` is the older single-range shape {file, function, line_start, line_end}.
Each run is matched against its OWN row's key (vuln_id = row id); one-to-one as below.
"""
import json

from eval import cwe as _cwe
from eval.names import function_name

_WINDOW = 10


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


def _func_match(finding_fn, key_fn) -> bool:
    """Same function: equal as written, or equal bare names (eval.names.function_name on both sides,
    so a Joern full name, "Cls.m", "Cls::m" and "m()" all reduce to "m")."""
    k, f = _strip_fn(key_fn), _strip_fn(finding_fn)
    if k is None or f is None:
        return False
    return f == k or (function_name(f) is not None and function_name(f) == function_name(k))


def _loc(finding, key_file, key_fn, lo, hi) -> bool:
    if not _same_file(finding.get("file"), key_file):
        return False
    if _func_match(finding.get("function"), key_fn):
        return True
    line = finding.get("line")
    if line is None or (lo is None and hi is None):
        return False
    # Degenerate keys only: a missing bound falls back to the other; inverted bounds are swapped.
    lo, hi = (hi if lo is None else lo), (lo if hi is None else hi)
    lo, hi = min(lo, hi), max(lo, hi)
    return lo - _WINDOW <= line <= hi + _WINDOW


def l1(finding: dict, answer_key: dict) -> bool:
    """L1 against an answer key: ANY of its `fix_sites` (manifest keys, see the module doc), else the
    single {file, function, line_start, line_end} range."""
    if "fix_sites" in answer_key:
        return any(l1_fix_site(finding, s) for s in answer_key.get("fix_sites") or ()
                   if isinstance(s, dict))
    return _loc(finding, answer_key.get("file"), answer_key.get("function"),
                answer_key.get("line_start"), answer_key.get("line_end"))


def l1_fix_site(lead: dict, fix_site: dict) -> bool:
    """The L1 rule against a single {file, line, end_line, function} fix site: same file AND
    (function match OR line in [line - 10, end_line + 10]); no end_line = the single line."""
    return _loc(lead, fix_site.get("file"), fix_site.get("function"), fix_site.get("line"),
                fix_site.get("end_line", fix_site.get("line")))


def l2(finding: dict, answer_key: dict) -> bool:
    """L1 + the finding's CWE is in the family of ANY CWE the advisory lists (``cwes``, when the
    answer key has a non-empty list), else of the answer key's single ``cwe``."""
    if not l1(finding, answer_key):
        return False
    keys = answer_key.get("cwes") or [answer_key.get("cwe")]
    return any(_cwe.same_family(finding.get("cwe"), k) for k in keys)


def _f1(a: set, b: set):
    if not a or not b:
        return None
    tp = len(a & b)
    if tp == 0:
        return 0.0
    p, r = tp / len(a), tp / len(b)
    return 2 * p * r / (p + r)


def _in_window(node: dict, site: dict) -> bool:
    """A path node inside a site's L1 window: same file and line in [line - 10, end_line + 10]
    (a site without end_line is the single line `line`)."""
    if node.get("line") is None or not _same_file(node.get("file"), site.get("file")):
        return False
    lo, hi = site.get("line"), site.get("end_line")
    if lo is None and hi is None:
        return False
    lo, hi = (hi if lo is None else lo), (lo if hi is None else hi)
    return min(lo, hi) - _WINDOW <= node["line"] <= max(lo, hi) + _WINDOW


def _entry_site(e: dict) -> dict:
    return {"file": e.get("file"), "line": e.get("line"), "end_line": e.get("end_line")}


def _lm_waypoint_f1(path: list, waypoints: list):
    """Waypoint F1 by file + line (orion-lm nodes): P = share of distinct (file, line) nodes inside
    some waypoint's window, R = share of waypoints with some node inside their window."""
    nodes = list({(_norm_file(n.get("file")), n.get("line")): n for n in path}.values())
    if not nodes or not waypoints:
        return None
    node_hits = sum(1 for n in nodes if any(_in_window(n, w) for w in waypoints))
    wp_hits = sum(1 for w in waypoints if any(_in_window(n, w) for n in nodes))
    if not node_hits or not wp_hits:
        return 0.0
    p, r = node_hits / len(nodes), wp_hits / len(waypoints)
    return 2 * p * r / (p + r)


def path_levels(finding: dict, answer_key: dict) -> dict:
    """Secondary path metrics (spec section 6).

    edge_validity is None for now: it needs the code graph to check each hop is a real edge.
    fix_traversal is deliberately location-only (spec: a path node's file and line within +/-10 of a
    fix site, i.e. in [line - 10, end_line + 10]), NOT l1_fix_site: a function-name match would credit
    any path through the fix function.

    orion-lm path nodes (a finding whose arm starts with "orion-lm") carry CpgCall.method_full_name,
    the CALLEE's full name (orion/lm/slice.py, shared by the runtime and the training data, so it is
    not changed here), not the enclosing function. For those nodes the path metrics compare file +
    line only: entry_hit = the first node inside an accepted entry point's window (its declaration
    `line`, from eval.pathgt, +/-10; an entry point without a line cannot be hit), and waypoint_f1 is
    computed over (file, line) windows (_lm_waypoint_f1). Plain arms' nodes name the enclosing
    function, so for them entry_hit and waypoint_f1 compare (file, function) via eval.names.
    KRISH CHECK: the two rules make the secondary path metrics less comparable across arms.
    """
    path = finding.get("path") or []
    fixes = answer_key.get("fix_sites") or []
    entries = answer_key.get("accepted_entry_points") or []
    lm_nodes = str(finding.get("arm") or "").startswith("orion-lm")

    fix_traversal = any(_in_window(n, fs) for n in path for fs in fixes)

    entry_hit = False
    if path:
        first = path[0]
        for e in entries:
            if lm_nodes:
                hit = e.get("line") is not None and _in_window(first, _entry_site(e))
            else:
                hit = (_func_match(first.get("function"), function_name(e.get("method_full_name")))
                       and (e.get("file") is None or _same_file(first.get("file"), e.get("file"))))
            if hit:
                entry_hit = True
                break

    waypoint_f1 = None
    if path and lm_nodes:
        waypoint_f1 = _lm_waypoint_f1(path, list(fixes) + [_entry_site(e) for e in entries])
    elif path:
        got = {(_norm_file(n.get("file")), function_name(n.get("function"))) for n in path}
        want = {(_norm_file(fs.get("file")), function_name(fs.get("function"))) for fs in fixes}
        want |= {(_norm_file(e.get("file")), function_name(e.get("method_full_name"))) for e in entries}
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
    # cwe_family is bound as int(bool); the column is declared TEXT, so SQLite's affinity keeps it
    # as "1"/"0" on read. Use read_matches() to get a real bool back.
    conn.executemany(
        "INSERT INTO matches(run_id, vuln_id, finding_idx, level, cwe_family, path_level) "
        "VALUES (?,?,?,?,?,?)",
        [(run_id, r["vuln_id"], r["finding_idx"], r["level"], int(bool(r["cwe_family"])),
          r["path_level"]) for r in rows])
    conn.commit()


def read_matches(conn, run_id) -> list:
    """Rows of `matches` for a run as dicts, with cwe_family as a real bool."""
    cur = conn.execute("SELECT vuln_id, finding_idx, level, cwe_family, path_level "
                       "FROM matches WHERE run_id=? ORDER BY finding_idx, id", (run_id,))
    return [{"vuln_id": v, "finding_idx": fi, "level": lv, "cwe_family": str(c) in ("1", "True"),
             "path_level": pl} for v, fi, lv, c, pl in cur.fetchall()]
