"""Fix diff -> graph nodes -> gold flow -> per-pair yield (plan Task D3).

* ``fix_hunks``: the fix hunks, from the LOCAL mirror (``git diff -U0 <vulnerable> <patched>`` via
  ``train.diffs``; never the GitHub API). For a linear multi-commit fix the range can also contain
  unrelated commits, so only files touched by a fix commit are kept.
* ``fix_sites(db, scan_id, hunks, *, side)``: each non-test hunk -> the CpgCalls on its lines (old
  lines on the vulnerable side, new lines on the patched side) + the enclosing method
  (``MethodResolver``: greatest declaration line <= L). A hunk whose range is EMPTY on this side
  (add-only on the vulnerable side, delete-only on the patched side) uses the enclosing method of the
  insertion point and that method's calls within +-``window`` lines (``windowed: true``).
* ``gold_flow(db, scan_id, sites) -> (flow | None, reason | None)``: the best-ranked CandidateFlow
  (rank 0 = best) whose parsed ``path_uids`` contains a fix-site call uid, else None with reason
  ``no_site_nodes`` | ``no_flow_through_site`` (or ``query_error: ...``). Never raises.
* ``pair_yield``: the per-pair yield record, including ``flows_gone_on_patched``.

Uids are treated as opaque strings (no format parsing: CpgParameter uids are changing upstream). They
also hash the scan_id, so a vulnerable-scan uid NEVER equals a patched-scan uid. "Same source->sink on
the patched scan" is therefore decided by node identity: (file, line mapped through the diff, call
name) for the source and the sink. A pure rename with no content change produces no hunk, so flows in
such a file are compared under the old path (and can show as gone) -- a known, rare limitation.

Paths: Orion stores ``CpgCall/CpgMethod.file_path`` repo-relative with no leading ``./`` (checked
read-only on 38 existing scans, ~600k js/ts/py/java calls: 0 absolute, 0 ``./``). ``norm_path`` is the
one helper that maps both graph and diff paths to that form anyway (strips ``./`` and the tree root).

Run (READ-only on Neo4j)::

    ./.venv/bin/python -I train/fixmap.py yield --ledger train/data/builds.jsonl --out train/data/yield.jsonl
"""
from __future__ import annotations

import bisect
import json
import os
import re
import subprocess
import sys
from collections import Counter

if __package__ in (None, ""):  # run as a script under `python -I`: put the repo root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.dataset.enrich import _is_test  # noqa: E402  -- same test-file rule as D1 / the eval
from orion.runtime.correlate import MethodResolver  # noqa: E402
from train.diffs import git_diff_u0, parse_u0  # noqa: E402

_ALL = 10_000_000   # row limit for whole-scan reads; a truncated read is an error, never silent

_Q_CALLS = ("MATCH (c:CpgCall {scan_id:$scan_id}) WHERE c.line > 0 "
            "RETURN c.uid AS uid, c.file_path AS f, c.line AS l, c.name AS name")
# Same filter as orion.runtime.enrich._methods, but errors are raised instead of read as "no methods".
_Q_METHODS = ("MATCH (m:CpgMethod {scan_id:$scan_id}) "
              "WHERE m.is_external = false AND m.file_path IS NOT NULL AND m.line IS NOT NULL "
              "RETURN m.full_name AS fn, m.file_path AS f, m.line AS l")
_Q_FLOWS = ("MATCH (f:CandidateFlow {scan_id:$scan_id}) "
            "RETURN f.uid AS uid, f.source_uid AS source_uid, f.sink_uid AS sink_uid, "
            "f.sink_category AS sink_category, f.path_uids AS path_uids, f.rank AS rank")


class GraphReadError(RuntimeError):
    """A graph read failed or was truncated."""


def norm_path(path, root: str | None = None) -> str | None:
    """THE path normaliser for graph and diff paths: strip the tree root (as given and resolved, e.g.
    /var vs /private/var) and any leading './', collapse '//'. None/'' -> None."""
    if not path:
        return None
    p = str(path)
    if root:
        roots = {root.rstrip("/"), os.path.realpath(root).rstrip("/")}
        cands = [p, os.path.realpath(p)] if os.path.isabs(p) else [p]
        for c in cands:
            hit = next((r for r in roots if r and c.startswith(r + "/")), None)
            if hit:
                p = c[len(hit) + 1:]
                break
    while p.startswith("./"):
        p = p[2:]
    p = re.sub(r"/{2,}", "/", p)
    return p or None


def _rows(db, scan_id: str, query: str) -> list[dict]:
    res = db.run_cypher(scan_id, query, limit=_ALL)
    if "error" in res:
        raise GraphReadError(res["error"])
    rows = res.get("rows") or []
    if res.get("row_count", len(rows)) > len(rows) or res.get("truncated"):
        raise GraphReadError(f"read truncated at {len(rows)} rows")
    return rows


class _ScanIndex:
    """One scan's calls (by normalised file, sorted by line; and by uid) + a MethodResolver."""

    def __init__(self, db, scan_id: str, root: str | None = None) -> None:
        self.by_file: dict[str, list[tuple[int, str, str | None]]] = {}
        self.by_uid: dict[str, tuple[str, int, str | None]] = {}
        for r in _rows(db, scan_id, _Q_CALLS):
            f, line = norm_path(r.get("f"), root), r.get("l")
            if f is None or not isinstance(line, int) or r.get("uid") is None:
                continue
            self.by_file.setdefault(f, []).append((line, r["uid"], r.get("name")))
            self.by_uid[r["uid"]] = (f, line, r.get("name"))
        for v in self.by_file.values():
            v.sort(key=lambda t: (t[0], t[1]))
        self._lines = {f: [t[0] for t in v] for f, v in self.by_file.items()}
        self.resolver = MethodResolver((r["fn"], norm_path(r.get("f"), root), r.get("l"))
                                       for r in _rows(db, scan_id, _Q_METHODS))

    def calls_in(self, f: str, lo: int, hi: int) -> list[tuple[int, str, str | None]]:
        rows = self.by_file.get(f, [])
        lines = self._lines.get(f, [])
        return rows[bisect.bisect_left(lines, lo):bisect.bisect_right(lines, hi)]

    def method(self, f: str, line: int) -> str | None:
        return self.resolver.resolve(f, line) if line > 0 else None


def _side_range(h: dict, side: str) -> tuple[str | None, int, int]:
    if side == "vulnerable":
        f = h["old_file"] if "old_file" in h else h.get("file")
        return f, h["old_start"], h["old_end"]
    if side == "patched":
        return h.get("file"), h["new_start"], h["new_end"]
    raise ValueError(f"side must be 'vulnerable' or 'patched', not {side!r}")


def _empty(h: dict, a: str, b: str) -> bool:
    return a in h and b in h and h[b] < h[a]


def _fix_sites(idx: _ScanIndex, hunks: list[dict], side: str, root: str | None, window: int) -> list[dict]:
    sites = []
    for h in hunks:
        f, start, end = _side_range(h, side)
        f = norm_path(f, root)
        if f is None or _is_test(f):
            continue
        if end < start:   # nothing on this side: the point the other side's lines attach to
            method = idx.method(f, start)
            calls = [c for c in idx.calls_in(f, start - window, start + window) if idx.method(f, c[0]) == method]
            methods, windowed = ([method] if method else []), True
        else:
            calls = idx.calls_in(f, start, end)
            methods = list(dict.fromkeys(m for m in (idx.method(f, ln) for ln in range(start, end + 1)) if m))
            method = idx.method(f, start) or (methods[0] if methods else None)
            windowed = False
        sites.append({"file": f, "side": side, "start": start, "end": end, "line": start,
                      "method_full_name": method, "methods": methods,
                      "call_uids": sorted({uid for _, uid, _ in calls}),
                      "add_only": _empty(h, "old_start", "old_end"),
                      "delete_only": _empty(h, "new_start", "new_end"), "windowed": windowed})
    return sites


def fix_sites(db, scan_id: str, hunks: list[dict], *, side: str, root: str | None = None,
              window: int = 3) -> list[dict]:
    """Map each non-test hunk to graph nodes on `scan_id` (see module doc). Returns
    [{file, side, start, end, line, method_full_name, methods, call_uids, add_only, delete_only,
    windowed}]. Raises GraphReadError if the graph cannot be read."""
    return _fix_sites(_ScanIndex(db, scan_id, root), hunks, side, root, window)


def _flows(db, scan_id: str) -> list[dict]:
    out = []
    for r in _rows(db, scan_id, _Q_FLOWS):
        path = r.get("path_uids")
        if isinstance(path, str):
            try:
                path = json.loads(path)
            except ValueError:
                continue
        if not isinstance(path, list):
            continue
        out.append({"uid": r.get("uid"), "source_uid": r.get("source_uid"), "sink_uid": r.get("sink_uid"),
                    "sink_category": r.get("sink_category"), "rank": r.get("rank"), "path_uids": path})
    return out


def _through(flows: list[dict], uids: set[str]) -> list[dict]:
    hits = [{**f, "site_uids": sorted(uids.intersection(f["path_uids"]))} for f in flows
            if uids.intersection(f["path_uids"])]
    hits.sort(key=lambda f: (f["rank"] is None, f["rank"] if isinstance(f["rank"], (int, float)) else 0,
                             str(f["uid"])))
    return hits


def _site_uids(sites: list[dict]) -> set[str]:
    return {u for s in sites for u in s.get("call_uids", ())}


def gold_flow(db, scan_id: str, sites: list[dict]) -> tuple[dict | None, str | None]:
    """(best-ranked CandidateFlow through a fix-site call, None) or (None, reason). Never raises."""
    uids = _site_uids(sites)
    if not uids:
        return None, "no_site_nodes"
    try:
        hits = _through(_flows(db, scan_id), uids)
    except Exception as e:  # noqa: BLE001 -- a yield run must never die on one pair
        return None, f"query_error: {e}"
    return (hits[0], None) if hits else (None, "no_flow_through_site")


def map_line(hunks: list[dict], file: str, line: int, *, root: str | None = None) -> tuple[str | None, list[int]]:
    """Where old `file`:`line` lands on the patched side: (new path, [lines]). An unchanged line shifts
    by the hunks above it; a line inside a changed range maps to that hunk's whole new range (empty if
    it was deleted); a deleted file maps to (None, [])."""
    hs = sorted((h for h in hunks if norm_path(h.get("old_file", h.get("file")), root) == file),
                key=lambda h: h["old_start"])
    if not hs:
        return file, [line]
    new = norm_path(hs[0].get("file"), root)
    if new is None:
        return None, []
    delta = 0
    for h in hs:
        a, b = h["old_start"], h["old_end"] - h["old_start"] + 1
        c, d = h["new_start"], h["new_end"] - h["new_start"] + 1
        if b > 0:
            if line < a:
                return new, [line + delta]
            if line < a + b:
                return new, list(range(c, c + d))
        elif line <= a:
            return new, [line + delta]
        delta += d - b
    return new, [line + delta]


def _compact(f: dict) -> dict:
    return {k: f.get(k) for k in ("uid", "source_uid", "sink_uid", "sink_category", "rank")}


def pair_yield(db, pair_id: str, hunks: list[dict], *, vulnerable_scan_id: str,
               patched_scan_id: str | None, root: str | None = None, window: int = 3) -> dict:
    """The per-pair yield record:
    {id, vulnerable_scan_id, patched_scan_id, n_sites, n_site_calls, n_site_flows, gold_flow, reason,
     flows_gone_on_patched, flows_unresolved}.

    Gold flows = every vulnerable CandidateFlow through a fix-site call (gold_flow = the best-ranked).
    flows_gone_on_patched = the gold flows whose (source, sink) has no CandidateFlow on the patched
    scan, matching nodes by (file, diff-mapped line, call name); a gold flow whose source or sink is not
    a CpgCall cannot be matched and goes to flows_unresolved instead. Never raises."""
    rec = {"id": pair_id, "vulnerable_scan_id": vulnerable_scan_id, "patched_scan_id": patched_scan_id,
           "n_sites": None, "n_site_calls": None, "n_site_flows": None, "gold_flow": None, "reason": None,
           "flows_gone_on_patched": None, "flows_unresolved": None}
    try:
        vidx = _ScanIndex(db, vulnerable_scan_id, root)
        sites = _fix_sites(vidx, hunks, "vulnerable", root, window)
        uids = _site_uids(sites)
        rec.update(n_sites=len(sites), n_site_calls=len(uids))
        if not uids:
            rec["reason"] = "no_site_nodes"
            return rec
        hits = _through(_flows(db, vulnerable_scan_id), uids)
        rec["n_site_flows"] = len(hits)
        if not hits:
            rec.update(reason="no_flow_through_site", flows_gone_on_patched=[], flows_unresolved=[])
            return rec
        rec["gold_flow"] = hits[0]
        if patched_scan_id is None:
            return rec
        pidx = _ScanIndex(db, patched_scan_id, root)
        on_patched = set()
        for pf in _flows(db, patched_scan_id):
            s, k = pidx.by_uid.get(pf["source_uid"]), pidx.by_uid.get(pf["sink_uid"])
            if s and k:
                on_patched.add((s, k))
        gone, unresolved = [], []
        for v in hits:
            s, k = vidx.by_uid.get(v["source_uid"]), vidx.by_uid.get(v["sink_uid"])
            if s is None or k is None:
                unresolved.append(_compact(v))
                continue
            (sf, sl), (kf, kl) = map_line(hunks, s[0], s[1], root=root), map_line(hunks, k[0], k[1], root=root)
            if not any(((sf, a, s[2]), (kf, b, k[2])) in on_patched for a in sl for b in kl):
                gone.append(_compact(v))
        rec.update(flows_gone_on_patched=gone, flows_unresolved=unresolved)
    except Exception as e:  # noqa: BLE001 -- recorded, never fatal
        rec["reason"] = f"query_error: {e}"
    return rec


def fix_hunks(mirror_dir: str, vulnerable: str, patched: str, *, fix_shas=None, run=None) -> list[dict]:
    """Hunks of vulnerable..patched from the local mirror. With more than one fix commit, hunks in files
    that no fix commit touched (unrelated commits inside a linear range) are dropped."""
    hs = parse_u0(git_diff_u0(mirror_dir, vulnerable, patched, run=run))
    if fix_shas and len(fix_shas) > 1:
        touched = set()
        for s in fix_shas:
            for h in parse_u0(git_diff_u0(mirror_dir, f"{s}^", s, run=run)):
                touched.update(x for x in (h["file"], h["old_file"]) if x)
        hs = [h for h in hs if h["file"] in touched or h["old_file"] in touched]
    return hs


def yield_all(builds: list[dict], db, *, out: str, on_event=print, run=None) -> Counter:
    """pair_yield for every ledger record with status ok that is not yet in `out` (resumable); one JSON
    line per pair. Uses the hunks stored with the build, else diffs the mirror. Returns a Counter of
    reasons ('gold' when a gold flow was found)."""
    done = set()
    if os.path.exists(out):
        with open(out) as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["id"])
                except (ValueError, KeyError, TypeError):
                    continue
    tally: Counter = Counter()
    todo = [b for b in builds if b.get("status") == "ok" and b["id"] not in done]
    for i, b in enumerate(todo, 1):
        try:
            hunks = b.get("hunks")
            if hunks is None:   # older ledger line: diff in the mirror
                hunks = fix_hunks(b["mirror"], b["vulnerable_sha"], b["patched_sha"],
                                  fix_shas=None if b.get("multi_commit_nonlinear") else b.get("fix_shas"), run=run)
        except (subprocess.CalledProcessError, OSError, KeyError) as e:
            rec = {"id": b["id"], "reason": f"diff_failed: {e}"}
        else:
            rec = pair_yield(db, b["id"], hunks, vulnerable_scan_id=b["vulnerable_scan_id"],
                             patched_scan_id=b.get("patched_scan_id"))
            rec["n_hunks"] = len(hunks)
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        key = "gold" if rec.get("gold_flow") else str(rec.get("reason"))
        tally[key] += 1
        on_event(f"[{i}/{len(todo)}] {b['id']} {key}")
    return tally


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Orion-LM fix-site -> gold-flow yield (read-only on Neo4j)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    y = sub.add_parser("yield")
    y.add_argument("--ledger", default="train/data/builds.jsonl")
    y.add_argument("--out", default="train/data/yield.jsonl")
    a = ap.parse_args(argv)

    from orion.graphdb import GraphDB
    from train.build import read_ledger
    latest = {r["id"]: r for r in read_ledger(a.ledger)}
    db = GraphDB()
    try:
        tally = yield_all(list(latest.values()), db, out=a.out)
    finally:
        db.close()
    print(json.dumps(dict(tally)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
