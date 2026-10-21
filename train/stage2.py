"""Stage 2 (plan Task H8): training examples from REAL graphs on a small, size-capped subset.

    select      dataflow pairs in train/dev with a known repo size <= a cap, picked round-robin across
                js/py/java in a seeded order (`train.repo_sizes` supplies the sizes)
    build       per selected pair: D2 `build_pair` (both scans) -> D3 `pair_yield` -> `cases_from_graph`
                -> `trace_for` -> write -> evict both scans. One ledger line per pair; resumable; Ctrl-C
                finishes the current pair, then stops.

Examples (`cases_from_graph`) have the Stage 1 row shape `{pair_id, label, tier, cwe_class, case, lead,
split}` plus `stage: 2`:

    vulnerable  the gold flow (the best-ranked CandidateFlow through a fix site) as a CodeCase from
                `case_from_flow`; the lead is the FIX SITE on the gold path (the first path node that is a
                fix-site call: its file / line / tree-sitter enclosing function) + the primary CWE, the
                same location convention as Stage 1 and the test rule (`eval.match.l1`). The row also
                carries `fix_site` = {file, function, line_start, line_end}: that node's fix hunk as an
                answer key (old-side range; an add-only hunk is its insertion line), which `rounds` scores
                with `eval.match.l1`. A gold path with no fix-site node skips the pair (`no_fix_site_node`;
                never a fallback to the sink)
    patched     the gold flow's counterpart on the PATCHED scan (`fixmap.patched_counterpart`), no lead.
                Omitted when the flow is gone (`flow_gone`), cannot be matched (`flow_unresolved`), has no
                counterpart, or there is no patched scan
    negative    seeded vulnerable-scan flows whose path touches no fix-site call, no lead; drawn only from the
                top `engine.DEFAULT_MAX_FLOWS` flows by rank (the ones the runtime judges)

Traces (`trace_for`) are `{case, actions: [*run_cypher, final], results, meta}`; `meta` carries `pair_id`
and `split` (train/examples.py `export` needs them), plus `fix_site` on the vulnerable trace (train/rounds.py).
They are written only when `train/templates/queries.json` exists (Krish writes it, see
train/templates/README.md); until then only the example rows are produced. Every model input is built later
by orion/lm/format.py from these CodeCases; nothing here builds a message by hand.

Ledger line per pair (null/absent when not measured, never estimated): id, status (ok | no_gold |
no_examples | no_hunks | <build_pair status> | error), reason, yield_reason (pair_yield's reason), the D2
`sides` records (stage timings, node counts, cpg size, RSS), build_total_s, n_examples, n_traces,
traces_dropped, evicted (n_examples = cases written as single-step rows, n_traces = cases written as
traces; a case with a trace is NOT also written as an example row). Example rows are written before the ledger line; `build` first drops rows of
pairs without a ledger line (a crashed pair) and a torn last line.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import signal
import sys
from collections import Counter

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import repo as erepo  # noqa: E402
from orion.lm import cases as _cases  # noqa: E402
from orion.lm import engine as lm_engine  # noqa: E402
from orion.lm import slice as lm_slice  # noqa: E402
from orion.lm import tools  # noqa: E402
from orion.lm.codeindex import RepoIndex  # noqa: E402
from train import build as build_mod  # noqa: E402
from train import fixmap  # noqa: E402
from train.sources import cwe_class  # noqa: E402
from train.stage1 import _append, _done_ids, primary_cwe  # noqa: E402

SPLITS = ("train", "dev")
MAX_FLOWS = 5000                  # candidate flows read per scan to find the gold flow (it can rank low)
PLACEHOLDERS = ("source_uid", "sink_uid")
_PH = re.compile(r"<<(\w+)>>")


# ───────────────────────────── selection ─────────────────────────────

def select(pairs: list[dict], splits: dict[str, str], sizes: dict[str, int | None], *, n: int,
           max_repo_kb: int, seed: int) -> list[dict]:
    """Up to `n` dataflow pairs (train/dev split, a primary CWE, a Joern-supported language, a KNOWN repo
    size <= `max_repo_kb`), round-robin across the languages (sorted) in a seeded order. Each returned
    pair is a copy carrying its `split`."""
    by_lang: dict[str, list[dict]] = {}
    for p in sorted(pairs, key=lambda p: p["id"]):
        size = sizes.get(p.get("repo"))
        if (p.get("cwe_class") == "dataflow" and splits.get(p["id"]) in SPLITS and primary_cwe(p) is not None
                and p.get("language") in build_mod.FRONTEND and size is not None and size <= max_repo_kb):
            by_lang.setdefault(p["language"], []).append({**p, "split": splits[p["id"]]})
    rng = random.Random(seed)
    for lang in sorted(by_lang):
        rng.shuffle(by_lang[lang])
    out: list[dict] = []
    while len(out) < n and any(by_lang.values()):
        for lang in sorted(by_lang):
            if by_lang[lang] and len(out) < n:
                out.append(by_lang[lang].pop())
    return out


# ───────────────────────────── examples ─────────────────────────────

def _example(pair: dict, klass: str, label: str, tier: str, case: dict, lead: dict | None) -> dict:
    return {"pair_id": pair["id"], "label": label, "tier": tier, "cwe_class": klass, "case": case,
            "lead": lead, "stage": 2}


def _find_flow(flows: list[dict], gold: dict) -> dict | None:
    same = [f for f in flows if f["source_uid"] == gold.get("source_uid") and f["sink_uid"] == gold.get("sink_uid")]
    return next((f for f in same if f["rank"] == gold.get("rank")), same[0] if same else None)


def _lead(db, scan_id: str, flow: dict, sites: list[dict], case: dict, cwe: str, idx: RepoIndex,
          tree: str) -> tuple[dict | None, dict | None, str | None]:
    """(lead, fix_site, None) at the fix site on `flow`'s path, else (None, None, reason).

    The node is the first path uid that is a fix-site call (`path_uids` & the sites' `call_uids`, the set D3's
    `_through` reports as `site_uids`); its file and line come from the graph, its function is the tree-sitter
    enclosing span (as in Stage 1). `fix_site` is that node's hunk as an answer key for `eval.match.l1`."""
    by_uid = {u: s for s in sites for u in s.get("call_uids", ())}
    uid = next((u for u in flow.get("path_uids") or [] if u in by_uid), None)
    if uid is None:
        return None, None, "no_fix_site_node"
    nodes = lm_slice.flow_slice(db, scan_id, {"path_uids": [uid]})["nodes"]
    node = nodes[0] if nodes else {}
    f, line = fixmap.norm_path(node.get("file"), tree), node.get("line")
    if f is None or not isinstance(line, int) or isinstance(line, bool):
        return None, None, "no_fix_site_node"
    span = idx.enclosing(f, line)
    if span is None:
        return None, None, "fix_site_unindexed"
    site = by_uid[uid]
    lead = {"flow_id": case["flow_id"], "file": f, "function": span.name, "line": line, "cwe": cwe,
            "confidence": "HIGH"}
    fix_site = {"file": site["file"], "function": span.name, "line_start": site["start"],
                "line_end": max(site["start"], site["end"])}
    return lead, fix_site, None


def _graph_cases(db, yield_rec: dict, pair: dict, vuln_tree: str, patched_tree: str, *,
                 budget: _cases.CaseBudget, n_negatives: int, seed: int,
                 hunks: list[dict] | None = None) -> tuple[list[dict], list[str]]:
    """(examples, reasons something was left out). See `cases_from_graph`."""
    why: list[str] = []
    gold = yield_rec.get("gold_flow")
    if not gold:
        return [], ["no_gold"]
    cwe = primary_cwe(pair)
    klass = pair.get("cwe_class") or cwe_class(pair.get("cwe"))
    if cwe is None or klass == "unknown":
        return [], ["no_cwe"]
    hunks = hunks or []
    vscan, pscan = yield_rec["vulnerable_scan_id"], yield_rec.get("patched_scan_id")
    vidx = RepoIndex(vuln_tree)
    flows = lm_slice.candidate_flows(db, vscan, max_flows=MAX_FLOWS)
    vflow = _find_flow(flows, gold)
    if vflow is None:
        return [], ["gold_not_in_candidates"]
    sites = fixmap.fix_sites(db, vscan, hunks, side="vulnerable") if hunks else []
    vcase = _cases.case_from_flow(lm_slice.flow_slice(db, vscan, vflow), vidx, budget=budget)
    if not vcase["snippets"]:
        return [], ["no_snippet"]
    lead, fix_site, miss = _lead(db, vscan, vflow, sites, vcase, cwe, vidx, vuln_tree)
    if lead is None:
        return [], [miss]
    out = [{**_example(pair, klass, "vulnerable", "graph", vcase, lead), "fix_site": fix_site}]

    guid = gold.get("uid")
    if pscan is None:
        why.append("no_patched_scan")
    elif guid in {f.get("uid") for f in yield_rec.get("flows_gone_on_patched") or []}:
        why.append("flow_gone")
    elif guid in {f.get("uid") for f in yield_rec.get("flows_unresolved") or []}:
        why.append("flow_unresolved")
    else:
        pf = fixmap.patched_counterpart(db, gold, hunks, vulnerable_scan_id=vscan, patched_scan_id=pscan)
        if pf is None:
            why.append("no_counterpart")
        else:
            pcase = _cases.case_from_flow(lm_slice.flow_slice(db, pscan, pf), RepoIndex(patched_tree),
                                          budget=budget)
            if pcase["snippets"]:
                out.append(_example(pair, klass, "patched", "graph", pcase, None))
            else:
                why.append("patched_no_snippet")

    site_uids = {u for s in sites for u in s["call_uids"]}
    pool = [f for f in flows[:lm_engine.DEFAULT_MAX_FLOWS] if not site_uids.intersection(f["path_uids"])
            and (f["source_uid"], f["sink_uid"]) != (vflow["source_uid"], vflow["sink_uid"])]
    random.Random(f"{seed}:{pair['id']}").shuffle(pool)
    got = 0
    for f in pool:
        if got >= max(n_negatives, 0):
            break
        ncase = _cases.case_from_flow(lm_slice.flow_slice(db, vscan, f), vidx, budget=budget)
        if ncase["snippets"]:
            out.append(_example(pair, klass, "negative", "negative", ncase, None))
            got += 1
    return out, why


def cases_from_graph(db, yield_rec: dict, pair: dict, vuln_tree: str, patched_tree: str, *,
                     budget: _cases.CaseBudget, n_negatives: int, seed: int,
                     hunks: list[dict] | None = None) -> list[dict]:
    """vulnerable / patched / negative Stage 2 examples for one pair (see the module doc).

    `yield_rec` is D3's `pair_yield` record (`gold_flow` is a dict {uid, source_uid, sink_uid, sink_category,
    rank}; `vulnerable_scan_id`, `patched_scan_id`, `flows_gone_on_patched`, `flows_unresolved`). `hunks` are
    the fix hunks (D2's record carries them): they locate the fix sites for the lead and the negatives and map
    lines for the patched counterpart; without them there is no fix site, so the pair is skipped."""
    return _graph_cases(db, yield_rec, pair, vuln_tree, patched_tree, budget=budget, n_negatives=n_negatives,
                        seed=seed, hunks=hunks)[0]


# ───────────────────────────── traces ─────────────────────────────

def _fill(template: str, case: dict) -> str:
    def sub(m):
        name = m.group(1)
        if name not in PLACEHOLDERS:
            raise ValueError(f"unknown placeholder <<{name}>> (allowed: {', '.join(PLACEHOLDERS)})")
        val = case.get(name)
        if not isinstance(val, str) or not val:
            raise ValueError(f"template needs <<{name}>> but the case has none")
        return lm_slice._lit(val)   # GraphDB.run_cypher binds only scan_id: other values are inlined

    return _PH.sub(sub, template)


def _filled_queries(case: dict, templates: list[str]) -> list[str]:
    queries = [_fill(t, case) for t in templates]
    for i, q in enumerate(queries):
        problem = tools.check_query(q)
        if problem is not None:
            raise ValueError(f"template {i} fails is_scoped: {problem}")
    return queries


def validate_templates(templates: list[str]) -> None:
    """Raise ValueError unless every template fills and passes `is_scoped` (checked with dummy uids)."""
    _filled_queries({name: "u" for name in PLACEHOLDERS}, templates)


def load_templates(path: str) -> list[str] | None:
    """`train/templates/queries.json` (a JSON list of query strings), validated; None when absent."""
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        templates = json.load(fh)
    if not isinstance(templates, list) or not all(isinstance(t, str) for t in templates):
        raise ValueError(f"{path} must be a JSON list of query strings")
    validate_templates(templates)
    return templates


def trace_for(case: dict, db, scan_id: str, templates: list[str] | None, *, lead: dict | None = None,
              meta: dict | None = None) -> dict | None:
    """A Stage 2 trace: the filled templates run through `tools.run_cypher` on `scan_id`, then a `final`
    action carrying `lead` (none for patched / negative cases). None when there are no templates, or when a
    query errors at run time (a trace is only kept if every step really ran). A template that fails
    `is_scoped` (or needs a uid the case lacks) is a bug and raises ValueError before anything runs."""
    if not templates:
        return None
    queries = _filled_queries(case, templates)
    actions, results = [], []
    for q in queries:
        res = tools.run_cypher(db, scan_id, q)
        if "error" in res:
            return None
        actions.append({"action": "run_cypher", "query": q})
        results.append(res)
    actions.append({"action": "final", "leads": [lead] if lead else []})
    return {"case": case, "actions": actions, "results": results, "meta": dict(meta or {})}


# ───────────────────────────── runner ─────────────────────────────

def _reconcile(out_jsonl: str, ledger: str) -> None:
    """Keep only rows (examples, and traces by `meta.pair_id`) whose pair has a ledger line and that parse."""
    if not os.path.exists(out_jsonl):
        return
    done, keep = _done_ids(ledger), []
    with open(out_jsonl) as fh:
        for line in fh:
            try:
                r = json.loads(line)
                pid = r.get("pair_id") or (r.get("meta") or {}).get("pair_id")
                if pid in done:
                    keep.append(line if line.endswith("\n") else line + "\n")
            except (ValueError, AttributeError):
                continue
    tmp = out_jsonl + ".tmp"
    with open(tmp, "w") as fh:
        fh.writelines(keep)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, out_jsonl)


def build(selected: list[dict], *, mirror_root: str, work_root: str, out_jsonl: str, ledger: str,
          budget: _cases.CaseBudget, n_negatives: int, seed: int, templates: list[str] | None,
          on_event=print, db=None, ensure=build_mod.ensure_mirror, pair_builder=build_mod.build_pair,
          yielder=fixmap.pair_yield, export_tree=erepo.export_tree, builder=None, run=None) -> dict:
    """Stage 2 over `selected` (from `select`, each carrying its `split`). The keyword arguments after
    `on_event` are injection points (tests, a shared GraphDB); `db=None` opens a GraphDB. Not-yet-ledgered
    pairs are processed in order; both scans of a pair are evicted after it, whatever happened."""
    if templates:
        validate_templates(templates)       # a bad template is a bug: fail before building anything
    _reconcile(out_jsonl, ledger)
    done = _done_ids(ledger)
    todo = [p for p in selected if p["id"] not in done]
    totals = {"pairs": len(todo), "done": 0, "interrupted": False, "examples": 0, "traces": 0, "status": Counter()}
    if not todo:
        return totals
    kw = {"run": run} if run is not None else {}
    own_db = db is None
    if own_db:
        from orion.graphdb import GraphDB
        db = GraphDB()
    stop = {"flag": False}

    def on_sigint(_sig, _frame):
        stop["flag"] = True
        on_event("interrupt: finishing the current pair, then stopping")
        signal.signal(signal.SIGINT, signal.default_int_handler)   # a second Ctrl-C aborts

    try:
        old = signal.signal(signal.SIGINT, on_sigint)
    except ValueError:      # not the main thread
        old = None
    try:
        for i, pair in enumerate(todo, 1):
            if stop["flag"]:
                totals["interrupted"] = True
                break
            on_event(f"[{i}/{len(todo)}] {pair['id']}")
            rows, row = _one_pair(pair, db, mirror_root, work_root, budget=budget, n_negatives=n_negatives,
                                  seed=seed, templates=templates, ensure=ensure, pair_builder=pair_builder,
                                  yielder=yielder, export_tree=export_tree, builder=builder, kw=kw,
                                  out_jsonl=out_jsonl)
            _append(ledger, [row])
            totals["done"] += 1
            totals["examples"] += row["n_examples"]
            totals["traces"] += row["n_traces"]
            totals["status"][row["status"]] += 1
            on_event(f"    -> {row['status']}" + (f" ({row['reason']})" if row["reason"] else "")
                     + f", {row['n_examples']} examples, {row['n_traces']} traces")
    finally:
        if old is not None:
            signal.signal(signal.SIGINT, old)
        if own_db:
            db.close()
    return totals


_SIDE_KEYS = ("status", "reason", "scan_id", "timings", "n_nodes", "n_edges", "neo4j_nodes", "cpg_bin_bytes",
              "peak_rss_python_mb", "peak_rss_children_mb", "maxrss_python_mb_hwm", "maxrss_children_mb_hwm")


def _one_pair(pair, db, mirror_root, work_root, *, budget, n_negatives, seed, templates, ensure, pair_builder,
              yielder, export_tree, builder, kw, out_jsonl) -> tuple[list[dict], dict]:
    row = {"id": pair["id"], "status": None, "reason": None, "yield_reason": None, "build_status": None,
           "build_total_s": None, "sides": None, "n_examples": 0, "n_traces": 0, "traces_dropped": 0,
           "evicted": None}
    scan_ids = [f"{pair['id']}:{s}" for s in build_mod.SIDES]
    trees = os.path.join(work_root, "stage2_trees", build_mod._safe(pair["id"]))
    try:
        mirror = ensure(pair, mirror_root, **kw)
        rec = pair_builder(pair, mirror, work_root, builder=builder, db=db, **kw)
        row.update(build_status=rec["status"], build_total_s=rec.get("total_s"),
                   sides={s: {k: v.get(k) for k in _SIDE_KEYS} for s, v in (rec.get("sides") or {}).items()})
        scan_ids = list(dict.fromkeys(scan_ids + [rec.get(f"{s}_scan_id") for s in build_mod.SIDES
                                                  if rec.get(f"{s}_scan_id")]))
        if rec["status"] != "ok":
            row.update(status=rec["status"], reason=rec.get("reason"))
            return [], row
        hunks = rec.get("hunks")
        if hunks is None:
            row.update(status="no_hunks", reason=rec.get("hunks_error"))
            return [], row
        y = yielder(db, pair["id"], hunks, vulnerable_scan_id=rec["vulnerable_scan_id"],
                    patched_scan_id=rec["patched_scan_id"])
        row["yield_reason"] = y.get("reason")
        if not y.get("gold_flow"):
            row.update(status="no_gold", reason=y.get("reason"))
            return [], row
        vt, pt = os.path.join(trees, "vulnerable"), os.path.join(trees, "patched")
        export_tree(mirror, rec["vulnerable_sha"], vt, **kw)
        export_tree(mirror, rec["patched_sha"], pt, **kw)
        examples, why = _graph_cases(db, y, pair, vt, pt, budget=budget, n_negatives=n_negatives, seed=seed,
                                     hunks=hunks)
        if not examples:
            row.update(status="no_examples", reason=",".join(why) or None)
            return [], row
        rows, n_single = [], 0
        for e in examples:
            e["split"] = pair["split"]
            tr = trace_for(e["case"], db, y["patched_scan_id"] if e["label"] == "patched" else y["vulnerable_scan_id"],
                           templates, lead=e["lead"],
                           meta={"pair_id": pair["id"], "split": pair["split"], "label": e["label"],
                                 "tier": e["tier"], **({"fix_site": e["fix_site"]} if e.get("fix_site") else {})})
            if tr is not None:      # the trace REPLACES the single-step row: same prompt, different target
                rows.append(tr)
            else:
                rows.append(e)
                n_single += 1
                if templates:
                    row["traces_dropped"] += 1
        row.update(status="ok", reason=",".join(why) or None, n_examples=n_single,
                   n_traces=len(rows) - n_single)
        _append(out_jsonl, rows)       # before the ledger line, so a crash redoes the pair (see _reconcile)
        return rows, row
    except Exception as exc:  # noqa: BLE001 -- one bad pair must not stop a long run
        row.update(status="error", reason=f"{type(exc).__name__}: {exc}"[:1500], n_examples=0, n_traces=0)
        return [], row
    finally:
        shutil.rmtree(trees, ignore_errors=True)
        try:
            os.rmdir(os.path.dirname(trees))
        except OSError:
            pass
        ev = build_mod.evict(scan_ids, db)
        row["evicted"] = all(v == "evicted" for v in ev.values())
        if not row["evicted"]:
            row["evict_errors"] = {k: v for k, v in ev.items() if v != "evicted"}
