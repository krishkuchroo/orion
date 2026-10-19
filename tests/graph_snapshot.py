"""A scan_id-free snapshot of the two things discovery reads first: FLOWS_TO and CandidateFlow.

Rows name calls by (file_path, line, code), never by uid, so two builds of the same repo under
different scan_ids (or hash seeds, or a build vs a reanalyze) compare row for row:

  flows_to:        [src_file, src_line, src_code, dst_file, dst_line, dst_code, arg_index]
  candidate_flows: ["sink_file:line", sink_category, rank, ["file:line:code", ... along the path]]

Both are multisets (two calls can share file/line/code). `diff` lists rows added and missing;
`format_diff` renders that for an assertion message. Test helper only -- not product code.
"""
from __future__ import annotations

import json
from collections import Counter


def _calls(nodes) -> dict[str, dict]:
    """CpgCall uid -> props, unioned across duplicate rows exactly as persist does."""
    out: dict[str, dict] = {}
    for label, props in nodes:
        if label == "CpgCall" and props.get("uid") is not None:
            out[props["uid"]] = {**out.get(props["uid"], {}), **props}
    return out


def _where(calls: dict[str, dict], uid: str) -> list:
    c = calls.get(uid, {})
    return [c.get("file_path"), c.get("line"), c.get("code")]


def _candidate_row(calls: dict[str, dict], sink_uid: str, category: str, rank: int,
                   path_uids: str) -> list:
    sink = _where(calls, sink_uid)
    path = [f"{f}:{ln}:{code}" for f, ln, code in (_where(calls, u) for u in json.loads(path_uids))]
    return [f"{sink[0]}:{sink[1]}", category, rank, path]


def _sorted(rows: list) -> list:
    return sorted(rows, key=lambda r: json.dumps(r))


def from_batch(batch) -> dict:
    """Snapshot of an in-memory `schema.Batch` (after pathfind)."""
    calls = _calls(batch.nodes)
    flows = [_where(calls, fk["uid"]) + _where(calls, tk["uid"]) + [props.get("arg_index")]
             for rtype, _fl, fk, _tl, tk, props in batch.edges if rtype == "FLOWS_TO"]
    cands = [_candidate_row(calls, p["sink_uid"], p["sink_category"], p["rank"], p["path_uids"])
             for label, p in batch.nodes if label == "CandidateFlow"]
    return {"flows_to": _sorted(flows), "candidate_flows": _sorted(cands)}


def from_neo4j(session, scan_id: str) -> dict:
    """Snapshot of a persisted scan partition (read-only queries, scan_id on every node)."""
    calls = {r["uid"]: {"file_path": r["f"], "line": r["l"], "code": r["c"]} for r in session.run(
        "MATCH (c:CpgCall {scan_id:$sid}) RETURN c.uid AS uid, c.file_path AS f, c.line AS l, "
        "c.code AS c", sid=scan_id)}
    flows = [[r["af"], r["al"], r["ac"], r["bf"], r["bl"], r["bc"], r["ai"]] for r in session.run(
        "MATCH (a:CpgCall {scan_id:$sid})-[r:FLOWS_TO {scan_id:$sid}]->(b:CpgCall {scan_id:$sid}) "
        "RETURN a.file_path AS af, a.line AS al, a.code AS ac, b.file_path AS bf, b.line AS bl, "
        "b.code AS bc, r.arg_index AS ai", sid=scan_id)]
    cands = [_candidate_row(calls, r["s"], r["k"], r["r"], r["p"]) for r in session.run(
        "MATCH (f:CandidateFlow {scan_id:$sid}) RETURN f.sink_uid AS s, f.sink_category AS k, "
        "f.rank AS r, f.path_uids AS p", sid=scan_id)]
    return {"flows_to": _sorted(flows), "candidate_flows": _sorted(cands)}


def diff(expected: dict, actual: dict) -> dict:
    """{kind: {"added": rows in actual only, "missing": rows in expected only}}, multiset-aware;
    kinds with no difference are omitted (so an empty dict means identical)."""
    out = {}
    for kind in sorted(set(expected) | set(actual)):
        want = Counter(json.dumps(r) for r in expected.get(kind, []))
        got = Counter(json.dumps(r) for r in actual.get(kind, []))
        added = [json.loads(r) for r in (got - want).elements()]
        missing = [json.loads(r) for r in (want - got).elements()]
        if added or missing:
            out[kind] = {"added": _sorted(added), "missing": _sorted(missing)}
    return out


def format_diff(d: dict, limit: int = 10) -> str:
    lines = []
    for kind, ch in d.items():
        for what in ("added", "missing"):
            rows = ch[what]
            lines.append(f"{kind} {what}: {len(rows)}")
            lines += [f"  {json.dumps(r)}" for r in rows[:limit]]
            if len(rows) > limit:
                lines.append(f"  ... {len(rows) - limit} more")
    return "\n".join(lines) or "identical"
