"""Scan partitions in Neo4j: which labels a scan owns, deleting / counting them in batches, and the
per-scan record that says whether a partition is complete and how it was built.

Every Orion node carries `scan_id`, but a label-less `MATCH (n {scan_id:$sid})` can't use an index:
it plans as an AllNodesScan over every scan in the database (~1.2M nodes on the dev box) and the
old deletes ran it as ONE transaction. Here every lookup names its label, is served by a
single-property scan_id RANGE index (the composite NODE_KEY indexes lead with scan_id but Neo4j 5
does not use them for a scan_id-only predicate), and deletes go in LIMIT-sized batches, one
transaction each, until a batch comes back empty.

Which labels each caller deletes is deliberate:
  - persist._clear: NODE_KEY labels only. It spares the semantic-index :Chunk nodes (embed writes
    them concurrently with persist) and the scan's record.
  - GraphDB.clear_scan / gc: SCAN_LABELS, everything the scan owns.

The record is one `(:OrionScan {scan_id, commit, profile, orion_version, status, built_at, counts})`
node per scan. `graph_build.build` writes status "building" before persist clears the partition
and "complete" after persist returns, so a crashed build stays "building" and `--scan-id` refuses
it. `counts` is a JSON string (Neo4j properties can't hold maps). OrionScan is NOT a NODE_KEY label
(persist never writes or clears it) and GraphDB.schema() hides it, so get_schema is unchanged.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from neo4j import GraphDatabase

from .. import config
from .schema import NODE_KEY

# Every label a node carrying a scan_id can have. NODE_KEY = the static graph (persist); Chunk = the
# semantic index (embed.py); OrionScan = the scan record. A new label carrying scan_id must be added
# here or a scan delete misses it (tests/test_scan_delete.py checks the live database).
SCAN_LABELS: tuple[str, ...] = (*NODE_KEY, "Chunk", "OrionScan")

DELETE_BATCH_SIZE = 10000

# `{label}` is filled per label (str.format); `{{ }}` are literal Cypher braces.
DELETE_BATCH = ("MATCH (n:`{label}` {{scan_id:$sid}}) WITH n LIMIT $batch "
                "DETACH DELETE n RETURN count(*) AS n")
COUNT = "MATCH (n:`{label}` {{scan_id:$sid}}) RETURN count(n) AS n"


def _index_name(label: str) -> str:
    return f"orion_scanid_{label}"


def ensure_scan_indexes(session) -> None:
    """Idempotently create a scan_id RANGE index per SCAN_LABELS label and wait until each is
    ONLINE (by name, like persist's NODE_KEY indexes, so an unrelated index build never blocks us).
    DDL auto-commits, so this runs on the session before any write transaction."""
    for label in SCAN_LABELS:
        session.run(f"CREATE RANGE INDEX `{_index_name(label)}` IF NOT EXISTS "
                    f"FOR (n:`{label}`) ON (n.scan_id)").consume()
    for label in SCAN_LABELS:
        session.run("CALL db.awaitIndex($name, 300)", name=_index_name(label)).consume()


def delete_scan(driver, scan_id: str, labels, batch: int = DELETE_BATCH_SIZE) -> dict[str, int]:
    """DETACH DELETE every node of `scan_id` under each of `labels`, `batch` nodes per transaction,
    until none is left. Returns {label: nodes deleted} for every label asked for."""
    deleted: dict[str, int] = {}
    with driver.session(database=config.NEO4J_DATABASE) as s:
        ensure_scan_indexes(s)
        for label in labels:
            cypher = DELETE_BATCH.format(label=label)
            total = 0
            while True:
                n = s.execute_write(
                    lambda tx: tx.run(cypher, sid=scan_id, batch=batch).single()["n"])
                total += n
                if n == 0:
                    break
            deleted[label] = total
    return deleted


def count_scan(session, scan_id: str, labels) -> dict[str, int]:
    """{label: nodes of `scan_id`} for each of `labels` (read-only)."""
    return {label: session.run(COUNT.format(label=label), sid=scan_id).single()["n"]
            for label in labels}


# ─────────────────────────────── the scan record ───────────────────────────────
RECORD = "OrionScan"
BUILDING = "building"
COMPLETE = "complete"


@contextmanager
def _session():
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            yield s
    finally:
        driver.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def mark_building(scan_id: str, *, commit: str, profile: str) -> None:
    """Create or reset the record to status 'building' (call BEFORE the partition is cleared)."""
    from .. import __version__
    with _session() as s:
        s.run(f"MERGE (r:{RECORD} {{scan_id:$sid}}) "
              "SET r.commit = $commit, r.profile = $profile, r.orion_version = $version, "
              "r.status = $status, r.built_at = $now, r.counts = null",
              sid=scan_id, commit=commit, profile=profile, version=__version__,
              status=BUILDING, now=_now()).consume()


def mark_complete(scan_id: str, counts: dict, **extra) -> None:
    """Set status 'complete' and store `counts` (as JSON) plus any `extra` scalar properties."""
    with _session() as s:
        rec = s.run(f"MATCH (r:{RECORD} {{scan_id:$sid}}) SET r.status = $status, r.counts = $counts, "
                    "r += $extra RETURN count(r) AS n",
                    sid=scan_id, status=COMPLETE, counts=json.dumps(counts, sort_keys=True),
                    extra=extra).single()
    if not rec["n"]:
        raise RuntimeError(f"no {RECORD} record for {scan_id}: mark_building was never called")


def set_status(scan_id: str, status: str) -> None:
    with _session() as s:
        s.run(f"MATCH (r:{RECORD} {{scan_id:$sid}}) SET r.status = $status",
              sid=scan_id, status=status).consume()


def get_record(scan_id: str) -> dict | None:
    """The record as a dict (`counts` parsed back from JSON), or None if the scan has none."""
    with _session() as s:
        rec = s.run(f"MATCH (r:{RECORD} {{scan_id:$sid}}) RETURN properties(r) AS p", sid=scan_id).single()
    if rec is None:
        return None
    p = dict(rec["p"])
    if p.get("counts"):
        p["counts"] = json.loads(p["counts"])
    return p


def _records(session) -> list[dict]:
    return [dict(r["p"]) for r in session.run(f"MATCH (r:{RECORD}) RETURN properties(r) AS p")]


def _unrecorded_ids(session, recorded: set[str]) -> set[str]:
    """scan_ids that own nodes but have no record (scans built before records existed)."""
    found: set[str] = set()
    for label in SCAN_LABELS:
        if label == RECORD:
            continue
        found.update(r["sid"] for r in session.run(
            f"MATCH (n:`{label}`) WHERE n.scan_id IS NOT NULL RETURN DISTINCT n.scan_id AS sid"))
    return found - recorded


# ─────────────────────────────── the --scan-id gate ───────────────────────────────
def expected_profile(engine: str, repo: str | None) -> str | None:
    """The profile name a scan must have been built with to be used by `engine` on `repo`; None when
    no repo is known on the claude path (then any profile without the lm sinks is accepted)."""
    from . import profiles
    if repo is None:
        return None
    base = profiles.select_profile(repo)
    return profiles.with_lm_sinks(base).name if engine == "lm" else base.name


def _rebuild_hint(engine: str, repo: str | None) -> str:
    cmd = f"orion scan {repo or '<repo>'}"
    if engine == "lm":
        cmd += " --engine lm --model <path>"
    return f"rebuild it with: {cmd}"


def check_usable(scan_id: str, *, engine: str, repo: str | None) -> str | None:
    """Why `scan_id` must not be used for `engine` (an error message), or None if it may.

    Refuses -- fails closed -- when there is no record (a scan built before records existed, or not
    by Orion), when its status is not 'complete' (a build crashed mid-persist: the partition may be
    half-loaded), or when it was built with another profile than `engine` needs (the lm sinks change
    the CandidateFlows). Also refuses when Neo4j can't be asked."""
    hint = _rebuild_hint(engine, repo)
    try:
        rec = get_record(scan_id)
    except Exception as exc:  # noqa: BLE001 -- can't check -> don't use it
        return f"cannot read the scan record for {scan_id}: {exc}"
    if rec is None:
        return f"scan {scan_id} has no {RECORD} record (built before scan records existed); {hint}"
    if rec.get("status") != COMPLETE:
        return (f"scan {scan_id} is incomplete (status {rec.get('status')!r} since "
                f"{rec.get('built_at')}): its build did not finish; {hint}")
    want, got = expected_profile(engine, repo), rec.get("profile") or ""
    if want is not None and got != want:
        return f"scan {scan_id} was built with profile {got!r}, but --engine {engine} needs {want!r}; {hint}"
    if want is None and got.endswith("+lm"):
        return (f"scan {scan_id} was built with profile {got!r} (lm sinks), which the claude engine "
                f"does not use; {hint}")
    return None


# ─────────────────────────────── gc ───────────────────────────────
UNRECORDED_PLAN = Path(".orion") / "gc_unrecorded_plan.json"


class GcRefused(RuntimeError):
    """gc was asked to do something it only does after a dry run (or with a sane --keep)."""


def gc(*, keep: int, prefix: str = "", dry_run: bool = False, include_unrecorded: bool = False,
       plan_path: Path = UNRECORDED_PLAN) -> dict:
    """Delete old scan partitions; returns {"deleted": [...], "kept": [...], "unrecorded": [...]}.

    Recorded scans whose id starts with `prefix` are sorted newest `built_at` first; the first
    `keep` are kept and the rest deleted (every SCAN_LABELS label, record included), whatever their
    status. A build in progress is the newest, so `keep >= 1` never deletes it.

    Scans with no record are only listed -- unless `include_unrecorded`: then a dry run saves the
    listed ids to `plan_path`, and a real run deletes only ids from that saved listing that still
    have no record (then removes the file). A real run with no saved listing is refused."""
    if keep < 1:
        raise GcRefused("--keep must be at least 1")
    driver = GraphDatabase.driver(config.NEO4J_URI, auth=config.NEO4J_AUTH)
    try:
        with driver.session(database=config.NEO4J_DATABASE) as s:
            records = [r for r in _records(s) if r["scan_id"].startswith(prefix)]
            unrecorded = sorted(sid for sid in _unrecorded_ids(s, {r["scan_id"] for r in _records(s)})
                                if sid.startswith(prefix))
        records.sort(key=lambda r: r.get("built_at") or "", reverse=True)
        kept, old = records[:keep], records[keep:]
        out = {"kept": [r["scan_id"] for r in kept], "deleted": [], "unrecorded": unrecorded}
        targets = [(r["scan_id"], r.get("status")) for r in old]
        if include_unrecorded:
            if dry_run:
                plan_path.parent.mkdir(parents=True, exist_ok=True)
                plan_path.write_text(json.dumps({"listed_at": _now(), "prefix": prefix,
                                                 "scan_ids": unrecorded}, indent=1))
            else:
                if not plan_path.exists():
                    raise GcRefused("--include-unrecorded deletes scans Orion has no record of; list "
                                    "them first with --dry-run --include-unrecorded")
                listed = set(json.loads(plan_path.read_text())["scan_ids"])
                targets += [(sid, None) for sid in unrecorded if sid in listed]
        for sid, status in targets:
            row = {"scan_id": sid, "status": status}
            if not dry_run:
                row["removed"] = delete_scan(driver, sid, SCAN_LABELS)
            out["deleted"].append(row)
        if include_unrecorded and not dry_run:
            plan_path.unlink()
        return out
    finally:
        driver.close()
