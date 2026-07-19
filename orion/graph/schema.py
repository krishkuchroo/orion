"""Canonical CPG schema for Orion — the frozen 7-node / 5-edge subset, as plain data.

A trimmed fork of sentryV2's collector framework. It keeps the one thing a collector must never
improvise — the deterministic uid — but drops the whole schema.json validation universe: Orion
persists exactly the schema-of-record labels, so node identity (the MERGE key) lives here as a
small dict, not a loaded JSON schema.

`Batch` is the write buffer: `emit_node`/`emit_edge` stamp scan_id and accumulate records the
persist layer MERGEs. Keeping scan_id on BOTH edge endpoint keys is bug-fix B2 (see emit_edge).
"""
from __future__ import annotations

import hashlib

# Node identity for MERGE — the key the persist layer matches and writes on. Every key leads
# with scan_id so a node is unique within its scan partition (never across scans).
NODE_KEY: dict[str, tuple[str, ...]] = {
    "CpgFile": ("scan_id", "uid"),
    "CpgMethod": ("scan_id", "full_name"),
    "CpgCall": ("scan_id", "uid"),
    "CpgModule": ("scan_id", "import_name"),
    "CpgParameter": ("scan_id", "uid"),
    "CpgReturn": ("scan_id", "uid"),
    "EntryPoint": ("scan_id", "uid"),
    "Dependency": ("scan_id", "name"),
}


def synthesize_uid(scan_id: str, cpg_type: str, file_path, line, column, code) -> str:
    """Deterministic structural identity (Doc 2 §5.3): the same normalized source always
    yields the same uid, so a re-scan MERGEs onto the same node and never duplicates. The
    scan_id is hashed in, so a uid is inherently scan-scoped. Never random."""
    parts = [scan_id, cpg_type, file_path or "", str(line), str(column), code or ""]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


class Batch:
    """Write buffer for one scan. Subclass-free: the adapter calls emit_node / emit_edge and
    the persist layer consumes `.nodes` / `.edges`. Every record carries scan_id."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.nodes: list[tuple[str, dict]] = []
        self.edges: list[tuple[str, str, dict, str, dict, dict]] = []

    def emit_node(self, label: str, props: dict) -> None:
        props.setdefault("scan_id", self.scan_id)
        self.nodes.append((label, props))

    def emit_edge(self, rtype: str, from_label: str, from_key: dict,
                  to_label: str, to_key: dict, props: dict | None = None) -> None:
        p = dict(props or {})
        p.setdefault("scan_id", self.scan_id)
        # Bug-fix B2: scan_id must be part of BOTH endpoint match keys. Endpoints matched only by
        # a non-scan-unique key (e.g. CpgMethod.full_name) would otherwise bind the wrong scan's
        # node when two scans share a name, cross-linking the graphs. Stamping it here fixes every
        # edge type at once (CONTAINS_CALL / RESOLVES_TO / DEFINED_IN / FLOWS_TO / ENTERS_AT).
        from_key = {**from_key, "scan_id": self.scan_id}
        to_key = {**to_key, "scan_id": self.scan_id}
        self.edges.append(
            (rtype, from_label, from_key, to_label, to_key, p))
