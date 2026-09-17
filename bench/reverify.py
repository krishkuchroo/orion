"""Re-verify selected leads from a prior Orion run, reusing the already-built graph.

Why this exists: Orion's per-lead verifier is capped at `VERIFY_MAX_TURNS` (default 10). A lead that
needs more tool-calling turns than that to re-derive exits as an `error_max_turns` ERROR verdict —
inconclusive, NOT a rejection. This bench-side helper re-runs `orion.verify.verify_all` on just the
ERROR (or any chosen decision) leads from a run's findings.json, so you can raise the budget and get
a clean CONFIRM/REJECT without repeating the ~25-minute build+discover pipeline. No Orion source is
modified — it calls the public `verify_all` seam and reuses the graph by scan_id.

Run it FROM the repo root (so `.mcp/orion.json` resolves) with Neo4j env sourced, e.g.:

    source bench/env.sh
    ORION_VERIFY_MAX_TURNS=30 ORION_VERIFY_TIMEOUT=600 \
      ./.venv/bin/python bench/reverify.py \
        bench/runs/<ts>/findings.json <scan_id> /home/lutherleo/apex --only ERROR
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _alias_transformers_config() -> None:
    # Same shim as bench/orion_scan.py: transformers<5 spells the config class `PretrainedConfig`;
    # Orion's lazy import expects the 5.x `PreTrainedConfig`. Harmless if unused by verification.
    try:
        import transformers.configuration_utils as cu
        if not hasattr(cu, "PreTrainedConfig") and hasattr(cu, "PretrainedConfig"):
            cu.PreTrainedConfig = cu.PretrainedConfig
    except Exception:  # noqa: BLE001
        pass


def main() -> int:
    _alias_transformers_config()
    from orion.contracts import Lead
    from orion.verify import verify_all
    import orion.config as config

    if len(sys.argv) < 4:
        print("usage: python bench/reverify.py <findings.json> <scan_id> <repo_path> [--only DECISION]",
              file=sys.stderr)
        return 2
    findings_path, scan_id, repo_path = sys.argv[1], sys.argv[2], sys.argv[3]
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else "ERROR"

    data = json.loads(Path(findings_path).read_text())
    leads: list[Lead] = []
    for it in data:
        if it.get("decision") != only:
            continue
        L = it["lead"]
        leads.append(Lead(index=L["index"], shape=L["shape"], text=L["text"],
                          evidence=L.get("evidence", ""), confidence=L.get("confidence", "MEDIUM")))
    if not leads:
        print(f"no leads with decision={only} in {findings_path}", file=sys.stderr)
        return 1

    print(f"re-verifying {len(leads)} {only} lead(s) | scan_id={scan_id} | "
          f"VERIFY_MAX_TURNS={config.VERIFY_MAX_TURNS} VERIFY_TIMEOUT={config.VERIFY_TIMEOUT}",
          flush=True)

    def on_event(e: dict) -> None:
        ev = e.get("event")
        if ev in ("start", "verdict", "error"):
            print(f"  [{e.get('phase')}/{ev}] shape={e.get('shape')} lead={e.get('lead')} "
                  f"{str(e.get('detail') or '')[:90]}", flush=True)

    verdicts = verify_all(scan_id, leads, repo_path, on_event)

    out = []
    for v in verdicts:
        print("=" * 88)
        print(f"lead {v.lead.index} shape {v.lead.shape}  ->  {v.decision}")
        print("  reason:  ", (v.reason or "")[:600])
        if v.evidence:
            print("  evidence:", (v.evidence or "")[:400])
        out.append({"lead": v.lead.__dict__, "decision": v.decision,
                    "reason": v.reason, "evidence": v.evidence})
    outp = Path(findings_path).with_name("reverify.json")
    outp.write_text(json.dumps(out, indent=2))
    tally: dict[str, int] = {}
    for v in verdicts:
        tally[v.decision] = tally.get(v.decision, 0) + 1
    print("\nre-verify tally:", "  ".join(f"{k}={n}" for k, n in sorted(tally.items())))
    print("wrote", outp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
