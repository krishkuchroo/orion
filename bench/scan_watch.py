"""Live monitor for a running Orion scan (build -> semantic -> discover -> verify -> report).

Passive: tails the scan's own progress.jsonl under <repo>/.orion/runs/<scan_id>/<ts>/. Safe to open,
close, and reopen while the scan runs. With no argument it attaches to the most recent scan.

    python bench/scan_watch.py [scan_id]
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = REPO_ROOT / ".orion" / "runs"

PHASE_LABEL = {
    "build": "Build graph (Joern -> Neo4j)",
    "discover": "Discovery fleet (4 agent shapes query the graph)",
    "verify": "Independent verifier (re-derives each lead)",
    "report": "Rank + render report",
}


def newest_log(scan_id: str | None) -> Path | None:
    base = RUNS_ROOT / scan_id if scan_id else RUNS_ROOT
    logs = sorted(base.glob("*/progress.jsonl") if scan_id else base.glob("*/*/progress.jsonl"),
                  key=lambda p: p.stat().st_mtime if p.exists() else 0)
    return logs[-1] if logs else None


def _sh(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout.strip()
    except Exception:
        return ""


def gpu() -> str:
    out = _sh(["nvidia-smi", "--query-gpu=utilization.gpu,memory.used", "--format=csv,noheader"])
    return out.splitlines()[0] if out else "n/a"


def claude_procs() -> int:
    out = _sh(["pgrep", "-c", "claude"])
    return int(out) if out.isdigit() else 0


def render(path: Path) -> str:
    events = []
    for line in path.read_text(errors="replace").splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    out = ["\033[H\033[J"]
    out.append(f"  ORION full scan   ({path.parent.parent.name[:12]}…)")
    out.append(f"  {datetime.now(timezone.utc).strftime('%H:%M:%SZ')}   "
               f"claude sessions: {claude_procs()}   gpu: {gpu()}")
    out.append("  " + "-" * 76)

    phase_last: dict[str, dict] = {}
    shapes: dict[str, str] = {}
    tool_q = 0
    verdicts: dict[str, int] = {}
    for e in events:
        phase_last[e.get("phase")] = e
        if e.get("phase") == "discover" and e.get("shape"):
            shapes[e["shape"]] = e.get("event", "")
        if e.get("event") == "tool":
            tool_q += 1
        if e.get("phase") == "verify" and e.get("event") == "verdict":
            verdicts[e.get("detail", "?")] = verdicts.get(e.get("detail", "?"), 0) + 1

    for ph in ("build", "discover", "verify", "report"):
        e = phase_last.get(ph)
        if not e:
            out.append(f"    .  {PHASE_LABEL[ph]:<48} pending")
        else:
            mark = "OK" if e.get("event") == "done" else ".."
            out.append(f"    {mark} {PHASE_LABEL[ph]:<48} {e.get('event')}")
    out.append("")
    if shapes:
        out.append("  discovery shapes:  " + "   ".join(f"{s}:{v}" for s, v in sorted(shapes.items())))
    if tool_q:
        out.append(f"  graph queries by agents: {tool_q}")
    if verdicts:
        out.append("  verdicts so far:   " + "   ".join(f"{k}={v}" for k, v in sorted(verdicts.items())))
    out.append("")
    out.append("  recent events:")
    for e in [e for e in events if e.get("event") != "tool"][-12:]:
        sh = f"[{e['shape']}]" if e.get("shape") else "   "
        out.append(f"    {e.get('phase',''):8}{e.get('event',''):8}{sh:4} {(e.get('detail') or '')[:58]}")
    last_q = next((e for e in reversed(events) if e.get("event") == "tool"), None)
    if last_q:
        out.append(f"    last query: {(last_q.get('detail') or '')[:70]}")
    return "\n".join(out)


def main() -> int:
    scan_id = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"waiting for a scan log under {RUNS_ROOT} ...")
    try:
        while True:
            p = newest_log(scan_id)
            if p is None:
                time.sleep(2)
                continue
            sys.stdout.write(render(p))
            sys.stdout.flush()
            if '"phase": "report"' in p.read_text(errors="replace") and \
                    '"event": "done"' in p.read_text(errors="replace").rsplit("report", 1)[-1]:
                print("\n\n  scan complete -- see bench/runs/<ts>/findings.json and report.log")
                return 0
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n(monitor closed; scan keeps running)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
