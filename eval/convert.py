import json
import os


def load(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    try:
        return json.loads(open(path).read())
    except Exception:
        return []


def confirmed_verdicts(verdicts: list[dict]) -> list[dict]:
    out = []
    for v in verdicts:
        if v.get("decision") != "CONFIRM":
            continue
        lead = v.get("lead") or {}
        out.append({
            "decision": "CONFIRM",
            "reason": v.get("reason") or "",
            "evidence": v.get("evidence") or "",
            "sink_centrality": float(v.get("sink_centrality") or 0.0),
            "text": lead.get("text") or "",
            "text_evidence": lead.get("evidence") or "",
        })
    return out
