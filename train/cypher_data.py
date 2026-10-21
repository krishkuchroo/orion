"""text2cypher retention set: non-LLM rows only (design rule: GPT/Claude/Gemini/T5 rows dropped,
unknown provenance excluded).

ALLOWED_SOURCES is EMPTY on purpose. The only provenance evidence available without downloading the data
is the Hugging Face card for neo4j/text2cypher-2025v1, and its README carries only front matter (license
apache-2.0, tags, size) and no statement of how any `data_source` value's questions or Cypher were
produced. Provenance is therefore unverified for every source, so none is allowed. Add an entry only with
a provenance comment recording how its non-LLM origin was checked. Until then the loader returns [].
"""
from __future__ import annotations

import json
import logging
from collections import Counter

log = logging.getLogger(__name__)

ALLOWED_SOURCES: tuple[str, ...] = ()

SYSTEM_PROMPT = "Write one Cypher query for this schema."


def load_text2cypher(path: str) -> list[dict]:
    """Read a JSONL export; keep rows whose `data_source` is in ALLOWED_SOURCES; log kept/dropped per source."""
    kept: list[dict] = []
    seen: Counter = Counter()
    keep_n: Counter = Counter()
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            r = json.loads(ln)
            src = r.get("data_source")
            seen[src] += 1
            if src not in ALLOWED_SOURCES:
                continue
            keep_n[src] += 1
            kept.append({
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": f"{r['schema']}\n\n{r['question']}"}],
                "target": r["cypher"],
            })
    for src, n in sorted(seen.items(), key=lambda kv: str(kv[0])):
        log.info("text2cypher source %r: kept %d, dropped %d", src, keep_n[src], n - keep_n[src])
    return kept
