"""Normalize every arm's output to one finding shape:
{arm, file, function, line, cwe, confidence, path: [{file, function, line, role}], raw_text}.

Never fabricates: anything absent from the raw finding is None ([] for path). Never drops a
finding: location-less ones are returned with file=None for the judge to handle later.

On-disk formats read by load_arm:
  plain-*   : {"findings": [{file, function, line_start, line_end, cwe, title, explanation, path?}]}
  orion-lm* : a JSON list of dataclasses.asdict(Verdict) dicts (same as `orion scan --json`).
"""
import re

from eval.convert import load

_EXT = r"(?:py|js|jsx|ts|tsx|mjs|cjs|java|go|rb|php|c|cc|cpp|h|hpp|cs|rs|kt|scala|swift|sql|html|ejs|xml|json|ya?ml)"
_FILE_RE = re.compile(r"(?<![\w./-])((?:[\w.-]+/)*[\w.-]+\.%s)(?![\w/])" % _EXT, re.I)
_CWE_RE = re.compile(r"\bCWE[-\s]?0*(\d+)", re.I)
_LINE_RE = re.compile(r"\blines?\s+(\d+)|\bL(\d+)\b|:(\d+)", re.I)
# well-known framework/library names that look like files; dropped when bare tokens
_STOP = {"express.js", "node.js", "vue.js", "react.js", "angular.js", "next.js", "nuxt.js",
         "d3.js", "three.js", "jquery.js"}


def _files(blob: str) -> list[str]:
    return [m.group(1) for m in _FILE_RE.finditer(blob)
            if "/" in m.group(1) or m.group(1).lower() not in _STOP]


def _cwe(*blobs: str):
    for b in blobs:
        m = _CWE_RE.search(b or "")
        if m:
            return f"CWE-{int(m.group(1))}"
    return None


def _extract_file_line(text: str, evidence: str):
    """File may be cited in text or evidence (cf. run_nodegoat_eval._file_blob). Rank candidates:
    present in both text and evidence, then containing a '/', then bare name.ext; first-seen
    within a tier."""
    in_text, in_ev = _files(text), _files(evidence)
    cands = list(dict.fromkeys(in_text + in_ev))
    if not cands:
        return None, None

    def tier(f):
        return 0 if (f in in_text and f in in_ev) else 1 if "/" in f else 2

    file = min(cands, key=tier)  # min is stable: first-seen wins ties
    for blob in ((text, evidence) if file in in_text else (evidence, text)):
        i = blob.find(file)
        if i >= 0:
            m = _LINE_RE.search(blob[i + len(file):i + len(file) + 40])
            if m:
                return file, int(next(g for g in m.groups() if g))
    return file, None


def _path(raw) -> list[dict]:
    if not isinstance(raw, list):
        return []
    return [{"file": s.get("file"), "function": s.get("function"),
             "line": s.get("line"), "role": s.get("role")} for s in raw if isinstance(s, dict)]


def finding(raw: dict, *, arm: str) -> dict:
    out = {"arm": arm, "file": None, "function": None, "line": None, "cwe": None,
           "confidence": None, "path": [], "raw_text": ""}
    if arm.startswith("plain-"):
        out.update(file=raw.get("file"), function=raw.get("function"), line=raw.get("line_start"),
                   cwe=raw.get("cwe"), path=_path(raw.get("path")),
                   raw_text=" ".join(p for p in (raw.get("title"), raw.get("explanation")) if p))
        return out
    lead = raw.get("lead") if isinstance(raw.get("lead"), dict) else raw
    out["confidence"] = lead.get("confidence")
    out["raw_text"] = lead.get("text") or ""
    if lead.get("shape") == "LM" or arm.startswith("orion-lm") and lead.get("file") is not None:
        out.update(file=lead.get("file"), function=lead.get("function"), line=lead.get("line"),
                   cwe=lead.get("cwe"), path=_path(lead.get("path")))
        return out
    # claude engine (or an LM lead without structure): location is prose
    text, ev = lead.get("text") or "", lead.get("evidence") or ""
    file, line = _extract_file_line(text, ev)
    out.update(file=lead.get("file") or file, function=lead.get("function"),
               line=lead.get("line") if lead.get("file") else line,
               cwe=lead.get("cwe") or _cwe(text, ev),
               path=_path(lead.get("path")))
    return out


def load_arm(path: str, *, arm: str) -> list[dict]:
    try:
        data = load(path)
        if arm.startswith("plain-"):
            items = data.get("findings") if isinstance(data, dict) else None
        else:
            items = data
        if not isinstance(items, list):
            return []
        return [finding(it, arm=arm) for it in items if isinstance(it, dict)]
    except Exception:
        return []
