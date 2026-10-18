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
_CWE_RE = re.compile(r"CWE-\d+", re.I)
_LINE_RE = re.compile(r"(?:\bline\s+|:)(\d+)", re.I)


def _files(blob: str) -> list[str]:
    return [m.group(1) for m in _FILE_RE.finditer(blob)]


def _extract_file_line(text: str, evidence: str):
    """File may be cited in text or evidence (cf. run_nodegoat_eval._file_blob): prefer a token
    present in both, then the first in text, then the first in evidence."""
    in_text, in_ev = _files(text), _files(evidence)
    both = [f for f in in_text if f in in_ev]
    file = (both or in_text or in_ev or [None])[0]
    if file is None:
        return None, None
    for blob in ((text, evidence) if file in in_text else (evidence, text)):
        i = blob.find(file)
        if i >= 0:
            m = _LINE_RE.match(blob[i + len(file):i + len(file) + 40].lstrip(" ,;)")) or \
                _LINE_RE.search(blob[i + len(file):i + len(file) + 40])
            if m:
                return file, int(m.group(1))
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
    m = _CWE_RE.search(text)
    out.update(file=lead.get("file") or file, function=lead.get("function"),
               line=lead.get("line") if lead.get("file") else line,
               cwe=lead.get("cwe") or (m.group(0).upper() if m else None),
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
