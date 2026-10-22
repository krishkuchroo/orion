import json
from pathlib import Path
from string import Template

FINDINGS_SCHEMA = json.loads((Path(__file__).parent / "findings.schema.json").read_text())

TASK_PROMPT = """You are a security auditor. Review the source code in the current repository \
for exploitable security vulnerabilities in its own first-party code (ignore third-party \
dependencies). Look for injection (SQL, command, code, template), path traversal, SSRF, \
cross-site scripting, insecure deserialization, authentication and authorization bypasses, \
and XML external entity processing.

Report every vulnerability you find by writing a file named findings.json in the repository \
root. It must be a JSON object of this exact shape and nothing else:

{"findings": [{"file": "<path from repo root>", "function": "<enclosing function or method>", \
"line_start": <int>, "line_end": <int>, "cwe": "CWE-<number>", "title": "<short label>", \
"explanation": "<why it is exploitable>", \
"path": [{"file": "<path>", "function": "<function>", "line": <int>, \
"role": "source|propagator|sink"}]}]}

The "path" field is optional: when you can trace how attacker-controlled data reaches the \
vulnerable code, list the steps in order from source to sink; omit it otherwise.

Report only vulnerabilities you can point to a specific location for. If you find none, write \
{"findings": []}. Do not modify any source file other than writing findings.json."""

_TYPES = {"file": str, "function": str, "line_start": int, "line_end": int,
          "cwe": str, "title": str, "explanation": str}
_OPTIONAL = {"path": list}  # absent is fine; present must be a list of objects


def validate_findings(obj: dict) -> list[str]:
    problems = []
    items = obj.get("findings")
    if not isinstance(items, list):
        return ["missing 'findings' list"]
    for i, it in enumerate(items):
        if not isinstance(it, dict):
            problems.append(f"finding {i} is not an object")
            continue
        for k, t in _TYPES.items():
            if k not in it:
                problems.append(f"finding {i} missing '{k}'")
            elif not isinstance(it[k], t) or (t is int and isinstance(it[k], bool)):
                problems.append(f"finding {i} field '{k}' wrong type")
        for k, t in _OPTIONAL.items():
            if k in it and (not isinstance(it[k], t) or not all(isinstance(s, dict) for s in it[k])):
                problems.append(f"finding {i} field '{k}' wrong type")
    return problems


# ---- OWASP Benchmark targeted judgement (spec 5.4; Task F2) ------------------------------------
# One case per run: the agent is pointed at the case's file and entry point and answers vulnerable
# or not. Same findings schema as TASK_PROMPT (incl. the optional "path"); the shape text below is
# cut from TASK_PROMPT itself so the two can never drift. Frozen with TASK_PROMPT at the tag.

# OWASP's short category name (expectedresults-*.csv, column 2) -> the plain description CASE_PROMPT
# names. Covers every category of Java v1.2 (11) and Python v0.1 (14). Each follows OWASP's own
# category title -- the Java v1.2 scorecard names ("Weak Encryption Algorithm", ...) and the Python
# v0.1 index page ("Unchecked Redirect Category", ...) -- with the CWE's plain meaning added where the
# title alone is vague (securecookie = CWE-614, a sensitive cookie without the Secure flag).
OWASP_CATEGORIES = {
    "cmdi": "OS command injection",                        # CWE-78
    "codeinj": "code injection",                           # CWE-94
    "crypto": "weak encryption algorithm",                 # CWE-327
    "deserialization": "insecure deserialization",         # CWE-502
    "hash": "weak hashing algorithm",                      # CWE-328
    "ldapi": "LDAP injection",                             # CWE-90
    "pathtraver": "path traversal",                        # CWE-22
    "redirect": "unchecked (open) redirect",               # CWE-601
    "securecookie": "insecure cookie (missing Secure flag)",  # CWE-614
    "sqli": "SQL injection",                               # CWE-89
    "trustbound": "trust boundary violation",              # CWE-501
    "weakrand": "weak randomness",                         # CWE-330
    "xpathi": "XPath injection",                           # CWE-643
    "xss": "cross-site scripting (XSS)",                   # CWE-79
    "xxe": "XML external entity (XXE) injection",          # CWE-611
}

_SHAPE = TASK_PROMPT[TASK_PROMPT.index('{"findings": [{"file"'):TASK_PROMPT.index("\n\nReport only")]

# string.Template placeholders ($file, $entry, $category): the JSON shape is full of braces.
CASE_PROMPT = ("You are a security auditor. Judge whether $file (entry $entry) contains an exploitable "
               "$category vulnerability. Write findings.json with zero or one finding.\n\n"
               "Put findings.json in the repository root; it must be a JSON object of this exact "
               "shape and nothing else:\n\n"
               + _SHAPE +
               "\n\nIf the code is vulnerable, report that one vulnerability as the single finding, at "
               "its location. If it is not, write {\"findings\": []}. Do not modify any source file "
               "other than writing findings.json.")


def case_prompt(case: dict) -> str:
    """CASE_PROMPT filled with one OWASP case's file, entry and plain category description. Only those
    three fields are read: the case's answer (`real`) never reaches the agent."""
    category = case.get("category")
    if category not in OWASP_CATEGORIES:
        raise ValueError(f"OWASP category {category!r} has no description in OWASP_CATEGORIES")
    return Template(CASE_PROMPT).substitute(file=case["file"], entry=case["entry"],
                                            category=OWASP_CATEGORIES[category])
