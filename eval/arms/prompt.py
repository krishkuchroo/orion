import json
from pathlib import Path

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
"explanation": "<why it is exploitable>"}]}

Report only vulnerabilities you can point to a specific location for. If you find none, write \
{"findings": []}. Do not modify any source file other than writing findings.json."""

_TYPES = {"file": str, "function": str, "line_start": int, "line_end": int,
          "cwe": str, "title": str, "explanation": str}


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
    return problems
