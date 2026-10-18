"""CWE family test for the L2 match level.

CWE_PARENTS maps a CWE number to its immediate parent in the CWE-1000 (Research Concepts) view,
for the 9 target CWEs plus the immediate children/parents that matter for L2.

verified against cwe.mitre.org <date>: NO -- verify before the tag (written from memory; the
controller records this as a Krish check before `eval-prereg-v1`/`orion-lm-prereg-v1`).
"""
CWE_PARENTS = {
    22: 706,    # Path Traversal -> Use of Incorrectly-Resolved Name or Reference
    23: 22,     # Relative Path Traversal (child of 22)
    36: 22,     # Absolute Path Traversal (child of 22)
    78: 77,     # OS Command Injection -> Command Injection
    79: 74,     # XSS -> Injection
    89: 943,    # SQL Injection -> Improper Neutralization of Special Elements in Data Query Logic
    94: 913,    # Code Injection -> Improper Control of Dynamically-Managed Code Resources
    502: 913,   # Deserialization of Untrusted Data
    611: 610,   # XXE -> Externally Controlled Reference to a Resource in Another Sphere
    918: 441,   # SSRF -> Unintended Proxy or Intermediary
    1321: 915,  # Prototype Pollution -> Improperly Controlled Modification of Dynamically-Determined Object Attributes
}


def parse(cwe) -> int | None:
    """'CWE-89' / 'cwe-89' / '89' / 89 -> 89; anything unparseable -> None."""
    if cwe is None:
        return None
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        s = s[4:]
    return int(s) if s.isdigit() else None


def same_family(a, b) -> bool:
    """Exact match, or one hop in CWE-1000 (parent/child), or shared immediate parent."""
    x, y = parse(a), parse(b)
    if x is None or y is None:
        return False
    px, py = CWE_PARENTS.get(x), CWE_PARENTS.get(y)
    return x == y or px == y or py == x or (px is not None and px == py)
