"""Manifest v2: the test-set vulnerabilities (vulnerable + patched commit, answer key).

File shape: {"repos": [row, ...]}. Row schema (spec 5.4):

Required (every row):
  id: str (unique)                      repo_url: str
  tier: "headline"|"control"|"scale"|"excluded"   (the names eval.dataset.check.classify returns)
  vulnerable_commit: str                patched_commit: str
  cwe: str - exactly one CWE (eval.cwe.parse must read it): the CWE that qualified the row
       for its kind (eval.dataset.mine.qualifying_cwe)
  fix_sites: list[{file: str, line: int|None, end_line: int|None, function: str|None,
                   method_full_name: str|None}]   VULNERABLE-side sites (lines of the vulnerable
                   commit; the shape eval.match reads)
  accepted_entry_points: list[dict]     (eval.pathgt: uid, kind, method_full_name, file, line)
  labelers: list[str]                   ([] until a human signs; required non-empty with
                                        require_labels=True, the tag-time check)
Optional (type-checked when present):
  fix_sites_patched: list[site]         the same fix sites on the PATCHED commit (its line numbers;
                                        eval.pathgt via fixmap.fix_sites(side="patched")): the
                                        answer key of a patched (false-alarm) run.
  repo: str ("owner/name"), repo_canonical: str, repo_raw: str (the advisory's name for a renamed
  repo), language: str, ghsa: str, cve: str, cwe_basis: str,
  cwes: list[str] (every CWE the advisory lists, in its order; must parse and include cwe),
  sink_or_protected_operation: dict|str|None, entry_evidence: str, guard: str|dict|None,
  agreement: number|str|dict|None, graph_missed: bool, kind: "dataflow"|"access_control".

validate() returns human-readable errors and never raises on bad rows. A row whose repo (or
repo_canonical, repo_raw, or the repo parsed from repo_url) is a training/dev/oldcve repo is an
error. With require_labels=True (the tag-time check, and eval.run's default) a row also needs a
non-empty `labelers`, `fix_sites` and `fix_sites_patched`: without sites L1 would match nothing.

answer_keys(row, side) is the L1/L2 answer key of one row for a run on its `side` commit
("vulnerable" -> fix_sites, "patched" -> fix_sites_patched); see eval.match for the rule.
"""
import json
import os
import re

from eval import cwe as _cwe

_TIERS = ("headline", "control", "scale", "excluded")
_KINDS = ("dataflow", "access_control")
_REQUIRED_STR = ("id", "repo_url", "tier", "vulnerable_commit", "patched_commit", "cwe")
_REQUIRED_LIST = ("fix_sites", "accepted_entry_points", "labelers")
_SIDES = {"vulnerable": "fix_sites", "patched": "fix_sites_patched"}
_OPT_STR = ("repo", "repo_canonical", "repo_raw", "language", "ghsa", "cve", "entry_evidence", "cwe_basis")
_GH = re.compile(r"github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", re.I)


def load(path: str) -> dict:
    """Parse the manifest file; checks only the top-level {"repos": [...]} structure."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("repos"), list):
        raise ValueError(f'{path}: manifest must be {{"repos": [...]}}')
    return data


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _site_errors(label: str, i: int, s, field: str = "fix_sites") -> list[str]:
    if not isinstance(s, dict):
        return [f"{label}: {field}[{i}] is not an object"]
    errs = []
    for k in ("file", "function", "method_full_name"):
        if s.get(k) is not None and not isinstance(s[k], str):
            errs.append(f"{label}: {field}[{i}].{k} must be a string")
    for k in ("line", "end_line"):
        if s.get(k) is not None and (not isinstance(s[k], int) or isinstance(s[k], bool)):
            errs.append(f"{label}: {field}[{i}].{k} must be an integer")
    if not s.get("file"):
        errs.append(f"{label}: {field}[{i}] needs a file")
    return errs


def _row_repos(row: dict) -> set[str]:
    out = {row[k].lower() for k in ("repo", "repo_canonical", "repo_raw") if isinstance(row.get(k), str)}
    m = _GH.search(row["repo_url"]) if isinstance(row.get("repo_url"), str) else None
    if m:
        out.add(f"{m.group(1)}/{m.group(2)}".lower())
    return out


def validate(data, *, split_repos=None, require_labels: bool = False) -> list[str]:
    """Human-readable errors for a loaded manifest (empty list = clean). Never raises on bad rows."""
    if not isinstance(data, dict) or not isinstance(data.get("repos"), list):
        return ['manifest must be {"repos": [...]}']
    errs, seen = [], set()
    trained = {r.lower() for r in split_repos or ()}
    for n, row in enumerate(data["repos"]):
        if not isinstance(row, dict):
            errs.append(f"row {n}: not an object")
            continue
        label = f"row {n} ({row['id']})" if isinstance(row.get("id"), str) and row["id"] else f"row {n}"
        for k in _REQUIRED_STR:
            if not isinstance(row.get(k), str) or not row[k]:
                errs.append(f"{label}: missing or empty {k}")
        for k in _REQUIRED_LIST:
            if not isinstance(row.get(k), list):
                errs.append(f"{label}: {k} must be a list")
        if isinstance(row.get("id"), str) and row["id"]:
            if row["id"] in seen:
                errs.append(f"{label}: duplicate id")
            seen.add(row["id"])
        if isinstance(row.get("cwe"), str) and row["cwe"] and _cwe.parse(row["cwe"]) is None:
            errs.append(f"{label}: cwe {row['cwe']!r} must be exactly one CWE (e.g. 'CWE-89')")
        if "cwes" in row:
            cw = row["cwes"]
            if not isinstance(cw, list) or any(_cwe.parse(x) is None for x in cw):
                errs.append(f"{label}: cwes must be a list of CWEs")
            elif _cwe.parse(row.get("cwe")) not in {_cwe.parse(x) for x in cw}:
                errs.append(f"{label}: cwes must include cwe {row.get('cwe')!r}")
        if isinstance(row.get("tier"), str) and row["tier"] not in _TIERS:
            errs.append(f"{label}: tier {row['tier']!r} not one of {list(_TIERS)}")
        for k in _OPT_STR:
            if k in row and row[k] is not None and not isinstance(row[k], str):
                errs.append(f"{label}: {k} must be a string")
        if row.get("kind") is not None and row["kind"] not in _KINDS:
            errs.append(f"{label}: kind {row['kind']!r} not one of {list(_KINDS)}")
        if row.get("graph_missed") is not None and not isinstance(row["graph_missed"], bool):
            errs.append(f"{label}: graph_missed must be a bool")
        if row.get("sink_or_protected_operation") is not None and \
                not isinstance(row["sink_or_protected_operation"], (dict, str)):
            errs.append(f"{label}: sink_or_protected_operation must be an object, string or null")
        if row.get("guard") is not None and not isinstance(row["guard"], (str, dict)):
            errs.append(f"{label}: guard must be a string, object or null")
        if row.get("agreement") is not None and not (_num(row["agreement"])
                                                     or isinstance(row["agreement"], (str, dict))):
            errs.append(f"{label}: agreement must be a number, string, object or null")
        for field in _SIDES.values():
            if field in row and row[field] is not None and not isinstance(row[field], list):
                errs.append(f"{label}: {field} must be a list")
            elif isinstance(row.get(field), list):
                for i, s in enumerate(row[field]):
                    errs.extend(_site_errors(label, i, s, field))
            if require_labels and not row.get(field):
                errs.append(f"{label}: {field} is empty (require_labels): L1 would match nothing")
        if isinstance(row.get("accepted_entry_points"), list):
            errs.extend(f"{label}: accepted_entry_points[{i}] is not an object"
                        for i, e in enumerate(row["accepted_entry_points"]) if not isinstance(e, dict))
        if isinstance(row.get("labelers"), list):
            if any(not isinstance(l, str) or not l for l in row["labelers"]):
                errs.append(f"{label}: labelers must be non-empty strings")
            if require_labels and not row["labelers"]:
                errs.append(f"{label}: labelers is empty (require_labels)")
        hit = sorted(_row_repos(row) & trained)
        if hit:
            errs.append(f"{label}: repo {hit[0]} is a training/dev/oldcve repo (in train/data/splits.json)")
    return errs


def answer_keys(row: dict, side: str) -> list[dict]:
    """The answer key(s) to pass to eval.match.match_run for a run on `side` ("vulnerable" or
    "patched") of manifest row `row`: ONE key per vulnerability (this row), carrying every fix site
    of that side, its CWE(s) and (vulnerable side) its accepted entry points. vuln_id = row["id"].

    Raises ValueError for an unknown side or a row without sites on that side (an unlabeled row):
    a key with no sites would silently score every run as a miss."""
    if side not in _SIDES:
        raise ValueError(f"side must be one of {sorted(_SIDES)}, not {side!r}")
    field = _SIDES[side]
    sites = row.get(field)
    if not isinstance(sites, list) or not sites:
        raise ValueError(f"row {row.get('id')!r} has no {field}: label it first "
                         "(eval.manifest.validate(require_labels=True))")
    return [{"id": row["id"], "side": side, "fix_sites": [dict(s) for s in sites],
             "cwe": row.get("cwe"), "cwes": list(row.get("cwes") or []),
             "accepted_entry_points": ([dict(e) for e in row.get("accepted_entry_points") or []]
                                       if side == "vulnerable" else [])}]


def split_repos(pairs_path: str = "train/data/pairs.json",
                splits_path: str = "train/data/splits.json") -> set[str]:
    """Lowercased repo and repo_canonical of every pair assigned in splits.json. A missing file, or
    a split pair id absent from pairs.json, raises: the training-repo check is never skipped."""
    for what, p in (("pairs", pairs_path), ("splits", splits_path)):
        if not os.path.exists(p):
            raise FileNotFoundError(
                f"{what} file not found: {p} (needed for the training-repo check; "
                f"pairs.json is gitignored and lives only in a checkout's train/data/)")
    with open(pairs_path) as f:
        pairs = {p["id"]: p for p in json.load(f)}
    with open(splits_path) as f:
        assignment = json.load(f)["assignment"]
    missing = sorted(set(assignment) - set(pairs))
    if missing:
        raise ValueError(f"{len(missing)} pair id(s) in {splits_path} missing from {pairs_path}, "
                         f"e.g. {missing[0]}")
    out = set()
    for pid in assignment:
        for k in ("repo", "repo_canonical"):
            if pairs[pid].get(k):
                out.add(pairs[pid][k].lower())
    return out
