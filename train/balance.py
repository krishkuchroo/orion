"""Balanced, ordered Stage 1 training rows: `select(rows, pairs_by_id) -> (rows, report)`.

Pool (train split only), in this order:
  rule 1    `drop_conflicts`: a patched/negative row whose target code (`case.snippets[0].code`, stripped) equals a
            vulnerable row's target code in the same split is dropped (an incomplete fix's "patched" version is the
            next CVE's vulnerable version); then one row is kept per identical (code, label), the first in input order.
  fits      optional `fits(row) -> bool` (e.g. "renders within the trainer's max length"); failing rows are removed.
Twins and targets are read from the RAW Stage 1 order, so a drop never creates a false twin; a twin is used only
when both it and its vulnerable row survive.

Unit = one fix (one train pair): ONE vulnerable row, its patched twin when it has one, and ONE negative.
  twin      the patched row written directly after a vulnerable row of the same pair (Stage 1 writes target by
            target: vulnerable, then its patched twin when one exists, then the pair's negatives).
  target    the pair's first surviving vulnerable row that has a surviving twin, else its first surviving one.
  negative  the pair's first surviving negative whose case has a sink line after `orion.lm.sinks.annotate` (harder:
            at runtime every flow ends at a sink), else its first surviving negative, else none.
Fill: every fix of a SMALL family (fewer than `small_family` vulnerable rows in the pool) first, then every Python
fix, then the other languages (JS, Java) one fix at a time, always to the language with fewer rows so far. Within
each queue annotated fixes come first, then a seeded random order; so when a cap or the row total forces a choice,
annotated fixes win.
Caps (checked in this order): at most `repo_cap` fixes per repo (`repo_canonical`, lowercased); no CWE (the
vulnerable row's lead CWE) on more than floor(`cwe_share` x vulnerable rows) of the OUTPUT's vulnerable rows; no
CWE family (`FAMILY_OF`) above floor(`family_share` x vulnerable rows), except the families in `FAMILY_CAP_EXEMPT`
("other": unrelated CWEs, each still under the per-CWE cap). Those counts depend on how
many fixes end up chosen, so the fill is rerun with a smaller estimate until both caps hold for the final count.
A fix that would overshoot `total` ends the main fill; smaller fixes may then fill the gap. Nothing is padded:
when the pool cannot reach `total` the output is shorter and the report says so.
Order: units are shuffled (seeded) and laid out so a vulnerable row and its twin always sit in the same block of
`grad_accum` rows (one optimizer step). A pair that would start on a block's last slot gets a single row in front
of it: the unit's own negative, else a later unit's negative, else a later twinless vulnerable row; if none is
left, the twin is dropped (counted) rather than split.
"""
from __future__ import annotations

import math
import random
import re
from collections import Counter, defaultdict

FIRST_LANGUAGE = "py"
SMALL = "__small_families__"

FAMILIES = ("injection", "path", "XSS", "SSRF", "deserialization", "XXE", "prototype pollution", "access control",
            "auth/session", "open redirect", "crypto", "info leak", "DoS", "CWE-20", "other")

# CWE id -> family, by what each CWE is (MITRE titles in the comments). Anything not listed (or no CWE) is "other";
# the report lists the "other" CWEs present. CSRF (352) and WebSocket origin checks (1385, cross-site WebSocket
# hijacking) are under auth/session: both ride on the victim's authenticated session.
_FAMILY_IDS = {
    "injection": (
        74,     # Injection (special elements in output used by a downstream component)
        75,     # Special Element Injection into a different plane
        77,     # Command Injection
        78,     # OS Command Injection
        88,     # Argument Injection
        89,     # SQL Injection
        90,     # LDAP Injection
        91,     # XML Injection (Blind XPath Injection)
        93,     # CRLF Injection
        94,     # Code Injection
        95,     # Eval Injection
        99,     # Resource Injection (improper control of resource identifiers)
        113,    # HTTP Request/Response Splitting
        470,    # Unsafe Reflection (externally-controlled input selects classes or code)
        917,    # Expression Language Injection
        943,    # Data Query Logic Injection (NoSQL etc.)
        1236,   # CSV (formula) Injection
        1336,   # Template Engine Injection (SSTI)
    ),
    "path": (
        22,     # Path Traversal
        23,     # Relative Path Traversal
        24,     # Path Traversal: '../filedir'
        26,     # Path Traversal: '/dir/../filename'
        27,     # Path Traversal: 'dir/../../filename'
        29,     # Path Traversal: '\..\filename'
        36,     # Absolute Path Traversal
        59,     # Link Following
        61,     # UNIX Symbolic Link Following
        73,     # External Control of File Name or Path
    ),
    "XSS": (
        79,     # Cross-site Scripting
        80,     # Basic XSS
    ),
    "SSRF": (
        918,    # Server-Side Request Forgery
    ),
    "deserialization": (
        502,    # Deserialization of Untrusted Data
    ),
    "XXE": (
        611,    # XML External Entity Reference
        776,    # XML Entity Expansion
    ),
    "prototype pollution": (
        1321,   # Prototype Pollution
    ),
    "access control": (
        250,    # Execution with Unnecessary Privileges
        264,    # Permissions, Privileges, and Access Controls (category)
        266,    # Incorrect Privilege Assignment
        267,    # Privilege Defined With Unsafe Actions
        269,    # Improper Privilege Management
        272,    # Least Privilege Violation
        273,    # Improper Check for Dropped Privileges
        276,    # Incorrect Default Permissions
        277,    # Insecure Inherited Permissions
        280,    # Improper Handling of Insufficient Permissions or Privileges
        281,    # Improper Preservation of Permissions
        283,    # Unverified Ownership
        284,    # Improper Access Control
        285,    # Improper Authorization
        425,    # Direct Request ('Forced Browsing')
        639,    # Authorization Bypass Through User-Controlled Key
        732,    # Incorrect Permission Assignment for Critical Resource
        862,    # Missing Authorization
        863,    # Incorrect Authorization
        1220,   # Insufficient Granularity of Access Control
    ),
    "auth/session": (
        255,    # Credentials Management Errors (category)
        256,    # Plaintext Storage of a Password
        287,    # Improper Authentication
        288,    # Authentication Bypass Using an Alternate Path or Channel
        290,    # Authentication Bypass by Spoofing
        294,    # Authentication Bypass by Capture-replay
        302,    # Authentication Bypass by Assumed-Immutable Data
        304,    # Missing Critical Step in Authentication
        306,    # Missing Authentication for Critical Function
        307,    # Improper Restriction of Excessive Authentication Attempts
        352,    # Cross-Site Request Forgery
        384,    # Session Fixation
        521,    # Weak Password Requirements
        522,    # Insufficiently Protected Credentials
        613,    # Insufficient Session Expiration
        640,    # Weak Password Recovery Mechanism for Forgotten Password
        798,    # Use of Hard-coded Credentials
        1385,   # Missing Origin Validation in WebSockets
    ),
    "open redirect": (
        601,    # URL Redirection to Untrusted Site ('Open Redirect')
    ),
    "crypto": (
        295,    # Improper Certificate Validation
        296,    # Improper Following of a Certificate's Chain of Trust
        310,    # Cryptographic Issues (category)
        311,    # Missing Encryption of Sensitive Data
        312,    # Cleartext Storage of Sensitive Information
        319,    # Cleartext Transmission of Sensitive Information
        320,    # Key Management Errors (category)
        325,    # Missing Cryptographic Step
        326,    # Inadequate Encryption Strength
        327,    # Use of a Broken or Risky Cryptographic Algorithm
        328,    # Use of Weak Hash
        330,    # Use of Insufficiently Random Values
        335,    # Incorrect Usage of Seeds in PRNG
        338,    # Cryptographically Weak PRNG
        347,    # Improper Verification of Cryptographic Signature
        759,    # One-Way Hash without a Salt
        1240,   # Cryptographic Primitive with a Risky Implementation
    ),
    "info leak": (
        200,    # Exposure of Sensitive Information to an Unauthorized Actor
        201,    # Insertion of Sensitive Information Into Sent Data
        202,    # Exposure of Sensitive Information Through Data Queries
        203,    # Observable Discrepancy
        208,    # Observable Timing Discrepancy
        209,    # Error Message Containing Sensitive Information
        212,    # Improper Removal of Sensitive Information Before Storage or Transfer
        214,    # Invocation of Process Using Visible Sensitive Information
        359,    # Exposure of Private Personal Information
        524,    # Use of Cache Containing Sensitive Information
        525,    # Use of Web Browser Cache Containing Sensitive Information
        527,    # Exposure of Version-Control Repository
        532,    # Insertion of Sensitive Information into Log File
        534,    # Information Exposure Through Debug Log Files (deprecated)
        538,    # Sensitive Information in an Externally-Accessible File or Directory
        548,    # Exposure of Information Through Directory Listing
        598,    # GET Request Method With Sensitive Query Strings
    ),
    "DoS": (
        399,    # Resource Management Errors (category)
        400,    # Uncontrolled Resource Consumption
        401,    # Missing Release of Memory after Effective Lifetime
        407,    # Inefficient Algorithmic Complexity
        408,    # Incorrect Behavior Order: Early Amplification
        674,    # Uncontrolled Recursion
        730,    # OWASP Top Ten 2004 A9 Denial of Service (category)
        770,    # Allocation of Resources Without Limits or Throttling
        772,    # Missing Release of Resource after Effective Lifetime
        789,    # Memory Allocation with Excessive Size Value
        834,    # Excessive Iteration
        835,    # Infinite Loop
        1333,   # Inefficient Regular Expression Complexity (ReDoS)
    ),
    "CWE-20": (
        20,     # Improper Input Validation
    ),
}
FAMILY_OF: dict[int, str] = {i: fam for fam, ids in _FAMILY_IDS.items() for i in ids}
# Families with no `family_share` cap. "other" is ~100 unrelated CWEs, not one bug type; the per-CWE cap
# (`cwe_share`) still applies to each CWE inside it.
FAMILY_CAP_EXEMPT = frozenset({"other"})


def family(cwe) -> str:
    """Family of a CWE string such as "CWE-79"; unknown, malformed or missing -> "other"."""
    m = re.fullmatch(r"CWE-(\d+)", str(cwe).strip()) if cwe is not None else None
    return FAMILY_OF.get(int(m.group(1)), "other") if m else "other"


def _code(r: dict) -> str | None:
    sn = (r.get("case") or {}).get("snippets") or []
    return sn[0].get("code", "").strip() if sn else None


def drop_conflicts(rows: list[dict]) -> tuple[list[dict], dict]:
    """Rule 1, per split, on the stripped target code: drop every patched/negative row whose code equals a
    vulnerable row's code, then keep the first row (input order) per identical (code, label). Pure."""
    vul = {(r.get("split"), _code(r)) for r in rows if r["label"] == "vulnerable" and _code(r) is not None}
    conflict = [r for r in rows if r["label"] != "vulnerable" and (r.get("split"), _code(r)) in vul]
    groups = {(r.get("split"), _code(r)) for r in conflict}
    conflict_ids = {id(r) for r in conflict}
    kept, seen, dups = [], set(), Counter()
    for r in rows:
        if id(r) in conflict_ids:
            continue
        key = (r.get("split"), _code(r), r["label"])
        if key[1] is not None and key in seen:
            dups[r["label"]] += 1
            continue
        seen.add(key)
        kept.append(r)
    return kept, {
        "rows_in": len(rows), "rows_kept": len(kept),
        "conflict_rows_dropped": dict(sorted(Counter(r["label"] for r in conflict).items())),
        "conflict_groups": len(groups),
        "conflict_group_rows": sum(1 for r in rows if (r.get("split"), _code(r)) in groups),
        "duplicate_rows_dropped": dict(sorted(dups.items())),
    }


def _cwe(v_row: dict, pair: dict) -> str | None:
    lead = v_row.get("lead") or {}
    if lead.get("cwe"):
        return lead["cwe"]
    from train.stage1 import primary_cwe
    return primary_cwe(pair)


def _raw_twins(rs: list[dict]) -> list[tuple[dict, dict | None]]:
    """(vulnerable row, its twin or None) in the raw Stage 1 order of one pair."""
    out = []
    for i, r in enumerate(rs):
        if r["label"] == "vulnerable":
            nxt = rs[i + 1] if i + 1 < len(rs) else None
            out.append((r, nxt if nxt is not None and nxt["label"] == "patched" else None))
    return out


def _fixes(train: list[dict], keep: set[int], pairs_by_id: dict, has_sink) -> tuple[list[dict], dict, dict]:
    by_pair: dict[str, list[dict]] = defaultdict(list)
    for r in train:
        by_pair[r["pair_id"]].append(r)
    fixes, no_target = [], 0
    twins = Counter(raw_twin_pairs=0, intact=0, twin_dropped_vulnerable_kept=0, vulnerable_dropped_twin_orphaned=0,
                    both_dropped=0)
    for pid in sorted(by_pair):
        rs = by_pair[pid]
        if pid not in pairs_by_id:
            raise KeyError(f"balance: pair {pid!r} is not in pairs.json")
        pair = pairs_by_id[pid]
        targets = []
        for v, p in _raw_twins(rs):
            if p is not None:
                twins["raw_twin_pairs"] += 1
                twins[{(True, True): "intact", (True, False): "twin_dropped_vulnerable_kept",
                       (False, True): "vulnerable_dropped_twin_orphaned",
                       (False, False): "both_dropped"}[(id(v) in keep, id(p) in keep)]] += 1
            if id(v) in keep:
                targets.append((v, p if p is not None and id(p) in keep else None))
        if not targets:
            no_target += 1
            continue
        v, p = next((t for t in targets if t[1] is not None), targets[0])
        negs = [r for r in rs if r["label"] == "negative" and id(r) in keep]
        n = next((r for r in negs if has_sink(r)), negs[0] if negs else None)
        cwe = _cwe(v, pair)
        fixes.append({"pair_id": pid, "v": v, "p": p, "n": n, "size": 1 + (p is not None) + (n is not None),
                      "tier": v.get("tier"), "language": pair.get("language"),
                      "repo": str(pair.get("repo_canonical") or pair.get("repo") or "").lower(),
                      "cwe": cwe, "family": family(cwe)})
    return fixes, {"train_pairs": len(by_pair), "pairs_without_target": no_target}, dict(twins)


def _fill(queues: dict[str, list[dict]], *, total: int, repo_cap: int, cwe_cap: int, family_cap: int) -> dict:
    queues = {k: list(v) for k, v in queues.items()}
    chosen, rows = [], 0
    lang_rows, repo_n, cwe_n, fam_n = Counter(), Counter(), Counter(), Counter()
    caps = ("repo_cap", "cwe_cap", "family_cap")
    dropped, dropped_rows, small_dropped = dict.fromkeys(caps, 0), dict.fromkeys(caps, 0), dict.fromkeys(caps, 0)

    def capped(f) -> str | None:
        if repo_n[f["repo"]] >= repo_cap:
            return "repo_cap"
        if f["cwe"] is not None and cwe_n[f["cwe"]] >= cwe_cap:
            return "cwe_cap"
        if f["family"] not in FAMILY_CAP_EXEMPT and fam_n[f["family"]] >= family_cap:
            return "family_cap"
        return None

    def take(f) -> None:
        nonlocal rows
        chosen.append(f)
        rows += f["size"]
        lang_rows[f["language"]] += f["size"]
        repo_n[f["repo"]] += 1
        fam_n[f["family"]] += 1
        if f["cwe"] is not None:
            cwe_n[f["cwe"]] += 1

    def next_queue():
        for first in (SMALL, FIRST_LANGUAGE):
            if queues.get(first):
                return first
        live = [k for k in queues if k not in (SMALL, FIRST_LANGUAGE) and queues[k]]
        return min(live, key=lambda k: (lang_rows[k], k)) if live else None

    while (q := next_queue()) is not None:          # main fill: caps refuse (counted), total ends it
        f = queues[q][0]
        why = capped(f)
        if why:
            dropped[why] += 1
            dropped_rows[why] += f["size"]
            if q == SMALL:
                small_dropped[why] += 1
            queues[q].pop(0)
            continue
        if rows + f["size"] > total:
            break
        take(queues[q].pop(0))
    while rows < total and (q := next_queue()) is not None:     # gap fill: smaller fixes that still fit
        f = queues[q].pop(0)
        if rows + f["size"] <= total and capped(f) is None:
            take(f)
    return {"chosen": chosen, "rows": rows, "dropped": dropped, "dropped_rows": dropped_rows,
            "small_dropped": small_dropped, "unused_after_total": sum(len(q) for q in queues.values())}


def _layout(fixes: list[dict], grad_accum: int, rng: random.Random) -> tuple[list[dict], int]:
    units = [{"v": f["v"], "p": f["p"], "n": f["n"]} for f in fixes]
    rng.shuffle(units)
    out: list[dict] = []
    twins_dropped = 0
    for i, u in enumerate(units):
        if u["p"] is not None and grad_accum > 1 and len(out) % grad_accum == grad_accum - 1:
            filler = None
            if u["n"] is not None:
                filler, u["n"] = u["n"], None
            else:
                for w in units[i + 1:]:
                    if w["n"] is not None:
                        filler, w["n"] = w["n"], None
                        break
                else:
                    for w in units[i + 1:]:
                        if w["v"] is not None and w["p"] is None:
                            filler, w["v"] = w["v"], None
                            break
            if filler is not None:
                out.append(filler)
            else:
                u["p"] = None
                twins_dropped += 1
        out.extend(r for r in (u["v"], u["p"], u["n"]) if r is not None)
    return out, twins_dropped


def select(rows: list[dict], pairs_by_id: dict, *, total: int = 7000, seed: int = 0, repo_cap: int = 15,
           cwe_share: float = 0.12, grad_accum: int = 16, family_share: float = 0.12, small_family: int = 150,
           annotate=None, fits=None) -> tuple[list[dict], dict]:
    """Ordered train rows (the original Stage 1 row dicts, unmodified) and a JSON-serialisable report of how they
    were chosen. See the module doc for the rules. `annotate` defaults to `orion.lm.sinks.annotate` (tests inject a
    fake). `fits(row) -> bool`, when given, removes failing rows from the pool after rule 1."""
    if annotate is None:
        from orion.lm.sinks import annotate
    sink_memo: dict[int, bool] = {}

    def has_sink(r: dict) -> bool:
        if id(r) not in sink_memo:
            sink_memo[id(r)] = annotate(r["case"]).get("sink_category") is not None
        return sink_memo[id(r)]

    train = [r for r in rows if r.get("split") == "train"]
    kept, rule1 = drop_conflicts(train)
    over = Counter()
    if fits is not None:
        fitting = []
        for r in kept:
            if fits(r):
                fitting.append(r)
            else:
                over[r["label"]] += 1
        kept = fitting
    keep = {id(r) for r in kept}
    fixes, pool, twins = _fixes(train, keep, pairs_by_id, has_sink)

    pool_cwe = Counter(_cwe(r, pairs_by_id[r["pair_id"]]) for r in kept if r["label"] == "vulnerable")
    pool_fam = Counter()
    for c, n in pool_cwe.items():
        pool_fam[family(c)] += n
    small = {fam for fam, n in pool_fam.items() if n < small_family}

    rng = random.Random(seed)
    keys = {f["pair_id"]: rng.random() for f in fixes}
    queues: dict[str, list[dict]] = defaultdict(list)
    for f in sorted(fixes, key=lambda f: (f["tier"] != "annotated", keys[f["pair_id"]], f["pair_id"])):
        queues[SMALL if f["family"] in small else f["language"]].append(f)

    estimate = len(fixes)
    while True:
        cap = math.floor(cwe_share * estimate + 1e-9)
        fam_cap = math.floor(family_share * estimate + 1e-9)
        res = _fill(queues, total=total, repo_cap=repo_cap, cwe_cap=cap, family_cap=fam_cap)
        if len(res["chosen"]) >= estimate:
            break
        estimate = len(res["chosen"])

    out, twins_dropped = _layout(res["chosen"], grad_accum, rng)
    chosen = res["chosen"]
    fix_of = {f["pair_id"]: f for f in chosen}
    by_label = Counter(r["label"] for r in out)
    sinks = Counter(r["label"] for r in out if has_sink(r))
    repo_fixes = Counter(f["repo"] for f in chosen)
    vuln_cwe = Counter(f["cwe"] for f in chosen)
    top_repo = min(repo_fixes.items(), key=lambda kv: (-kv[1], kv[0])) if repo_fixes else None
    pos = {id(r): i for i, r in enumerate(out)}
    twins_kept = sum(1 for f in chosen if f["p"] is not None and id(f["p"]) in pos)
    fam_rows = Counter(fix_of[r["pair_id"]]["family"] for r in out)
    fam_py_rows = Counter(fix_of[r["pair_id"]]["family"] for r in out if fix_of[r["pair_id"]]["language"] == "py")
    fam_fixes = Counter(f["family"] for f in chosen)
    fam_annot = Counter(f["family"] for f in chosen if f["tier"] == "annotated")
    families = {fam: {"pool_vulnerable_rows": pool_fam[fam], "small": fam in small,
                      "vulnerable_rows": fam_fixes[fam], "rows": fam_rows[fam], "python_rows": fam_py_rows[fam],
                      "annotated_share": round(fam_annot[fam] / fam_fixes[fam], 4) if fam_fixes[fam] else None}
                for fam in FAMILIES}
    small_fixes = [f for f in fixes if f["family"] in small]
    report = {
        "params": {"total": total, "seed": seed, "repo_cap": repo_cap, "cwe_share": cwe_share,
                   "grad_accum": grad_accum, "family_share": family_share, "small_family": small_family,
                   "fits": fits is not None},
        "rules": {
            "conflicts": "rule 1 on the train split, before units: a patched/negative row whose stripped "
                         "case.snippets[0].code equals a vulnerable row's is dropped; then the first row (Stage 1 "
                         "file order) per identical (code, label) is kept, other labels' rows untouched",
            "over_length": "when fits is given, rows failing fits(row) are removed after rule 1 (by label in "
                           "dropped_over_length)",
            "twin": "adjacency in the RAW Stage 1 order: the patched row directly after a vulnerable row of the "
                    "same pair; a twin is used only when both rows survive rule 1 and fits (a drop never makes a "
                    "new twin); an orphaned patched row is never used, a vulnerable row whose twin is gone counts "
                    "as twinless (see twins_after_drops)",
            "unit": "one fix = first surviving vulnerable row that has a surviving twin (else the first surviving "
                    "vulnerable row) + its twin + the first surviving negative with a sink line after "
                    "orion.lm.sinks.annotate (else the first surviving negative)",
            "families": f"FAMILY_OF maps CWE ids to {len(FAMILIES)} families, unknown/missing -> other; CSRF (352) "
                        f"and CWE-1385 are auth/session (both ride on the victim's session); a family with < "
                        f"{small_family} vulnerable rows in the train pool after rule 1 (before sampling) is small "
                        f"and all its fixes go first, still under the repo and per-CWE caps",
            "language": "after the small families: every py fix, then js/java one fix at a time to the language "
                        "with fewer rows",
            "caps": f"repo: <= {repo_cap} fixes per lowercased repo_canonical; cwe: <= floor({cwe_share} x final "
                    f"vulnerable rows) per lead CWE (None exempt); family: <= floor({family_share} x final "
                    f"vulnerable rows) per family except {sorted(FAMILY_CAP_EXEMPT)} (FAMILY_CAP_EXEMPT: 'other' is ~100 "
                    f"unrelated CWEs, each still under the per-CWE cap); checked repo, cwe, family; annotated fixes "
                    f"first, then seeded random, so annotated win when a cap or the total forces a choice",
            "order": f"seeded unit shuffle; a vulnerable row and its twin never straddle a {grad_accum}-row step "
                     f"(a single row is put in front: own negative, a later unit's negative, a later twinless "
                     f"vulnerable row; else the twin is dropped)",
        },
        "requested": total, "rows": len(out), "shortfall": max(total - len(out), 0), "fixes": len(chosen),
        "rule1_train": rule1,
        "dropped_over_length": dict(sorted(over.items())),
        "twins_after_drops": twins,
        "pool": {**pool, "fixes_available": len(fixes),
                 "fixes_available_by_language": dict(sorted(Counter(f["language"] for f in fixes).items()))},
        "counts": {
            "label": dict(sorted(by_label.items())),
            "language": dict(sorted(Counter(fix_of[r["pair_id"]]["language"] for r in out).items())),
            "fixes_by_language": dict(sorted(Counter(f["language"] for f in chosen).items())),
            "tier": dict(sorted(Counter(r.get("tier") for r in out).items())),
            "cwe_top15": [[c, n] for c, n in sorted(vuln_cwe.items(), key=lambda kv: (-kv[1], str(kv[0])))[:15]],
        },
        "families": families,
        "other_cwes": [[c, n] for c, n in sorted(pool_cwe.items(), key=lambda kv: (-kv[1], str(kv[0])))
                       if family(c) == "other"],
        "small_family_fixes": {"available": len(small_fixes),
                               "taken": sum(1 for f in chosen if f["family"] in small),
                               "dropped": res["small_dropped"]},
        "cwe_cap": cap, "family_cap": fam_cap,
        "repos_used": len(repo_fixes),
        "biggest_repo": {"repo": top_repo[0], "fixes": top_repo[1]} if top_repo else None,
        "dropped": res["dropped"],
        "dropped_rows": res["dropped_rows"],
        "unused_after_total": res["unused_after_total"],
        "sink_present": dict(sorted(sinks.items())),
        "sink_share": {lab: round(sinks[lab] / n, 4) for lab, n in sorted(by_label.items())},
        "twin_pairs_kept": twins_kept,
        "twins_dropped_for_layout": twins_dropped,
        "rows_in_partial_last_step": len(out) % grad_accum if grad_accum > 0 else 0,
    }
    return out, report
