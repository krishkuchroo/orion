_SUPPORTED = {"js", "ts", "py", "java"}
MAX_FIX_FILES = 10   # a localized fix: at most this many non-test files (dataset rule)
_COMMIT_STATUS = {"commit_missing": "commit_missing", "error": "commit_fetch_error",
                  "pending": "commit_not_fetched"}


def load_candidates(path: str) -> list[dict]:
    rows = []
    header = None
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if header is None:
                header = parts
                continue
            rows.append(dict(zip(header, parts)))
    return rows


def _le(date_a: str, cutoff: str) -> bool:
    return bool(date_a) and date_a <= cutoff


def _exclusion(row: dict) -> str | None:
    """First row-driven exclusion for a mined row (eval.dataset.mine); each rule fires only when
    its key is present, so hand-made TSV rows classify exactly as before."""
    if row.get("training_repo"):
        return f"training_repo: {row['training_repo']}"
    shas = row.get("fix_shas")
    if shas is not None and len(shas) > 1:
        return f"multi_commit_fix: {len(shas)} fix commits"
    if row.get("shared_fix_with"):
        return f"bundled_fix: the fix commit also fixes {', '.join(row['shared_fix_with'])}"
    status = row.get("enrich_status")
    if status is not None and status != "ok":
        return _COMMIT_STATUS.get(status, f"commit_{status}")
    if row.get("files_truncated"):
        return "files_truncated: GitHub paginated the fix commit's file list (>300 files)"
    n = row.get("n_files")
    if n is not None and n > MAX_FIX_FILES:
        return f"n_files {n} > {MAX_FIX_FILES}"
    return None


def classify(row: dict, *, cutoff: str = "2026-05-31") -> tuple[str, list[str]]:
    status = row.get("status", "")
    if status.startswith("excluded:"):
        return "excluded", [status]
    excluded = _exclusion(row)
    if excluded:
        return "excluded", [excluded]
    if row.get("lang") not in _SUPPORTED:
        return "excluded", [f"unsupported language: {row.get('lang')}"]
    if row.get("submodule_paths"):
        return "excluded", [f"submodule: the fix touches {', '.join(row['submodule_paths'])}"]
    if row.get("submodule_check") == "error":
        return "excluded", ["submodule_check_error: .gitmodules at the fix commit could not be read"]
    if status.startswith("control:"):
        return "control", [status]
    for k in ("advisory_published", "fix_commit_date"):
        if k in row and row[k] is None:          # a mined row whose date is unknown is never headline
            return "excluded", [f"{k} missing"]
    reasons = []
    if _le(row.get("advisory_published", ""), cutoff):
        reasons.append(f"advisory_published {row.get('advisory_published')} <= {cutoff}")
    if _le(row.get("fix_commit_date", ""), cutoff):
        reasons.append(f"fix_commit_date {row.get('fix_commit_date')} <= {cutoff}")
    if _le(row.get("advisory_first_public") or "", cutoff):
        basis = row.get("advisory_first_public_basis")
        reasons.append(f"advisory_first_public {row['advisory_first_public']} <= {cutoff}"
                       + (f" ({basis})" if basis else ""))
    if reasons:
        return "control", reasons
    loc = str(row.get("loc_first_party") or "")
    if loc.isdigit() and int(loc) > 1_000_000:
        return "scale", [f"loc {loc} > 1000000"]
    return "headline", ["passes all rules"]
