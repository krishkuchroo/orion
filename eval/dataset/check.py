_SUPPORTED = {"js", "ts", "py", "java"}


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


def classify(row: dict, *, cutoff: str = "2026-05-31") -> tuple[str, list[str]]:
    status = row.get("status", "")
    if status.startswith("excluded:"):
        return "excluded", [status]
    if row.get("lang") not in _SUPPORTED:
        return "excluded", [f"unsupported language: {row.get('lang')}"]
    if status.startswith("control:"):
        return "control", [status]
    reasons = []
    if _le(row.get("advisory_published", ""), cutoff):
        reasons.append(f"advisory_published {row.get('advisory_published')} <= {cutoff}")
    if _le(row.get("fix_commit_date", ""), cutoff):
        reasons.append(f"fix_commit_date {row.get('fix_commit_date')} <= {cutoff}")
    if reasons:
        return "control", reasons
    loc = row.get("loc_first_party", "")
    if loc.isdigit() and int(loc) > 1_000_000:
        return "scale", [f"loc {loc} > 1000000"]
    return "headline", ["passes all rules"]
