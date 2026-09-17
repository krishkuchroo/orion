import json
import subprocess

_TEST_MARKERS = ("/test/", "/tests/", ".test.", "_test.", "spec.")


def _default_run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def _is_test(path: str) -> bool:
    p = "/" + path
    return any(m in p for m in _TEST_MARKERS)


def commit_meta(repo: str, sha: str, *, run=_default_run) -> dict:
    raw = run(["gh", "api", f"repos/{repo}/commits/{sha}"])
    data = json.loads(raw)
    date = data["commit"]["author"]["date"][:10]
    files = [f["filename"] for f in data.get("files", []) if not _is_test(f["filename"])]
    return {"fix_commit_date": date, "files": files, "n_files": len(files)}


def enrich_all(candidates: list[dict], *, run=_default_run) -> list[dict]:
    out = []
    for row in candidates:
        r = dict(row)
        try:
            m = commit_meta(row["repo"], row["fix_commit"], run=run)
            r["fix_commit_date"] = m["fix_commit_date"]
            r["n_files"] = m["n_files"]
        except Exception as e:
            r["fix_commit_date"] = ""
            r["n_files"] = None
            r["enrich_error"] = str(e)
        out.append(r)
    return out
