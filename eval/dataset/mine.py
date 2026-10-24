"""Test-set miner: post-cutoff OSV advisories -> one-commit fix pairs -> manifest v2 skeleton rows.

The test set comes from the SAME OSV exports (raw/osv-{npm,pypi,maven}/all.zip) that built the
training leak set (``train.sources.post_cutoff``), with the opposite date filter, so every repo a
test advisory names was kept out of training by construction (``split_repos`` re-checks it).

Steps (``mine_testset`` runs them; GitHub objects are cached and resumable via ``train.enrich_gh``):

1. ``candidates``: advisories published strictly after the cutoff with a GitHub fix commit and a
   dataflow (``sources.DATAFLOW_CWES``) or access-control (CWE-284/285/862/863) weakness.
2. GitHub: each fix commit (parents, files, dates, canonical repo) -> ``fill_commit``; for a
   merge-commit fix, the compare ``parents[0]...merge`` dates the commits it brings in
   (``apply_merge_compare``: the earliest of them is the fix date).
3. ``assess``: training checks + ``check.classify``; ``.gitmodules`` at every otherwise-passing
   fix commit is read, and a fix that touches a submodule is excluded.
4. ``select``: headline rows, at most ``max_per_repo`` per (repo, kind), earliest advisories first.
5. ``eval/dataset/manifest.json`` (selected rows) + ``testset_candidates.json`` (every candidate
   with its tier and reasons).

Nothing is estimated: a value OSV or GitHub does not give stays None. LOC is not measured here;
the scale tier is decided by the build pre-check (Task F2). Answer-key fields stay empty until
E5 runs on real builds and a human labels them.

    ./.venv/bin/python -I eval/dataset/mine.py [--raw RAW] [--cache CACHE] 2> mine.log > tables.md
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone

if __package__ in (None, ""):  # run as a script under `python -I`: put the repo root on sys.path
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval import manifest  # noqa: E402
from eval.dataset import check  # noqa: E402
from train import enrich_gh, sources  # noqa: E402
from train.mine import DEFAULT_RAW, OSV_ZIPS  # noqa: E402

ACCESS_CONTROL_CWES = frozenset({284, 285, 862, 863})
KINDS = ("dataflow", "access_control")

# first-reason kinds in check order (tier, reason_kind), for the funnel table
FUNNEL_ORDER = (("excluded", "training_repo"), ("excluded", "training_pair"), ("excluded", "multi_commit_fix"),
                ("excluded", "bundled_fix"), ("excluded", "commit_missing"), ("excluded", "commit_fetch_error"),
                ("excluded", "commit_not_fetched"), ("excluded", "files_truncated"), ("excluded", "n_files"),
                ("excluded", "unsupported language"), ("excluded", "submodule"),
                ("excluded", "submodule_check_error"), ("excluded", "advisory_published"),
                ("excluded", "fix_commit_date"), ("excluded", "parent_missing"),
                ("control", "advisory_published"), ("control", "fix_commit_date"),
                ("control", "advisory_first_public"), ("scale", "loc"))


# ---- kinds ----------------------------------------------------------------------------------------

def _cwe_ids(cwe) -> set[int]:
    vals = cwe.split(",") if isinstance(cwe, str) else (cwe or [])
    return {int(c[4:]) for c in (sources.norm_cwe(v) for v in vals) if c}


def kind_of(cwe, *, cwes=sources.DATAFLOW_CWES, access_cwes=ACCESS_CONTROL_CWES) -> str | None:
    """"dataflow" if any CWE is a dataflow one, else "access_control" if any is, else None."""
    ids = _cwe_ids(cwe)
    return "dataflow" if ids & cwes else "access_control" if ids & access_cwes else None


def split_by_kind(cands) -> tuple[list[dict], list[dict]]:
    kinds = [c.get("kind") or kind_of(c.get("cwe")) for c in cands]
    return ([c for c, k in zip(cands, kinds) if k == "dataflow"],
            [c for c, k in zip(cands, kinds) if k == "access_control"])


# ---- candidates from the OSV exports --------------------------------------------------------------

def _ecosystem(path: str) -> str | None:
    m = re.fullmatch(r"osv-([a-z]+)", os.path.basename(os.path.dirname(os.path.abspath(path))))
    return m.group(1) if m else None


def _record_extras(zips, want: set[str]) -> dict[str, tuple[str | None, list[str]]]:
    """source_id -> (NVD publication date, the CWEs in the advisory's own order) for ``want``
    (``database_specific.nvd_published_at`` / ``cwe_ids``; osv_pairs sorts its CWE list)."""
    out: dict[str, tuple[str | None, list[str]]] = {}
    for path in zips:
        for name, z in sources._osv_records(path):
            sid = name[:-len(".json")]
            if sid in want and sid not in out:
                ds = json.loads(z.read(name)).get("database_specific") or {}
                order = list(dict.fromkeys(c for c in map(sources.norm_cwe, ds.get("cwe_ids") or []) if c))
                out[sid] = (sources._date(ds.get("nvd_published_at")), order)
    return out


def qualifying_cwe(cwes, kind: str, *, dataflow=sources.DATAFLOW_CWES,
                   access=ACCESS_CONTROL_CWES) -> tuple[str | None, str | None]:
    """(cwe, basis): the first CWE in ``cwes`` (advisory order) that is in ``kind``'s set, and
    "only_qualifying" or "first_of_<n>_qualifying". (None, None) when none qualifies."""
    pool = dataflow if kind == "dataflow" else access if kind == "access_control" else frozenset()
    hits = [c for c in cwes if _cwe_ids([c]) & pool]
    if not hits:
        return None, None
    return hits[0], "only_qualifying" if len(hits) == 1 else f"first_of_{len(hits)}_qualifying"


def _same_vuln(a: dict, b: dict) -> bool:
    return bool((set(a["aliases"]) | {a["id"]}) & (set(b["aliases"]) | {b["id"]}))


def _shared_with(r: dict, by_repo: dict) -> list[str]:
    """Ids of OTHER advisories (any date, any CWE) whose fix links name one of r's fix commits."""
    out = set()
    for s in r["fix_shas"]:
        for t, o in by_repo.get(r["repo"], ()):
            if (s.startswith(t) or t.startswith(s)) and o["source_id"] != r["source_id"] and not _same_vuln(r, o):
                out.add(o["id"])
    return sorted(out)


def _by_date(r: dict):
    return (r.get("advisory_published") or "9999", r["id"])


def cap_per_repo(rows, max_per_repo, *, repo=lambda r: r["repo"]) -> tuple[list[dict], list[dict]]:
    """(kept, dropped), both ordered by advisory date: the ``max_per_repo`` earliest-published rows
    of each (repo, kind); ties by id. ``None`` keeps everything."""
    order = sorted(rows, key=_by_date)
    if max_per_repo is None:
        return order, []
    seen, kept, dropped = Counter(), [], []
    for r in order:
        k = (repo(r), r.get("kind") or kind_of(r.get("cwe")))
        (kept if seen[k] < max_per_repo else dropped).append(r)
        seen[k] += 1
    return kept, dropped


def candidates(osv_zip, *, cutoff: str = sources.CUTOFF, cwes=sources.DATAFLOW_CWES,
               access_cwes=ACCESS_CONTROL_CWES, max_per_repo: int | None = 2, stats: dict | None = None) -> list[dict]:
    """Advisories published strictly after ``cutoff`` with a GitHub fix commit whose CWE is a
    dataflow (``cwes``) or access-control (``access_cwes``) one, ordered by advisory date.

    ``osv_zip`` is one export or a list (an advisory listed in several is kept once; one CVE with
    several advisory records is kept once, GHSA first). Each candidate carries every fix commit the
    advisory links (``fix_shas``), ``shared_fix_with`` (other advisories linking the same commit),
    ``advisory_first_public``: the earliest of its own date, any alias's OSV date and its NVD
    date; ``cwes`` (every listed CWE, advisory order), ``cwe`` (the one that qualified it for its
    kind, ``qualifying_cwe``) and ``cwe_basis``. ``max_per_repo`` keeps the earliest advisories per (raw repo, kind); ``None`` keeps all
    (the mining run caps after the tier rules instead, see ``select``). ``stats`` gets the funnel.
    """
    zips = [osv_zip] if isinstance(osv_zip, str) else list(osv_zip)
    st = stats if stats is not None else {}
    rows, seen = [], set()
    for path in zips:
        zst: dict = {}
        for r in sources.osv_pairs(path, ecosystem=_ecosystem(path), stats=zst):
            if r["source_id"] not in seen:
                seen.add(r["source_id"])
                rows.append(r)
        for k in ("skipped_malware", "skipped_withdrawn"):
            st[k] = st.get(k, 0) + zst.get(k, 0)
    st["advisories"] = len(rows)
    st["advisory_date_missing"] = sum(1 for r in rows if not r["advisory_published"])
    st["latest_advisory_published"] = max((r["advisory_published"] for r in rows if r["advisory_published"]),
                                          default=None)
    post = [r for r in rows if r["advisory_published"] and r["advisory_published"] > cutoff]
    st["post_cutoff"] = len(post)
    linked = [r for r in post if r["fix_sha"] and r["repo"]]
    st["github_fix_commit"] = len(linked)
    st["pr_link_only"] = sum(1 for r in post if not r["fix_sha"] and r["fix_pr"])
    st["no_github_fix_link"] = len(post) - len(linked) - st["pr_link_only"]
    kinds = {r["source_id"]: kind_of(r["cwe"], cwes=cwes, access_cwes=access_cwes) for r in linked}
    for k in KINDS:
        st[k] = sum(1 for v in kinds.values() if v == k)
    st["no_cwe"] = sum(1 for r in linked if not r["cwe"])
    st["other_cwe"] = len(linked) - st["dataflow"] - st["access_control"] - st["no_cwe"]
    picked = [r for r in linked if kinds[r["source_id"]]]

    first_dates = sources.advisory_date_index(rows)
    extras = _record_extras(zips, {r["source_id"] for r in picked})
    by_repo: dict = {}
    for r in rows:
        for s in r["fix_shas"]:
            by_repo.setdefault(r["repo"], []).append((s, r))
    out, by_id = [], {}
    for r in sorted(picked, key=lambda r: (not r["source_id"].startswith("GHSA-"), r["source_id"])):
        if r["id"] in by_id:
            by_id[r["id"]]["merged_source_ids"].append(r["source_id"])
            continue
        nv, order = extras.get(r["source_id"], (None, []))
        listed = order + [c for c in r["cwe"] if c not in order]     # advisory order; osv_pairs' set
        cwe, cwe_basis = qualifying_cwe(listed, kinds[r["source_id"]], dataflow=cwes, access=access_cwes)
        first, basis = min([(r["advisory_published"], "advisory")]
                           + [(first_dates[a], "osv_alias") for a in r["aliases"] if a in first_dates]
                           + ([(nv, "nvd_published_at")] if nv else []), key=lambda x: x[0])
        c = {"id": r["id"], "cve": r["cve"], "ghsa": r["ghsa"], "aliases": r["aliases"], "source": r["source"],
             "source_id": r["source_id"], "merged_source_ids": [], "repo": r["repo"], "cwe": cwe,
             "cwes": listed, "cwe_basis": cwe_basis, "kind": kinds[r["source_id"]], "fix_sha": r["fix_sha"], "fix_shas": r["fix_shas"],
             "shared_fix_with": _shared_with(r, by_repo), "advisory_published": r["advisory_published"],
             "nvd_published": nv, "advisory_first_public": first, "advisory_first_public_basis": basis,
             "language": r["language"], "language_basis": r["language_basis"], "packages": r["packages"],
             "reviewed": r.get("reviewed"), "enrich_status": "pending", "enrich_basis": None}
        by_id[r["id"]] = c
        out.append(c)
    st["duplicate_id_merged"] = len(picked) - len(out)
    kept, dropped = cap_per_repo(out, max_per_repo)
    if max_per_repo is not None:
        st["beyond_repo_cap"] = len(dropped)
    return kept


# ---- GitHub facts -----------------------------------------------------------------------------------

def fill_commit(c: dict, rec: dict | None, *, canonical: str | None = None) -> dict:
    """Copy of candidate ``c`` with its fix commit's GitHub record applied: full sha, parents,
    fix_commit_date (the EARLIER of author and committer date), non-test ``fix_files`` and their
    count, and the language of those files (``language_basis = "fix_files"``; the ecosystem's
    language is kept as ``ecosystem_language``). A truncated file list leaves counts and language
    None. ``canonical`` names the repo when the record does not (e.g. the commit is missing)."""
    c = dict(c)
    c.setdefault("ecosystem_language", c.get("language"))
    status = rec.get("status") if rec else "pending"
    c["enrich_status"] = status
    canon = (rec or {}).get("repo_canonical") or canonical
    if canon:
        c["repo_canonical"] = canon
    if status != "ok":
        return c
    files = rec.get("files") or []
    truncated = bool(rec.get("truncated"))
    dates = [d for d in (rec.get("author_date"), rec.get("committer_date")) if d]
    non_test = [f for f in files if not sources._is_test(f)]
    lang = None if truncated else sources.language_from_files(files)
    c.update(fix_sha_full=rec.get("sha_full"), parents=rec.get("parents") or [],
             author_date=rec.get("author_date"), committer_date=rec.get("committer_date"),
             fix_commit_date=min(dates) if dates else None, fix_commit_date_basis="fix_commit",
             files_truncated=truncated,
             language=lang, language_basis="fix_files" if lang else None,
             n_files=None if truncated else len(non_test), n_files_total=None if truncated else len(files),
             fix_files=None if truncated else non_test)
    return c


def compare_key(repo: str, base: str, head: str) -> str:
    return f"compare:{repo}@{base}...{head}"


def fetch_compare(client: enrich_gh.GitHub, repo: str, base: str, head: str) -> dict:
    """The commits ``head`` brings in over ``base``: ``GET /repos/{repo}/compare/{base}...{head}``.
    For a merge fix with base = its first parent this is the merged branch plus the merge itself,
    and ``files`` is the vulnerable->patched diff. ok (commits with UTC dates, ``truncated`` when
    GitHub returned fewer commits than ``total_commits``) or error."""
    status, _, data = client.request(f"/repos/{repo}/compare/{base}...{head}")
    rec = {"key": compare_key(repo, base, head), "kind": "compare", "repo": repo, "base": base, "head": head,
           "http_status": status, "fetched_at": enrich_gh._now()}
    if status == 200 and isinstance(data, dict) and isinstance(data.get("commits"), list):
        commits = [{"sha": x.get("sha"),
                    "author_date": sources._date(((x.get("commit") or {}).get("author") or {}).get("date")),
                    "committer_date": sources._date(((x.get("commit") or {}).get("committer") or {}).get("date"))}
                   for x in data["commits"]]
        total = data.get("total_commits")
        rec.update(status="ok", total_commits=total, commits=commits,
                   truncated=not isinstance(total, int) or total > len(commits),
                   files=[f.get("filename") for f in data.get("files") or []])
    else:
        rec["status"] = "error"
    return rec


def apply_merge_compare(c: dict, rec: dict | None) -> dict:
    """Copy of a merge-commit fix ``c`` whose ``fix_commit_date`` is the EARLIEST author/committer
    date among the commits the merge brings in (``rec`` from ``fetch_compare``; the merge's own
    date is kept as ``fix_commit_date_merge``). A failed or truncated compare leaves the date None
    (never headline). ``merge_compare_files_match``: the compare's non-test files equal ``fix_files``."""
    c = dict(c, fix_commit_date_merge=c.get("fix_commit_date"))
    if not rec or rec.get("status") != "ok" or rec.get("truncated"):
        c["fix_commit_date"] = None
        c["fix_commit_date_basis"] = "merge_compare_truncated" if rec and rec.get("status") == "ok" \
            else "merge_compare_error"
        return c
    dates = [d for x in rec["commits"] for d in (x.get("author_date"), x.get("committer_date")) if d]
    dates += [c["fix_commit_date"]] if c.get("fix_commit_date") else []
    c.update(fix_commit_date=min(dates) if dates else None, fix_commit_date_basis="merge_compare",
             merge_commits_brought_in=len(rec["commits"]),
             merge_compare_files_match=sorted(f for f in rec.get("files") or [] if not sources._is_test(f))
             == sorted(c.get("fix_files") or []))
    return c


_SUBMODULE_PATH = re.compile(r"^\s*path\s*=\s*(.+?)\s*$", re.M)


def parse_gitmodules(text: str) -> list[str]:
    return [p.strip('"').rstrip("/") for p in _SUBMODULE_PATH.findall(text or "")]


def submodule_hits(files, paths) -> list[str]:
    """The changed paths that are a submodule or lie inside one."""
    return [f for f in files or [] if any(f == p or f.startswith(p + "/") for p in paths)]


def gitmodules_key(repo: str, sha: str) -> str:
    return f"gitmodules:{repo}@{sha}"


def fetch_gitmodules(client: enrich_gh.GitHub, repo: str, sha: str) -> dict:
    """``.gitmodules`` at ``sha`` via the contents API: ok + paths, ok + absent (404), or error."""
    status, _, data = client.request(f"/repos/{repo}/contents/.gitmodules?ref={sha}")
    rec = {"key": gitmodules_key(repo, sha), "kind": "gitmodules", "repo": repo, "sha": sha,
           "http_status": status, "fetched_at": enrich_gh._now()}
    if status == 200 and isinstance(data, dict) and data.get("encoding") == "base64":
        text = base64.b64decode(data.get("content") or "").decode("utf-8", "replace")
        rec.update(status="ok", present=True, paths=parse_gitmodules(text))
    elif status == 404:
        rec.update(status="ok", present=False, paths=[])
    else:
        rec["status"] = "error"
    return rec


# ---- tiers, commit pairs, manifest rows -------------------------------------------------------------

def classify_candidate(c: dict, *, cutoff: str = sources.CUTOFF) -> tuple[str, list[str]]:
    """``check.classify`` on a mined candidate (its ``language`` is check's ``lang``)."""
    return check.classify(dict(c, lang=c.get("language")), cutoff=cutoff)


def _norm(out) -> tuple[str, list[str]]:
    if isinstance(out, tuple):
        return out[0], list(out[1])
    return out, []


def _training_repo(c: dict, trained: set[str]) -> str | None:
    return next((n.lower() for n in (c.get("repo"), c.get("repo_canonical")) if n and n.lower() in trained), None)


def _training_pair(c: dict, splits: dict) -> str | None:
    return next((f"{a} ({splits[a]})" for a in [c["id"], *(c.get("aliases") or [])] if a in splits), None)


def assess(cands, *, splits, split_repos, classify, parent) -> list[dict]:
    """Every candidate (copied) with ``kind``, ``tier``, ``reasons`` and its commit pair.

    ``classify(c)`` returns a tier or (tier, reasons). A repo in ``split_repos`` (raw or canonical
    name) or an id/alias in ``splits`` is excluded whatever ``classify`` says. For a row that is
    not excluded, ``parent(repo, fix_sha)`` (raw repo and sha as the advisory gives them) names the
    vulnerable commit; the patched commit is the fix's full sha. No parent -> ``parent_missing``."""
    trained = {r.lower() for r in split_repos or ()}
    out = []
    for c in cands:
        a = dict(c)
        a["kind"] = c.get("kind") or kind_of(c.get("cwe"))
        a["training_repo"] = _training_repo(a, trained)
        tier, reasons = _norm(classify(a))
        pair = _training_pair(a, splits or {})
        if a["training_repo"]:
            tier, reasons = "excluded", [f"training_repo: {a['training_repo']}"]
        elif pair:
            tier, reasons = "excluded", [f"training_pair: {pair}"]
        a["vulnerable_commit"] = a["patched_commit"] = None
        if tier != "excluded":
            vuln = parent(a["repo"], a["fix_sha"])
            if vuln:
                a["vulnerable_commit"], a["patched_commit"] = vuln, a.get("fix_sha_full") or a["fix_sha"]
            else:
                tier, reasons = "excluded", ["parent_missing"]
        a["tier"], a["reasons"] = tier, reasons
        out.append(a)
    return out


def select(assessed, *, max_per_repo: int | None = 2) -> tuple[list[dict], list[dict]]:
    """(selected, beyond_cap): headline rows, at most ``max_per_repo`` per (canonical repo, kind)."""
    head = [a for a in assessed if a["tier"] == "headline"]
    return cap_per_repo(head, max_per_repo, repo=lambda a: a.get("repo_canonical") or a["repo"])


def manifest_row(a: dict) -> dict:
    """Manifest-v2 skeleton row; answer-key fields stay empty/None until E5 + labeling."""
    repo = a.get("repo_canonical") or a["repo"]
    row = {"id": a["id"], "cve": a.get("cve"), "ghsa": a.get("ghsa"), "repo": repo,
           "repo_url": f"https://github.com/{repo}"}
    if repo != a["repo"]:
        row["repo_raw"] = a["repo"]
    row.update(language=a.get("language"), cwe=a["cwe"], cwes=a.get("cwes") or [a["cwe"]],
               cwe_basis=a.get("cwe_basis"), kind=a["kind"], tier=a["tier"], vulnerable_commit=a["vulnerable_commit"],
               patched_commit=a["patched_commit"], advisory_published=a.get("advisory_published"),
               fix_commit_date=a.get("fix_commit_date"), fix_commit_date_basis=a.get("fix_commit_date_basis"),
               fix_files=a.get("fix_files"), n_files=a.get("n_files"),
               loc_first_party=None, fix_sites=[], sink_or_protected_operation=None, accepted_entry_points=[],
               entry_evidence=None, guard=None, labelers=[], agreement=None, graph_missed=None)
    return row


def to_manifest_rows(cands, *, splits, split_repos, classify, parent, max_per_repo: int | None = 2) -> list[dict]:
    """Manifest rows for the candidates that pass every tier rule, ordered by advisory date."""
    kept, _ = select(assess(cands, splits=splits, split_repos=split_repos, classify=classify, parent=parent),
                     max_per_repo=max_per_repo)
    return [manifest_row(a) for a in kept]


def reason_kind(reason: str) -> str:
    return reason.split(":", 1)[0] if ":" in reason else reason.split(" ", 1)[0]


# ---- the mining run -------------------------------------------------------------------------------

def _export_info(zips) -> dict:
    files = []
    for p in zips:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        files.append({"file": os.path.join(os.path.basename(os.path.dirname(p)), os.path.basename(p)),
                      "bytes": os.path.getsize(p), "sha256": h.hexdigest(),
                      "mtime_utc": datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).isoformat(
                          timespec="seconds")})
    days = sorted({f["mtime_utc"][:10] for f in files})
    return {"date": days[0] if len(days) == 1 else days, "date_basis": "zip file mtime (UTC)", "files": files}


def _counts(rows, key) -> dict:
    c = Counter()
    for r in rows:
        for v in key(r):
            c[v] += 1
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def summarize(stats: dict, assessed, selected, beyond_cap, *, submodules: dict, merges: dict,
              max_per_repo: int | None) -> dict:
    per_kind = {}
    for k in KINDS:
        rows = [a for a in assessed if a["kind"] == k]
        first = Counter((a["tier"], reason_kind(a["reasons"][0]) if a["reasons"] else "")
                        for a in rows if a["tier"] != "headline")
        order = [x for x in FUNNEL_ORDER if x in first] + sorted(x for x in first if x not in FUNNEL_ORDER)
        sel = [a for a in selected if a["kind"] == k]
        head = [a for a in rows if a["tier"] == "headline"]
        per_kind[k] = {"candidates": len(rows), "tiers": dict(Counter(a["tier"] for a in rows)),
                       "first_reason": [[t, r, first[(t, r)]] for t, r in order],
                       "headline": len(head), "beyond_repo_cap": sum(1 for a in beyond_cap if a["kind"] == k),
                       "manifest": len(sel), "manifest_repos": len({a.get("repo_canonical") or a["repo"] for a in sel}),
                       "manifest_by_cwe": _counts(sel, lambda a: [a["cwe"]]),
                       "manifest_by_cwe_basis": _counts(sel, lambda a: [a.get("cwe_basis")]),
                       "manifest_listing_several_cwes": sum(1 for a in sel if len(a.get("cwes") or []) > 1),
                       "manifest_by_language": _counts(sel, lambda a: [a.get("language")]),
                       "headline_by_language": _counts(head, lambda a: [a.get("language")]),
                       "candidates_by_ecosystem_language": _counts(rows, lambda a: [a.get("ecosystem_language")]),
                       "manifest_fix_is_merge_commit": sum(1 for a in sel if len(a.get("parents") or []) > 1)}
    return {"funnel": stats, "merge_fix_check": merges, "submodule_check": submodules,
            "max_per_repo": max_per_repo, "by_kind": per_kind}


def mine_testset(zips, *, cache_path: str, splits: dict, split_repos, cutoff: str = sources.CUTOFF,
                 max_per_repo: int | None = 2, get=None, sleep=None, clock=None, log=print) -> tuple[list, list, dict]:
    """(selected rows, every assessed candidate, summary). GitHub is read through the cache;
    missing objects are fetched (``get`` defaults to the real API with the ``gh`` token)."""
    sleep, clock = sleep or time.sleep, clock or time.time
    stats: dict = {}
    cands = candidates(zips, cutoff=cutoff, max_per_repo=None, stats=stats)
    log(f"[mine] {len(cands)} candidates; fetching fix commits")
    get = get or enrich_gh.urllib_get(enrich_gh._token())
    enrich_gh.run(cands, cache_path, repos=sorted({c["repo"] for c in cands}), get=get, sleep=sleep, clock=clock,
                  log=log)
    cache = enrich_gh.Cache(cache_path)
    canon, _ = enrich_gh.canonical_repos(cache)

    def record(c):
        return cache.records.get(enrich_gh.commit_key(c["repo"], c["fix_sha"]))

    def parent(repo, sha):
        rec = cache.records.get(enrich_gh.commit_key(repo, sha)) or {}
        return (rec.get("parents") or [None])[0] if rec.get("status") == "ok" else None

    def classify(c):
        return classify_candidate(c, cutoff=cutoff)

    kw = dict(splits=splits, split_repos=split_repos, classify=classify, parent=parent)
    filled = [fill_commit(c, record(c), canonical=canon.get(c["repo"])) for c in cands]
    client = enrich_gh.GitHub(get, sleep=sleep, clock=clock, log=log)
    merges, fetched = {"merge_fixes": 0, "date_moved_earlier": 0, "errors": 0, "truncated": 0, "files_match": 0}, 0
    for i, c in enumerate(filled):                 # merge-commit fixes: date from the merged commits
        if c.get("enrich_status") != "ok" or len(c.get("parents") or []) < 2:
            continue
        repo = c.get("repo_canonical") or c["repo"]
        key = compare_key(repo, c["parents"][0], c["fix_sha_full"])
        if not cache.done(key):
            cache.add(fetch_compare(client, repo, c["parents"][0], c["fix_sha_full"]))
            fetched += 1
        filled[i] = m = apply_merge_compare(c, cache.records[key])
        merges["merge_fixes"] += 1
        merges["date_moved_earlier"] += bool(m["fix_commit_date"] and m["fix_commit_date"] < c["fix_commit_date"])
        merges["errors"] += m["fix_commit_date_basis"] == "merge_compare_error"
        merges["truncated"] += m["fix_commit_date_basis"] == "merge_compare_truncated"
        merges["files_match"] += bool(m.get("merge_compare_files_match"))
    log(f"[mine] merge-commit fixes: {merges}; compares fetched from GitHub this run: {fetched}")
    first = {a["id"]: a for a in assess(filled, **kw)}
    sub, fetched = {"checked": 0, "with_gitmodules": 0, "fix_touches_submodule": 0, "errors": 0}, 0
    for i, c in enumerate(filled):
        if first[c["id"]]["tier"] != "headline":
            continue
        repo, sha = c.get("repo_canonical") or c["repo"], c["fix_sha_full"]
        key = gitmodules_key(repo, sha)
        if not cache.done(key):
            cache.add(fetch_gitmodules(client, repo, sha))
            fetched += 1
        rec = cache.records[key]
        hits = submodule_hits((record(c) or {}).get("files"), rec.get("paths") or [])
        filled[i] = dict(c, submodule_check=rec["status"], submodule_paths=hits)
        sub["checked"] += 1
        sub["with_gitmodules"] += bool(rec.get("present"))
        sub["fix_touches_submodule"] += bool(hits)
        sub["errors"] += rec["status"] != "ok"
    log(f"[mine] submodule check: {sub}; .gitmodules fetched from GitHub this run: {fetched}")
    assessed = assess(filled, **kw)
    selected, beyond = select(assessed, max_per_repo=max_per_repo)
    chosen, capped = {a["id"] for a in selected}, {a["id"] for a in beyond}
    for a in assessed:
        a["selection"] = "manifest" if a["id"] in chosen else "beyond_repo_cap" if a["id"] in capped else None
    return selected, assessed, summarize(stats, assessed, selected, beyond, submodules=sub, merges=merges,
                                         max_per_repo=max_per_repo)


def tables_markdown(summary: dict) -> str:
    f = summary["funnel"]
    out = ["| Funnel stage | Count |", "|---|---|",
           f"| OSV advisories in the three exports (non-withdrawn, non-malware, unique) | {f['advisories']} |",
           f"| published after the cutoff | {f['post_cutoff']} |",
           f"| ... with a GitHub fix commit link | {f['github_fix_commit']} "
           f"(PR link only: {f['pr_link_only']}; no GitHub fix link: {f['no_github_fix_link']}) |",
           f"| ... in a dataflow CWE | {f['dataflow']} |",
           f"| ... in an access-control CWE (284/285/862/863) | {f['access_control']} |",
           f"| ... other CWE / no CWE | {f['other_cwe']} / {f['no_cwe']} |",
           f"| same CVE in several advisory records (merged) | {f['duplicate_id_merged']} |", ""]
    for k, d in summary["by_kind"].items():
        out += [f"**{k}** — {d['candidates']} candidates", "", "| Tier | First reason | Dropped |", "|---|---|---|"]
        out += [f"| {t} | {r} | {n} |" for t, r, n in d["first_reason"]]
        out += [f"| **headline** | passes every rule | **{d['headline']}** |",
                f"| headline beyond the per-repo cap | ({summary['max_per_repo']} per repo and kind) | "
                f"{d['beyond_repo_cap']} |",
                f"| **manifest rows** | in {d['manifest_repos']} repos | **{d['manifest']}** |", ""]
        for name in ("manifest_by_cwe", "manifest_by_cwe_basis", "manifest_by_language", "headline_by_language"):
            out.append(f"{name.replace('_', ' ')}: " + (", ".join(f"{a} {b}" for a, b in d[name].items()) or "none"))
        out += [f"manifest rows whose advisory lists several CWEs: {d['manifest_listing_several_cwes']}",
                f"manifest rows whose fix is a merge commit: {d['manifest_fix_is_merge_commit']}", ""]
    out.append(f"merge-commit fix check: {summary['merge_fix_check']}")
    out.append(f"submodule check: {summary['submodule_check']}")
    return "\n".join(out) + "\n"


def _dump(path: str, obj) -> None:
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=False)
        f.write("\n")


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--raw", default=DEFAULT_RAW)
    ap.add_argument("--cache", default=enrich_gh.DEFAULT_CACHE)
    ap.add_argument("--out", default="eval/dataset")
    ap.add_argument("--pairs", default="train/data/pairs.json")
    ap.add_argument("--splits", default="train/data/splits.json")
    ap.add_argument("--cutoff", default=sources.CUTOFF)
    ap.add_argument("--max-per-repo", type=int, default=2)
    args = ap.parse_args(argv)

    def log(*a):
        print(*a, file=sys.stderr, flush=True)

    zips = [os.path.join(args.raw, z) for z in OSV_ZIPS]
    with open(args.splits) as f:
        splits = json.load(f)["assignment"]
    split_repos = manifest.split_repos(args.pairs, args.splits)
    selected, assessed, summary = mine_testset(zips, cache_path=args.cache, splits=splits, split_repos=split_repos,
                                               cutoff=args.cutoff, max_per_repo=args.max_per_repo, log=log)
    source = {"osv_export": _export_info(zips), "cutoff": args.cutoff, "cutoff_rule": "strictly after",
              "max_per_repo": args.max_per_repo, "counts": summary}
    generated = datetime.now(timezone.utc).date().isoformat()
    data = {"version": 2, "generated": generated, "source": source, "repos": [manifest_row(a) for a in selected]}
    errs = manifest.validate(data, split_repos=split_repos)
    source["validate"] = {"split_repos": len(split_repos), "errors": errs}
    _dump(os.path.join(args.out, "manifest.json"), data)
    _dump(os.path.join(args.out, "testset_candidates.json"),
          {"generated": generated, "source": source, "candidates": assessed})
    log(f"[mine] manifest rows {len(selected)}; validate errors {len(errs)}")
    print(tables_markdown(summary) + f"\nvalidate: {len(errs)} errors against {len(split_repos)} training repos\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
