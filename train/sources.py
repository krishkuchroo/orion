"""Training-pair sources: every loader turns one real dataset into rows of one shape.

A row is one (advisory, fix commit) candidate. Nothing here is synthesised: a value the source does
not carry stays ``None`` (dates and file counts are filled later from GitHub by ``enrich_gh``, or
stay ``None`` and are counted under a "missing" reason by ``filters.keep``).

Row shape (all loaders)::

    id, source, source_id, cve, ghsa, aliases, repo ("owner/repo", lowercased, GitHub only),
    repo_url (raw, kept when not GitHub), fix_sha, fix_shas, fix_pr, vuln_sha, cwe, cwe_class,
    language ("js" = JS/TS family, "py", "java", other extension name, "mixed" or None),
    language_basis, advisory_published (YYYY-MM-DD), advisory_published_basis, packages,
    enrich_status ("pending" until enriched), fix_commit_date, n_files (non-test), n_files_total,
    n_files_lang

All downloaded files are parsed as data only; no code from a download is ever executed (the
CVEfixes SQL dump is tokenised by hand, never fed to sqlite; the MoreFixes pg_dump's COPY blocks are
split by hand, never loaded into Postgres).
"""
from __future__ import annotations

import csv
import glob
import gzip
import io
import json
import os
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone

from eval.dataset.enrich import _is_test  # same test-file rule as the eval's <=10-files check

CUTOFF = "2026-05-31"

# Injection / dataflow-shaped weaknesses (plan D1 list + close relatives); everything else is "other".
DATAFLOW_CWES = frozenset({22, 78, 79, 89, 94, 502, 611, 918, 1321,
                           77, 73, 23, 36, 943, 917, 1336, 643, 90, 113})
SUPPORTED_LANGUAGES = ("js", "py", "java")
ECOSYSTEM_LANG = {"npm": "js", "pypi": "py", "maven": "java"}

# Dedupe survivor order: hand-curated ready-made sets first, then reviewed advisories, then mined sets.
SOURCE_PRIORITY = ("cwe-bench-java", "openssf", "vul4j", "vulcan", "secbench-js",
                   "osv-maven", "osv-npm", "osv-pypi", "sap-kb", "javavulbench", "repopairbench",
                   "cvefixes", "crossvul", "morefixes", "pyvul")
# Per-pair location annotations a duplicate's survivor inherits (they matter later for locating the bug).
ANNOTATION_KEYS = ("weaknesses", "locations", "sink_location", "fix_methods", "source_sink", "vuln_methods",
                   "fix_file")

_SUPPORTED_EXT = {".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
                  ".mts": "js", ".cts": "js", ".py": "py", ".java": "java"}
_OTHER_CODE_EXT = {"c", "h", "cc", "cpp", "cxx", "hpp", "hh", "go", "rb", "php", "rs", "cs", "swift", "kt",
                   "kts", "scala", "m", "mm", "pl", "pm", "lua", "sh", "groovy", "ex", "exs", "erl", "hs",
                   "clj", "dart", "r", "jl", "vb", "f90", "pas", "ml", "coffee", "jsp", "asp", "aspx", "cfm",
                   "tcl", "sql", "vue", "svelte"}

_GH = re.compile(r"https?://(?:www\.)?github\.com/([^/\s?#]+)/([^/\s?#]+)", re.I)
_COMMIT = re.compile(r"https?://(?:www\.)?github\.com/([^/\s?#]+)/([^/\s?#]+)/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})\b", re.I)
_PR = re.compile(r"https?://(?:www\.)?github\.com/([^/\s?#]+)/([^/\s?#]+)/pull/(\d+)", re.I)
_NOT_OWNERS = {"advisories", "orgs", "users", "sponsors", "topics", "marketplace", "settings", "features",
               "about", "pricing", "site", "security", "collections", "explore", "notifications", "login"}
_SHA = re.compile(r"^[0-9a-f]{7,40}$")


# ---- small helpers ----------------------------------------------------------------------------

def norm_cwe(x) -> str | None:
    m = re.search(r"(\d+)", str(x)) if x is not None and not str(x).upper().startswith("NVD-") else None
    return f"CWE-{int(m.group(1))}" if m else None


def _cwes(values) -> list[str]:
    out = {c for c in (norm_cwe(v) for v in values or []) if c}
    return sorted(out, key=lambda c: int(c[4:]))


def cwe_class(cwes) -> str:
    ids = {int(c[4:]) for c in (norm_cwe(x) for x in cwes or []) if c}
    if not ids:
        return "unknown"
    return "dataflow" if ids & DATAFLOW_CWES else "other"


def _norm_repo(owner: str, name: str) -> str | None:
    name = re.sub(r"\.git$", "", name, flags=re.I)
    if not owner or not name or owner.lower() in _NOT_OWNERS:
        return None
    return f"{owner}/{name}".lower()


def github_repo(url: str | None) -> str | None:
    m = _GH.search(url or "")
    return _norm_repo(m.group(1), m.group(2)) if m else None


def file_lang(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    if ext in _SUPPORTED_EXT:
        return _SUPPORTED_EXT[ext]
    return ext[1:] if ext[1:] in _OTHER_CODE_EXT else None


def language_from_files(paths) -> str | None:
    fams = {file_lang(p) for p in paths or [] if not _is_test(p)} - {None}
    if not fams:
        return None
    return fams.pop() if len(fams) == 1 else "mixed"


def _date(s) -> str | None:
    """ISO-ish timestamp -> UTC YYYY-MM-DD (offsets converted); None stays None."""
    if not s or str(s).strip() in ("", "None", "NULL"):
        return None
    s = str(s).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.date().isoformat()
    except ValueError:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", s)
        return m.group(1) if m else None


def _row(source: str, source_id: str, *, aliases=(), repo=None, repo_url=None, fix_shas=(), fix_pr=None,
         vuln_sha=None, cwe=(), language=None, language_basis=None, advisory_published=None, packages=(),
         **extra) -> dict:
    ids = [a for a in dict.fromkeys([source_id, *aliases]) if a]
    cve = next((a for a in ids if a.upper().startswith("CVE-")), None)
    ghsa = next((a for a in ids if a.upper().startswith("GHSA-")), None)
    shas = [s.lower() for s in dict.fromkeys(fix_shas) if s and _SHA.match(s.lower())]
    cwes = _cwes(cwe)
    r = {"id": cve or ghsa or source_id, "source": source, "source_id": source_id, "cve": cve, "ghsa": ghsa,
         "aliases": sorted(set(ids)), "repo": repo, "repo_url": repo_url if repo is None else None,
         "fix_sha": shas[0] if shas else None, "fix_shas": shas, "fix_pr": fix_pr if not shas else None,
         "vuln_sha": vuln_sha.lower() if vuln_sha else None, "cwe": cwes, "cwe_class": cwe_class(cwes),
         "language": language, "language_basis": language_basis if language else None,
         "advisory_published": advisory_published,
         "advisory_published_basis": "source" if advisory_published else None,
         "packages": [list(p) for p in packages],
         "enrich_status": "pending", "enrich_basis": None, "fix_commit_date": None, "n_files": None,
         "n_files_total": None, "n_files_lang": None}
    r.update(extra)
    return r


def _bump(stats, key, n=1):
    if stats is not None:
        stats[key] = stats.get(key, 0) + n


# ---- OSV (GHSA + PYSEC) -------------------------------------------------------------------------

def _osv_records(osv_zip: str):
    with zipfile.ZipFile(osv_zip) as z:
        for name in z.namelist():
            if name.endswith(".json"):
                yield name, z


def _osv_fix(d: dict):
    """(repo, [shas], pr, non_github_url) in priority: GIT-range fixed > FIX-typed commit ref > other commit refs."""
    cands, non_gh = [], None
    for a in d.get("affected") or []:
        for rg in a.get("ranges") or []:
            if rg.get("type") != "GIT":
                continue
            repo = github_repo(rg.get("repo"))
            if repo is None:
                non_gh = non_gh or rg.get("repo")
                continue
            cands += [(repo, e["fixed"]) for e in rg.get("events") or [] if e.get("fixed")]
    refs = d.get("references") or []
    for typed in (True, False):
        for r in refs:
            if (r.get("type") == "FIX") != typed:
                continue
            m = _COMMIT.search(r.get("url", ""))
            if m and _norm_repo(m.group(1), m.group(2)):
                cands.append((_norm_repo(m.group(1), m.group(2)), m.group(3)))
    cands = [(repo, sha.lower()) for repo, sha in cands if _SHA.match(sha.lower())]
    if cands:
        repo = cands[0][0]
        return repo, [s for r, s in cands if r == repo], None, None
    for typed in (True, False):
        for r in refs:
            if (r.get("type") == "FIX") != typed:
                continue
            m = _PR.search(r.get("url", ""))
            if m and _norm_repo(m.group(1), m.group(2)):
                return _norm_repo(m.group(1), m.group(2)), [], int(m.group(3)), None
    return None, [], None, non_gh


def osv_pairs(osv_zip: str, *, ecosystem: str | None = None, stats: dict | None = None) -> list[dict]:
    """One row per non-withdrawn, non-malware OSV advisory (GHSA, PYSEC, ...) in an ecosystem export.

    Rows without a GitHub fix commit are kept with ``fix_sha=None`` so the funnel can count them.
    ``ecosystem`` (the export's own, e.g. "npm") labels advisories that list several ecosystems.
    """
    rows = []
    for name, z in _osv_records(osv_zip):
        if name.startswith("MAL-"):
            _bump(stats, "skipped_malware")
            continue
        d = json.loads(z.read(name))
        if d.get("withdrawn"):
            _bump(stats, "skipped_withdrawn")
            continue
        _bump(stats, f"records:{d['id'].split('-')[0]}")
        pkgs = [(a["package"].get("ecosystem", "").lower(), a["package"].get("name", "").lower())
                for a in d.get("affected") or [] if a.get("package")]
        ecos = [e for e, _ in pkgs]
        eco = (ecosystem.lower() if ecosystem and ecosystem.lower() in ecos else
               next((e for e in ecos if e in ECOSYSTEM_LANG), ecos[0] if ecos else ""))
        repo, shas, pr, non_gh = _osv_fix(d)
        ds = d.get("database_specific") or {}
        rows.append(_row(f"osv-{eco}", d["id"], aliases=d.get("aliases") or [], repo=repo, repo_url=non_gh,
                         fix_shas=shas, fix_pr=pr, cwe=ds.get("cwe_ids") or [],
                         language=ECOSYSTEM_LANG.get(eco, eco or None), language_basis="ecosystem",
                         advisory_published=_date(d.get("published")), packages=sorted(set(pkgs)),
                         reviewed=ds.get("github_reviewed")))
    return rows


def _repos_named(d: dict, *, fix_links_only: bool = False) -> set[str]:
    out = set()
    for r in d.get("references") or []:
        u = r.get("url") or ""
        if fix_links_only and not (_COMMIT.search(u) or _PR.search(u)):
            continue
        repo = github_repo(u)
        if repo:
            out.add(repo)
    for a in d.get("affected") or []:
        for rg in a.get("ranges") or []:
            repo = github_repo(rg.get("repo"))
            if repo:
                out.add(repo)
    return out


def post_cutoff(osv_zips, *, cutoff: str = CUTOFF) -> dict:
    """Leak sets from every advisory published on/after the cutoff (withdrawn ones included).

    ``repos``/``packages`` come from vulnerability advisories (GHSA, PYSEC, ...); malicious-package
    reports (MAL-*) are not vulnerability advisories and are reported separately (``malware_repos``).
    ``repos`` uses EVERY GitHub repo URL an advisory names (conservative); ``repos_fix_links`` is the
    narrower set named only by commit / PR / GIT-range links, kept for a sensitivity count.
    """
    if isinstance(osv_zips, str):
        osv_zips = [osv_zips]
    repos, packages, mal_repos, n, fix_repos = set(), set(), set(), 0, set()
    for path in osv_zips:
        for name, z in _osv_records(path):
            d = json.loads(z.read(name))
            pub = _date(d.get("published"))
            if not pub or pub < cutoff:
                continue
            if name.startswith("MAL-"):
                mal_repos |= _repos_named(d)
                continue
            n += 1
            repos |= _repos_named(d)
            fix_repos |= _repos_named(d, fix_links_only=True)
            packages |= {(a["package"].get("ecosystem", "").lower(), a["package"].get("name", "").lower())
                         for a in d.get("affected") or [] if a.get("package")}
    return {"repos": repos, "packages": packages, "malware_repos": mal_repos - repos, "n_advisories": n,
            "repos_fix_links": fix_repos}


def post_cutoff_repos(osv_zips, *, cutoff: str = CUTOFF) -> set[str]:
    return post_cutoff(osv_zips, cutoff=cutoff)["repos"]


# ---- ready-made pair sets -----------------------------------------------------------------------

def readymade(kind: str, path: str, *, stats: dict | None = None, advisory_dir: str | None = None) -> list[dict]:
    if kind == "cwe-bench-java":
        return _cwe_bench_java(path, advisory_dir)
    if kind == "openssf":
        return _openssf(path, stats)
    if kind == "vul4j":
        return _vul4j(path)
    raise ValueError(f"unknown ready-made source: {kind}")


def _csv_rows(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _cwe_bench_java(root: str, advisory_dir: str | None = None) -> list[dict]:
    """CWE-Bench-Java seed tables. Accepts the cwe-bench-java repo layout (data/*.csv + advisory/) and
    the newer iris-sast/iris ``data/`` layout (*.csv only; advisory JSONs optional via advisory_dir)."""
    data = os.path.join(root, "data") if os.path.exists(os.path.join(root, "data", "project_info.csv")) else root
    adv_dir = os.path.join(root, "advisory") if os.path.isdir(os.path.join(root, "advisory")) else advisory_dir
    has_fix_info = os.path.exists(os.path.join(data, "fix_info.csv"))
    # keyed by slug AND by CVE id: iris v2 spells some slugs differently across its files
    methods: dict[str, list] = {}
    for m in _csv_rows(os.path.join(data, "fix_info.csv")):
        item = {k: m.get(k) for k in ("commit", "file", "class", "method", "method_start", "method_end")}
        methods.setdefault(m["project_slug"], []).append(item)
        methods.setdefault(m.get("cve_id") or m.get("cve") or "", []).append(item)
    ss: dict[str, list] = {}
    for m in _csv_rows(os.path.join(data, "fix_info_source_sink.csv")):   # manually extracted (IRIS news)
        item = {"file": m.get("file"), "method": m.get("method"), "source": m.get("Source"),
                "source_line": m.get("Source Line"), "sink": m.get("Sink"), "sink_line": m.get("Sink Line")}
        ss.setdefault(m["project_slug"], []).append(item)
        ss.setdefault(m.get("cve_id") or "", []).append(item)
    rows = []
    for r in _csv_rows(os.path.join(data, "project_info.csv")):
        adv_path = os.path.join(adv_dir, f"{r['project_slug']}.json") if adv_dir else ""
        published, aliases = None, [r.get("advisory_id") or ""]
        if adv_path and os.path.exists(adv_path):
            with open(adv_path) as af:
                adv = json.load(af)
            published = _date(adv.get("published"))
            aliases += adv.get("aliases") or []
        fixes = [x.strip() for x in (r.get("fix_commit_ids") or "").split(";") if x.strip()]
        extra = {}
        if has_fix_info:
            extra["fix_methods"] = methods.get(r["project_slug"]) or methods.get(r["cve_id"]) or []
        if ss.get(r["project_slug"]) or ss.get(r["cve_id"]):
            extra["source_sink"] = ss.get(r["project_slug"]) or ss[r["cve_id"]]
        rows.append(_row("cwe-bench-java", r["project_slug"], aliases=[r["cve_id"], *aliases],
                         repo=_norm_repo(r["github_username"], r["github_repository_name"]),
                         fix_shas=fixes, vuln_sha=r.get("buggy_commit_id") or None, cwe=[r.get("cwe_id")],
                         language="java", language_basis="dataset", advisory_published=published, **extra))
    return rows


def _openssf(root: str, stats) -> list[dict]:
    rows = []
    for p in sorted(glob.glob(os.path.join(root, "CVEs", "*.json"))):
        with open(p) as f:
            d = json.load(f)
        if d.get("state") != "PUBLISHED":
            _bump(stats, f"skipped_state:{d.get('state')}")
            continue
        repo = github_repo(d.get("repository"))
        pre, post = d.get("prePatch") or {}, d.get("postPatch") or {}
        weak = [{"file": (w.get("location") or {}).get("file"), "line": (w.get("location") or {}).get("line"),
                 "explanation": w.get("explanation")} for w in pre.get("weaknesses") or []]
        rows.append(_row("openssf", d["CVE"], aliases=[d["CVE"]], repo=repo,
                         repo_url=d.get("repository") if repo is None else None,
                         fix_shas=[post.get("commit")], vuln_sha=pre.get("commit"), cwe=d.get("CWEs") or [],
                         language="js", language_basis="dataset", weaknesses=weak))
    return rows


def _vul4j(csv_path: str) -> list[dict]:
    rows = []
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            m = _COMMIT.search(r.get("human_patch") or "")
            cve = r.get("cve_id") if (r.get("cve_id") or "").upper().startswith("CVE-") else None
            rows.append(_row("vul4j", r["vul_id"], aliases=[cve],
                             repo=_norm_repo(m.group(1), m.group(2)) if m else None,
                             repo_url=None if m else r.get("human_patch"),
                             fix_shas=[m.group(3)] if m else [], cwe=[r.get("cwe_id")],
                             language="java", language_basis="dataset"))
    return rows


# ---- other mined datasets -----------------------------------------------------------------------

def _purl_pkg(purl: str):
    m = re.match(r"pkg:([^/]+)/(.+?)(?:@.*)?$", purl or "")
    if not m:
        return None
    typ, rest = m.group(1).lower(), m.group(2)
    if typ == "maven":
        return ("maven", rest.replace("/", ":").lower())
    return (typ, rest.lower())


def sap_kb(root: str) -> list[dict]:
    """SAP Project KB ``vulnerability-data`` branch: statements/<id>/statement.yaml (manually curated)."""
    import yaml  # PyYAML (present in the venv); safe_load only — never yaml.load on downloaded data

    rows = []
    for p in sorted(glob.glob(os.path.join(root, "statements", "*", "statement.yaml"))):
        with open(p) as f:
            d = yaml.safe_load(f) or {}
        vid = str(d.get("vulnerability_id") or os.path.basename(os.path.dirname(p)))
        commits = [(c.get("repository") or "", str(c.get("id") or "")) for fx in d.get("fixes") or []
                   for c in fx.get("commits") or []]
        gh = [(github_repo(u), s) for u, s in commits if github_repo(u)]
        repo = gh[0][0] if gh else None
        pkgs = sorted({_purl_pkg(a.get("id")) for a in d.get("artifacts") or []} - {None})
        lang = next((ECOSYSTEM_LANG.get(t) for t, _ in pkgs if ECOSYSTEM_LANG.get(t)), None)
        rows.append(_row("sap-kb", vid, aliases=[vid], repo=repo,
                         repo_url=None if repo else (commits[0][0] if commits else None),
                         fix_shas=[s for r, s in gh if r == repo], language=lang,
                         language_basis="purl" if lang else None, packages=pkgs))
    return rows


def crossvul(metadata_json: str) -> list[dict]:
    """CrossVul metadata.json: one entry per fix commit -> one row per (CVE, repo)."""
    with open(metadata_json) as f:
        entries = json.load(f)
    groups: dict = {}
    for e in entries:
        m = _COMMIT.search(e.get("url") or "")
        repo = _norm_repo(m.group(1), m.group(2)) if m else None
        key = (e.get("cve"), repo or e.get("url"))
        g = groups.setdefault(key, {"cve": e.get("cve"), "repo": repo, "url": e.get("url"), "shas": [],
                                    "cwe": set(), "files": []})
        if m:
            g["shas"].append(m.group(3))
        if e.get("cwe"):
            g["cwe"].add(e["cwe"])
        g["files"] += [x.get("original_name") or "" for x in e.get("files") or []
                       if (x.get("database_name") or "").startswith("bad_")]
    rows = []
    for g in groups.values():
        lang = language_from_files(g["files"])
        rows.append(_row("crossvul", g["cve"] or g["url"], aliases=[g["cve"]], repo=g["repo"],
                         repo_url=None if g["repo"] else g["url"], fix_shas=g["shas"], cwe=sorted(g["cwe"]),
                         language=lang, language_basis="dataset_files" if lang else None))
    return rows


def _github_fix(urls):
    """(repo, shas, pr) from a list of URLs: commit links first (same repo as the first), then a PR.
    Nested lists are flattened and non-string entries ignored (VulcaN stores some urls as lists)."""
    flat = []
    for u in urls:
        flat += [x for x in u if isinstance(x, str)] if isinstance(u, list) else [u] if isinstance(u, str) else []
    urls = flat
    commits = [(m.group(1), m.group(2), m.group(3)) for u in urls for m in [_COMMIT.search(u or "")] if m]
    commits = [(_norm_repo(o, n), sha) for o, n, sha in commits if _norm_repo(o, n)]
    if commits:
        repo = commits[0][0]
        return repo, [sha for r, sha in commits if r == repo], None
    for u in urls:
        m = _PR.search(u or "")
        if m and _norm_repo(m.group(1), m.group(2)):
            return _norm_repo(m.group(1), m.group(2)), [], int(m.group(3))
    repo = next((github_repo(u) for u in urls if github_repo(u)), None)
    return repo, [], None


def vulcan(reviews_dir: str) -> list[dict]:
    """VulcaN (github.com/VulcaN-Study/Supplementary-Material) manual npm advisory reviews, with the
    reviewer's corrected CWE and source->sink locations (paths relative to the npm tarball)."""
    rows = []
    for p in sorted(glob.glob(os.path.join(reviews_dir, "*.json"))):
        with open(p) as f:
            d = json.load(f)
        adv = d.get("advisory") or {}
        aid = str(adv.get("id") or "")
        aliases = [aid if aid.upper().startswith("GHSA-") else None, adv.get("cve") or None,
                   f"npm:{adv['npm_id']}" if adv.get("npm_id") else (f"npm:{aid}" if aid.isdigit() else None)]
        m = re.search(r"registry\.npmjs\.org/(.+?)/-/(.+?)\.tgz", d.get("correct_package_link") or "")
        pkg = m.group(1).lower() if m else None
        ver = m.group(2)[len(m.group(1).split("/")[-1]) + 1:] if m else None
        repo, shas, pr = _github_fix([x.get("url") for x in d.get("patch") or [] if isinstance(x, dict)])
        rows.append(_row("vulcan", os.path.splitext(os.path.basename(p))[0], aliases=aliases, repo=repo,
                         fix_shas=shas, fix_pr=pr, cwe=[d.get("correct_cwe") or adv.get("cwe")],
                         language="js", language_basis="dataset", packages=[("npm", pkg)] if pkg else [],
                         advisory_cwe=adv.get("cwe"), package_version=ver,
                         locations=(d.get("vulnerability") or {}).get("vulnerability_location") or []))
    return rows


_SECBENCH_CLASS = {"code-injection": "dataflow", "command-injection": "dataflow", "path-traversal": "dataflow",
                   "prototype-pollution": "dataflow", "redos": "other"}


def secbench_js(root: str) -> list[dict]:
    """SecBench.js exploit metadata (<class>/<pkg>_<version>/package.json); exploits are never run.
    The dataset has no CWE field; ``cwe_class`` comes from its vulnerability-class folder."""
    rows = []
    for cls in sorted(_SECBENCH_CLASS):
        for p in sorted(glob.glob(os.path.join(root, cls, "*", "package.json"))):
            with open(p) as f:
                d = json.load(f)
            deps = d.get("dependencies") or {}
            pkg, ver = next(iter(deps.items()), (None, None))
            links = [v for v in (d.get("links") or {}).values() if v]
            ids = [x for u in links for x in re.findall(r"(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|SNYK-[A-Z0-9-]+)", u)]
            cve = d.get("id") if str(d.get("id") or "").upper().startswith("CVE-") else None
            repo, shas, pr = _github_fix([d.get("fixCommit") or ""])
            r = _row("secbench-js", f"{cls}/{os.path.basename(os.path.dirname(p))}", aliases=[cve, *ids], repo=repo,
                     fix_shas=shas, fix_pr=pr, language="js", language_basis="dataset",
                     packages=[("npm", pkg.lower())] if pkg else [], package_version=ver, vuln_class=cls,
                     fixed_version=d.get("fixedVersion"), fix_commit_url=d.get("fixCommit"),
                     sink_location=d.get("sink") or None)
            r["cwe_class"], r["cwe_class_basis"] = _SECBENCH_CLASS[cls], "vuln_class"
            rows.append(r)
    return rows


def javavulbench(jsonl: str) -> list[dict]:
    """JavaVulBench (Zenodo 10.5281/zenodo.20110173) method-level benchmark -> one row per (CVE, repo),
    fix commits as given, vulnerable methods kept as annotations."""
    groups: dict = {}
    with open(jsonl) as f:
        for line in f:
            if not line.strip():
                continue
            x = json.loads(line)
            if x.get("label") not in ("vulnerable", "patched"):
                continue
            key = (x.get("cve_id"), (x.get("repo_full_name") or "").lower())
            g = groups.setdefault(key, {"cve": x.get("cve_id"), "repo": x.get("repo_full_name") or "", "shas": [],
                                        "cwe": set(), "published": _date(x.get("published_date")), "methods": []})
            g["shas"].append(x.get("commit_sha"))
            g["cwe"] |= set(x.get("cwe_ids") or [])
            if x["label"] == "vulnerable":
                g["methods"].append({"file": x.get("file_path"), "method": x.get("method_name"),
                                     "start_line": x.get("start_line"), "end_line": x.get("end_line"),
                                     "vulnerable_lines": x.get("vulnerable_lines")})
    rows = []
    for g in groups.values():
        owner, _, name = g["repo"].partition("/")
        rows.append(_row("javavulbench", f"{g['cve']}@{g['repo'].lower()}", aliases=[g["cve"]],
                         repo=_norm_repo(owner, name), fix_shas=g["shas"], cwe=sorted(g["cwe"]), language="java",
                         language_basis="dataset", advisory_published=g["published"], vuln_methods=g["methods"]))
    return rows


def repopairbench(jsonl: str) -> list[dict]:
    """RepoPairBench (DREA, github.com/huhusmang/DREA) Python fix commits."""
    import ast

    rows = []
    with open(jsonl) as f:
        for line in f:
            if not line.strip():
                continue
            x = json.loads(line)
            vd = x.get("vuln_data")
            if isinstance(vd, str):
                try:
                    vd = ast.literal_eval(vd)          # a Python literal; literal_eval never executes code
                except (ValueError, SyntaxError):
                    vd = {}
            lang = {"python": "py", "java": "java", "javascript": "js", "typescript": "js"}.get(
                str(x.get("language") or "").lower(), x.get("language"))
            rows.append(_row("repopairbench", str(x.get("id")), aliases=x.get("cve_ids") or [],
                             repo=github_repo(x.get("repo_url")), fix_shas=[x.get("commit_hash")],
                             cwe=x.get("cwe_ids") or [], language=lang, language_basis="dataset",
                             fix_file=(vd or {}).get("file_path") if isinstance(vd, dict) else None))
    return rows


def pyvul(root: str) -> list[dict]:
    """PyVul (github.com/billquan/PyVul) commit-level set. Its commit membership was filtered with
    GPT-4 (LLM-VDC), so every row is tagged ``llm_assisted_labels=True`` and is dropped by
    ``filters.keep`` unless explicitly allowed."""
    def key(u):
        m = _COMMIT.search(u or "")
        return (_norm_repo(m.group(1), m.group(2)), m.group(3).lower()) if m else None

    def load(name, default):
        path = os.path.join(root, name)
        if not os.path.exists(path):
            return default
        with open(path) as f:
            return json.load(f)

    cwes, ids = defaultdict(set), defaultdict(set)
    for u, c in load("commits_cwe_map.json", {}).items():
        if key(u):
            cwes[key(u)].add(c)
    for c, entries in load("github_adv_src_links.json", {}).items():
        for e in entries:
            for u in e.get("src_links") or []:
                if key(u):
                    ids[key(u)].add(e.get("id"))
                    cwes[key(u)].add(c)
    for u, e in load("huntr_reports_with_src", {}).items():
        k = key(e.get("fix_commit"))
        if k:
            ids[k].add(e.get("cve") or None)
            cwes[k].add(e.get("cwe"))
    for u, e in load("snyk_reports_with_src", {}).items():
        sid = re.search(r"(SNYK-[A-Z0-9-]+)", u)
        for ref in e.get("refs") or []:
            k = key(ref)
            if k:
                ids[k] |= {e.get("cve") or None, sid.group(1) if sid else None}
                cwes[k].add(e.get("cwe"))
    rows = []
    with open(os.path.join(root, "commit_level_dataset.out")) as f:
        for line in f:
            k = key(line.strip())
            if not k:
                continue
            repo, sha = k
            rows.append(_row("pyvul", f"pyvul:{repo}@{sha[:12]}", aliases=sorted(i for i in ids[k] if i),
                             repo=repo, fix_shas=[sha], cwe=sorted(c for c in cwes[k] if c), language="py",
                             language_basis="dataset", llm_assisted_labels=True))
    return rows


# ---- CVEfixes SQLite dump (parsed by hand; never executed) --------------------------------------

_STR = re.compile(r"'([^']*(?:''[^']*)*)'", re.S)
_NUM = re.compile(r"[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
_WS = re.compile(r"\s*")
_INSERT = re.compile(r'INSERT INTO "?(\w+)"? VALUES\(')
_CREATE = re.compile(r'CREATE TABLE (?:IF NOT EXISTS )?"?(\w+)"?\s*\((.*)\)\s*;\s*$', re.S)


def _sql_expr(s: str, pos: int):
    """One SQLite-dump literal: 'text', NULL, a number, X'hex', char(N), or replace(a,b,c)."""
    pos = _WS.match(s, pos).end()
    if s.startswith("'", pos):
        m = _STR.match(s, pos)
        return m.group(1).replace("''", "'"), m.end()
    if s.startswith("NULL", pos):
        return None, pos + 4
    if s.startswith("X'", pos) or s.startswith("x'", pos):
        m = _STR.match(s, pos + 1)
        return m.group(1), m.end()
    if s.startswith("char(", pos):
        m = re.compile(r"char\((\d+)\)").match(s, pos)
        return chr(int(m.group(1))), m.end()
    if s.startswith("replace(", pos):
        args, pos = [], pos + len("replace(")
        for i in range(3):
            v, pos = _sql_expr(s, pos)
            args.append(v)
            pos = _WS.match(s, pos).end()
            if s[pos] != ("," if i < 2 else ")"):
                raise ValueError(f"bad replace() near {s[pos:pos + 40]!r}")
            pos += 1
        return args[0].replace(args[1], args[2]), pos
    m = _NUM.match(s, pos)
    if not m:
        raise ValueError(f"unparseable SQL literal near {s[pos:pos + 80]!r}")
    return m.group(0), m.end()


def _sql_values(stmt: str, start: int) -> list:
    out, pos = [], start
    while True:
        v, pos = _sql_expr(stmt, pos)
        out.append(v)
        pos = _WS.match(stmt, pos).end()
        if stmt[pos] == ",":
            pos += 1
            continue
        if stmt[pos] == ")":
            return out
        raise ValueError(f"unexpected {stmt[pos:pos + 40]!r} in VALUES list")


def _columns(create_stmt: str):
    m = _CREATE.search(create_stmt)
    if not m:
        return None, None
    cols = []
    for c in m.group(2).split(",\n"):
        c = c.strip()
        if c and not re.match(r"(PRIMARY|FOREIGN|UNIQUE|CONSTRAINT|CHECK)\b", c, re.I):
            cols.append(re.match(r'"?(\w+)"?', c).group(1))
    return m.group(1), cols


def iter_sql_dump(lines, tables: set[str]):
    """Yield (table, {column: value}) for INSERTs into ``tables`` from SQLite ``.dump`` text lines.

    A statement may span lines (string literals with raw newlines); it ends at a line ending in
    ``);`` once the running count of single quotes is even (``''`` escapes keep the parity). Rows of
    other tables are skipped without being buffered.
    """
    columns: dict[str, list[str]] = {}
    create, table, keep, buf, quotes = None, None, False, [], 0
    for line in lines:
        if create is not None:
            create.append(line)
            if line.rstrip().endswith(");"):
                name, cols = _columns("".join(create))
                if name:
                    columns[name] = cols
                create = None
            continue
        if table is not None:
            quotes += line.count("'")
            if keep:
                buf.append(line)
            if quotes % 2 == 0 and line.rstrip().endswith(");"):
                if keep:
                    stmt = "".join(buf)
                    yield table, dict(zip(columns[table], _sql_values(stmt, _INSERT.match(stmt).end())))
                table, buf = None, []
            continue
        if line.startswith("CREATE TABLE"):
            create = [line]
            if line.rstrip().endswith(");"):
                name, cols = _columns(line)
                if name:
                    columns[name] = cols
                create = None
        elif line.startswith("INSERT INTO "):
            m = _INSERT.match(line)
            if not m:
                continue
            table, quotes = m.group(1), line.count("'")
            keep = table in tables
            buf = [line] if keep else []
            if quotes % 2 == 0 and line.rstrip().endswith(");"):
                if keep:
                    yield table, dict(zip(columns[table], _sql_values(line, m.end())))
                table, buf = None, []


def _open_dump(path: str):
    """Text lines of a ``.sql.gz`` (or the ``*.sql.gz`` member of a CVEfixes release zip)."""
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        member = next(n for n in z.namelist() if n.endswith(".sql.gz"))
        raw = z.open(member)
    else:
        raw = open(path, "rb")
    return io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="surrogateescape", newline="\n")


_LANG_NAMES = {"javascript": "js", "typescript": "js", "python": "py", "java": "java"}


def cvefixes(path: str) -> list[dict]:
    """CVEfixes (Zenodo) SQL dump -> one row per (CVE, repo), with commit dates and changed files
    taken from the dump itself (``enrich_basis = "cvefixes"``)."""
    want = {"fixes", "commits", "file_change", "cve", "cwe_classification", "repository"}
    fixes, commits, files, cve_date, cwes, repo_lang = [], {}, {}, {}, {}, {}
    with _open_dump(path) as lines:
        for table, r in iter_sql_dump(lines, want):
            if table == "fixes":
                fixes.append((r["cve_id"], r["hash"], r["repo_url"]))
            elif table == "commits":
                commits[(r["hash"], r["repo_url"])] = (_date(r.get("author_date")), _date(r.get("committer_date")))
            elif table == "file_change":
                p = r.get("new_path") if r.get("new_path") not in (None, "None") else r.get("old_path")
                lang = _LANG_NAMES.get(str(r.get("programming_language") or "").lower()) or file_lang(p or "")
                files.setdefault(r["hash"], []).append((p or r.get("filename") or "", lang))
            elif table == "cve":
                cve_date[r["cve_id"]] = _date(r.get("published_date"))
            elif table == "cwe_classification":
                cwes.setdefault(r["cve_id"], set()).add(r["cwe_id"])
            elif table == "repository":
                repo_lang[r["repo_url"]] = _LANG_NAMES.get(str(r.get("repo_language") or "").lower())
    groups: dict = {}
    for cve, sha, url in fixes:
        groups.setdefault((cve, url), []).append(sha)
    rows = []
    for (cve, url), shas in groups.items():
        dated = sorted(dict.fromkeys(shas), key=lambda s: (max(filter(None, commits.get((s, url), (None, None))),
                                                                default="9999"), s))
        repo = github_repo(url)
        fix = dated[0]
        fl = files.get(fix)
        non_test = [(p, lg) for p, lg in fl or [] if not _is_test(p)]
        fams = {lg for _, lg in non_test} - {None}
        lang = (fams.pop() if len(fams) == 1 else
                repo_lang.get(url) if repo_lang.get(url) in fams else "mixed" if fams else None)
        a_date, c_date = commits.get((fix, url), (None, None))
        has = (fix, url) in commits
        row = _row("cvefixes", cve, aliases=[cve], repo=repo, repo_url=None if repo else url, fix_shas=dated,
                   cwe=sorted(cwes.get(cve, [])), language=lang, language_basis="dataset_files" if lang else None,
                   advisory_published=cve_date.get(cve))
        if has:
            row.update(enrich_status="ok", enrich_basis="cvefixes", author_date=a_date, committer_date=c_date,
                       fix_commit_date=max(filter(None, (a_date, c_date)), default=None))
            if fl is not None:
                row.update(n_files=len(non_test), n_files_total=len(fl),
                           n_files_lang=sum(1 for _, lg in non_test if lg == lang) if lang in SUPPORTED_LANGUAGES else None,
                           fix_files=[p for p, _ in non_test])
        rows.append(row)
    return rows


# ---- MoreFixes PostgreSQL dump (COPY blocks split by hand; never loaded into Postgres) -----------

_COPY_HEAD = re.compile(rb'COPY (?:"?\w+"?\.)?"?(\w+)"? \(([^)]*)\) FROM stdin;')
_COPY_ESC = re.compile(r"\\(?:([0-7]{1,3})|x([0-9a-fA-F]{1,2})|(.))", re.S)
_COPY_CHR = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
MOREFIXES_DIRECT = 1337        # fixes.score of a commit the NVD/GHSA record itself links
MOREFIXES_MIN_SCORE = 65       # MoreFixes' own noise floor for Prospector-found commits


def _copy_field(s: str):
    """One field of PostgreSQL COPY text format: ``\\N`` is NULL, backslash escapes are decoded."""
    if s == "\\N":
        return None
    if "\\" not in s:
        return s
    return _COPY_ESC.sub(lambda m: chr(int(m.group(1), 8)) if m.group(1) else
                         chr(int(m.group(2), 16)) if m.group(2) else _COPY_CHR.get(m.group(3), m.group(3)), s)


def iter_copy_dump(raw, wanted: dict[str, tuple[str, ...]]):
    """Yield (table, {column: value}) for rows of the ``wanted`` tables (only the named columns are
    decoded) from the binary lines of a pg_dump plain-text dump. COPY escapes newlines, so each data
    row is one line; rows of other tables are skipped unparsed."""
    cols, skipping = None, False
    for line in raw:
        if cols is None and not skipping:
            if line.startswith(b"COPY "):
                m = _COPY_HEAD.match(line)
                table = m.group(1).decode() if m else None
                if table in wanted:
                    names = [c.strip().strip('"') for c in m.group(2).decode().split(",")]
                    cols = (table, [(c, names.index(c)) for c in wanted[table] if c in names])
                else:
                    skipping = True
            continue
        if line.rstrip(b"\r\n") == b"\\.":
            cols, skipping = None, False
            continue
        if skipping:
            continue
        parts = line.rstrip(b"\r\n").split(b"\t")      # the MoreFixes dump has CRLF line ends; data CRs are escaped
        yield cols[0], {c: _copy_field(parts[i].decode("utf-8", "surrogateescape")) for c, i in cols[1]}


def morefixes(path: str, *, min_score: int = MOREFIXES_MIN_SCORE, stats: dict | None = None) -> list[dict]:
    """MoreFixes (Zenodo 20776007) pg_dump -> one row per (CVE, repo), with commit dates and changed
    files taken from the dump itself (``enrich_basis = "morefixes"``). Language comes from the changed
    files' extensions; the dump's ``programming_language`` is a guesslang model guess and is ignored.

    A pair uses the commits its advisory links (score 1337, ``fix_link = "advisory"``) when it has
    any. Otherwise it uses the Prospector-found commits scoring >= ``min_score`` and is tagged
    ``heuristic_fix_link`` (``filters.keep`` drops those unless explicitly allowed). Commits below
    ``min_score`` never become rows; MoreFixes leaves them out of its own data tables too."""
    want = {"fixes": ("cve_id", "hash", "repo_url", "rel_type", "score"),
            "commits": ("hash", "repo_url", "author_date", "committer_date"),
            "file_change": ("hash", "filename", "old_path", "new_path", "programming_language"),
            "cve": ("cve_id", "published_date"), "cwe_classification": ("cve_id", "cwe_id"),
            "repository": ("repo_url", "repo_language")}
    groups: dict = {}
    commits, files, cve_date, cwes, repo_lang = {}, {}, {}, {}, {}
    with gzip.open(path, "rb") as raw:
        for table, r in iter_copy_dump(raw, want):
            if table == "fixes":
                score = int(r["score"]) if r.get("score") not in (None, "") else None
                groups.setdefault((r["cve_id"], r["repo_url"]), []).append((r["hash"], score))
                _bump(stats, f"fix_links_rel_type:{r.get('rel_type')}:{'direct' if score == MOREFIXES_DIRECT else 'prospector'}")
            elif table == "commits":
                commits[(r["hash"], r["repo_url"])] = (_date(r.get("author_date")), _date(r.get("committer_date")))
            elif table == "file_change":           # programming_language is a guesslang guess: unused
                p = r.get("new_path") if r.get("new_path") not in (None, "None") else r.get("old_path")
                p = p or r.get("filename") or ""
                files.setdefault(r["hash"], []).append((p, file_lang(p)))
            elif table == "cve":
                cve_date[r["cve_id"]] = _date(r.get("published_date"))
            elif table == "cwe_classification":
                cwes.setdefault(r["cve_id"], set()).add(r["cwe_id"])
            elif table == "repository":
                repo_lang[r["repo_url"]] = _LANG_NAMES.get(str(r.get("repo_language") or "").lower())
    rows = []
    for (cve, url), links in groups.items():
        direct = [s for s, sc in links if sc == MOREFIXES_DIRECT]
        found = {s: sc for s, sc in links if sc != MOREFIXES_DIRECT and sc is not None and sc >= min_score}
        _bump(stats, "fix_links_below_min_score", sum(1 for _, sc in links if sc is None or sc < min_score))
        if direct:
            shas, link = direct, "advisory"
            _bump(stats, "prospector_links_ignored_for_advisory_links", len(found))
        elif found:
            shas, link = list(found), "prospector"
            _bump(stats, "groups_heuristic_only")
        else:
            _bump(stats, "groups_below_min_score_only")
            continue
        dated = sorted(dict.fromkeys(shas), key=lambda s: (max(filter(None, commits.get((s, url), (None, None))),
                                                                default="9999"), s))
        repo = github_repo(url)
        fix = dated[0]
        fl = files.get(fix)
        non_test = [(p, lg) for p, lg in fl or [] if not _is_test(p)]
        fams = {lg for _, lg in non_test} - {None}
        lang = (fams.pop() if len(fams) == 1 else
                repo_lang.get(url) if repo_lang.get(url) in fams else "mixed" if fams else None)
        row = _row("morefixes", cve, aliases=[cve], repo=repo, repo_url=None if repo else url, fix_shas=dated,
                   cwe=sorted(cwes.get(cve, [])), language=lang, language_basis="fix_file_extensions" if lang else None,
                   advisory_published=cve_date.get(cve), fix_link=link, heuristic_fix_link=link == "prospector",
                   fix_score=MOREFIXES_DIRECT if link == "advisory" else found[fix])
        if (fix, url) in commits:
            a_date, c_date = commits[(fix, url)]
            row.update(enrich_status="ok", enrich_basis="morefixes", author_date=a_date, committer_date=c_date,
                       fix_commit_date=max(filter(None, (a_date, c_date)), default=None))
            if fl is not None:
                row.update(n_files=len(non_test), n_files_total=len(fl),
                           n_files_lang=sum(1 for _, lg in non_test if lg == lang) if lang in SUPPORTED_LANGUAGES else None,
                           fix_files=[p for p, _ in non_test])
        rows.append(row)
    return rows


# ---- cross-source advisory dates ----------------------------------------------------------------

def advisory_date_index(rows) -> dict[str, str]:
    """alias -> earliest real publication date seen in any source row that carries one."""
    idx: dict[str, str] = {}
    for r in rows:
        d = r.get("advisory_published")
        if not d or r.get("advisory_published_basis") not in (None, "source"):
            continue
        for a in r.get("aliases") or [r["id"]]:
            if a not in idx or d < idx[a]:
                idx[a] = d
    return idx


def fill_advisory_dates(rows, idx) -> list[dict]:
    """Copy rows; a row without its own date takes the earliest date of any alias (a real advisory)."""
    out = []
    for r in rows:
        r = dict(r)
        if not r.get("advisory_published"):
            dates = [idx[a] for a in r.get("aliases") or [r["id"]] if a in idx]
            if dates:
                r["advisory_published"], r["advisory_published_basis"] = min(dates), "alias_index"
        out.append(r)
    return out
