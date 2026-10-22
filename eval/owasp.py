"""OWASP Benchmark as the false-alarm set, run as a targeted judgement (spec 5.4; Task F2).

60 Java v1.2 + 60 Python v0.1 cases, stratified by category and balanced real/trap within each. Each
run points ONE agent at ONE case (its file and entry point) and the agent answers vulnerable or not.
All cases of a benchmark share one repo and one pinned commit; `runs.case_id` tells them apart.

  sample(csv_path)        the stratified sample, read from the benchmark's OWN expected-results CSV
                          inside an exported tree at the pinned commit; `file`/`entry` come from that
                          tree's layout (never guessed)
  strip_answers(tree)     deletes the answer-bearing files from an exported tree (the launcher calls
                          it right after export_tree for every OWASP item, every arm)
  case_flows(db, ...)     the scan's CandidateFlows whose path touches the case's file (orion-lm arms)
  score / youden          per-case confusion row; Youden J = TPR - FPR (spec 6, secondary)
  load_sample / validate_sample   eval/dataset/owasp_sample.json, the run input (not manifest rows:
                          a case has no vulnerable/patched commit pair)

`python -m eval.owasp ...` (main) regenerates eval/dataset/owasp_sample.json from the two mirrors.
"""
import argparse
import hashlib
import json
import os
import random
import re
import shutil
import tempfile
from datetime import date

from eval.match import _same_file   # the frozen L1 "same file" rule (./-stripped, suffix match)

# The two benchmarks of the study (spec 5.4). `version` must equal the version in the header of the
# expected-results CSV at the pinned commit (build_sample checks it).
BENCHMARKS = {
    "owasp-java": {"language": "java", "version": "1.2",
                   "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkJava"},
    "owasp-python": {"language": "python", "version": "0.1",
                     "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkPython"},
}

_CASE_ID = re.compile(r"BenchmarkTest\d+")
_SOURCE_EXT = {".java": "java", ".py": "python"}
_VERSION = re.compile(r"Benchmark version:\s*([^,\s]+)")
_SHA = re.compile(r"[0-9a-f]{40}")


# ---- the expected results and the layout --------------------------------------------------------

def read_expected(csv_path: str) -> tuple:
    """(version or None, rows) from an OWASP expected-results CSV: '#'-header line(s) (the version is
    read from 'Benchmark version: X'), then `test name, category, real vulnerability, cwe` rows ->
    [{case_id, category, real: bool, cwe: 'CWE-N'}]. A malformed row raises ValueError."""
    version, rows = None, []
    with open(csv_path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                m = _VERSION.search(line)
                if m and version is None:
                    version = m.group(1)
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 4 or not _CASE_ID.fullmatch(parts[0]) or not parts[3].isdigit():
                raise ValueError(f"{csv_path}:{n}: not a 'test name, category, real, cwe' row: {line!r}")
            if parts[2] not in ("true", "false"):
                raise ValueError(f"{csv_path}:{n}: real vulnerability must be true/false, got {parts[2]!r}")
            rows.append({"case_id": parts[0], "category": parts[1], "real": parts[2] == "true",
                         "cwe": f"CWE-{int(parts[3])}"})
    return version, rows


def case_files(tree: str) -> dict:
    """{case_id: repo-relative path} of every case source file (BenchmarkTestNNNNN.java / .py) in the
    tree. A case id with two source files is ambiguous and raises ValueError."""
    out = {}
    for d, dirs, files in os.walk(tree):
        dirs.sort()
        for f in sorted(files):
            stem, ext = os.path.splitext(f)
            if ext in _SOURCE_EXT and _CASE_ID.fullmatch(stem):
                rel = os.path.relpath(os.path.join(d, f), tree).replace(os.sep, "/")
                if stem in out:
                    raise ValueError(f"two source files for {stem}: {out[stem]} and {rel}")
                out[stem] = rel
    return out


_SERVLET = re.compile(r'@WebServlet\(\s*(?:value\s*=\s*|urlPatterns\s*=\s*)?"([^"]+)"')
_FLASK = re.compile(r"""@app\.route\(\s*['"]([^'"]+)['"]\s*,\s*methods\s*=\s*\[\s*['"](\w+)['"]\s*\]\s*\)"""
                    r"""\s*\n\s*def\s+(\w+)\s*\(""")


def entry_for(tree: str, file: str, case_id: str) -> str:
    """The case's entry point as its source gives it: `<METHOD> <route> -> <handler>`.
      Java v1.2:   @WebServlet(value = "/<cat>-NN/<id>") on class <id>; the test logic is doPost
                   (doGet forwards to it or serves the form) -> "POST /sqli-00/<id> -> <id>.doPost"
      Python v0.1: @app.route('<route>', methods=['POST']) on def <id>_post
                   -> "POST /benchmark/sqli-00/<id> -> <id>_post"
    Raises ValueError when the layout does not say (never guessed)."""
    with open(os.path.join(tree, file), encoding="utf-8", errors="replace") as f:
        src = f.read()
    if file.endswith(".java"):
        m = _SERVLET.search(src)
        for method, http in (("doPost", "POST"), ("doGet", "GET")):
            if m and re.search(rf"\bpublic\s+void\s+{method}\s*\(", src):
                return f"{http} {m.group(1)} -> {case_id}.{method}"
    else:
        routes = {http.upper(): (route, fn) for route, http, fn in _FLASK.findall(src)}
        for http in ("POST", "GET"):
            if http in routes:
                route, fn = routes[http]
                return f"{http} {route} -> {fn}"
    raise ValueError(f"{case_id}: no servlet/route entry point found in {file}")


# ---- the sample ----------------------------------------------------------------------------------

def sample(csv_path: str, *, n_per_lang: int = 60, seed: int = 0) -> list:
    """A stratified sample of one benchmark: `n_per_lang` cases spread as evenly as possible over its
    categories (each gets n // C; the n % C remainder goes to categories drawn with the seed), real and
    trap at most 1 apart within every category (an odd quota's extra case alternates real/trap over the
    categories, in a seeded order, so the overall split is balanced too), cases drawn with the seed.
    Deterministic for a given seed.

    `csv_path` is the benchmark's own expected-results CSV inside an exported tree at the pinned commit;
    each case's `file` and `entry` are read from that tree (the CSV's directory). Returns
    [{case_id, category, real, cwe, file, entry}] sorted by case_id. Raises ValueError when a category
    cannot be balanced, or a sampled case has no source file / entry point."""
    _, rows = read_expected(csv_path)
    if not rows:
        raise ValueError(f"{csv_path}: no cases")
    if n_per_lang > len(rows):
        raise ValueError(f"{csv_path}: asked for {n_per_lang} cases, the CSV has {len(rows)}")
    rng = random.Random(seed)
    by_cat = {}
    for r in sorted(rows, key=lambda r: r["case_id"]):
        by_cat.setdefault(r["category"], []).append(r)
    cats = sorted(by_cat)
    base, extra = divmod(n_per_lang, len(cats))
    bonus = set(rng.sample(cats, extra))
    quota = {c: base + (c in bonus) for c in cats}
    odd = [c for c in cats if quota[c] % 2]
    rng.shuffle(odd)
    extra_real = set(odd[0::2])
    picked = []
    for c in cats:
        n_real = quota[c] // 2 + (c in extra_real)
        n_trap = quota[c] - n_real
        reals = [r for r in by_cat[c] if r["real"]]
        traps = [r for r in by_cat[c] if not r["real"]]
        if len(reals) < n_real or len(traps) < n_trap:
            raise ValueError(f"category {c}: needs {n_real} real + {n_trap} trap cases to balance, "
                             f"the CSV has {len(reals)} + {len(traps)}")
        picked += rng.sample(reals, n_real) + rng.sample(traps, n_trap)
    tree = os.path.dirname(os.path.abspath(csv_path))
    files = case_files(tree)
    out = []
    for r in sorted(picked, key=lambda r: r["case_id"]):
        if r["case_id"] not in files:
            raise ValueError(f"{r['case_id']}: no source file {r['case_id']}.java/.py in {tree}")
        file = files[r["case_id"]]
        out.append(dict(r, file=file, entry=entry_for(tree, file, r["case_id"])))
    return out


# ---- answer stripping ----------------------------------------------------------------------------

# What carries OWASP's answers in an exported tree (survey of both pinned trees: docs/notes/orion-lm-owasp.md):
_ANSWER_CSV = re.compile(r"expectedresults.*\.csv", re.I)   # the answer key (any depth)
_CASE_METADATA = re.compile(r"BenchmarkTest\d+\.xml")        # per-case category + real/false (Java <1.2-2025)
_ANSWER_DIRS = ("results", "scorecard")                       # top level only: tool results and scorecards,
#                                                               which list per-case TP/FP/TN/FN
# Never removed, whatever directory they sit in: deleting a build marker would also change Orion's
# marker-based language detection (pom.xml -> javasrc, requirements.txt/setup.py -> pythonsrc).
_BUILD_FILES = frozenset({"pom.xml", "web.xml", "build.xml", "build.gradle", "build.gradle.kts",
                          "settings.gradle", "gradlew", "mvnw", "setup.py", "setup.cfg",
                          "pyproject.toml", "requirements.txt", "Pipfile", "package.json", "go.mod"})


def strip_answers(tree: str) -> list:
    """Delete OWASP's answer-bearing files from an exported tree: every expectedresults*.csv, every
    per-case BenchmarkTestNNNNN.xml metadata file, and everything under the top-level results/ and
    scorecard/ directories (which are removed once empty). Build files (_BUILD_FILES) are never
    removed. Symlinks are not followed. Returns the removed paths, repo-relative and sorted."""
    removed = []
    for d, dirs, files in os.walk(tree):
        rel_dir = os.path.relpath(d, tree)
        top = rel_dir.split(os.sep)[0] if rel_dir != "." else ""
        for f in files:
            if f in _BUILD_FILES:
                continue
            if top in _ANSWER_DIRS or _ANSWER_CSV.fullmatch(f) or _CASE_METADATA.fullmatch(f):
                os.remove(os.path.join(d, f))
                removed.append(os.path.normpath(os.path.join(rel_dir, f)).replace(os.sep, "/"))
    for top in _ANSWER_DIRS:   # drop the emptied answer dirs (bottom-up), keep any that still hold a file
        root = os.path.join(tree, top)
        if os.path.isdir(root) and not os.path.islink(root):
            for d, _dirs, _files in sorted(os.walk(root), key=lambda w: -len(w[0])):
                if not os.listdir(d):
                    os.rmdir(d)
    return sorted(removed)


# ---- the orion-lm case mode ----------------------------------------------------------------------

# How many CandidateFlows case_flows reads: every one the scan has. graph/pathfind._MAX_FLOWS (300 on
# 2026-10-22) caps what a build persists; a test pins this limit above it.
CASE_FLOW_LIMIT = 10_000


def case_flows(db, scan_id: str, case: dict) -> list:
    """The scan's CandidateFlows (rank order) whose path touches the case's file, as `flow_slice` dicts
    for `discover_lm(..., flows=...)`. A path node's file is CpgCall.file_path, repo-relative; it is
    compared with the case's file by the L1 same-file rule. [] when no flow touches the file -- a
    genuine 'nothing to flag', not an error. Graph errors raise (RuntimeError from slice)."""
    from orion.lm import slice as lm_slice   # lazy: eval.run imports this module
    out = []
    for flow in lm_slice.candidate_flows(db, scan_id, max_flows=CASE_FLOW_LIMIT):
        s = lm_slice.flow_slice(db, scan_id, flow)
        if any(_same_file(n.get("file"), case["file"]) for n in s["nodes"]):
            out.append(s)
    return out


# ---- scoring -------------------------------------------------------------------------------------

def norm_path(p, root=None):
    """A finding's file, repo-relative: the tree root (when given) and leading './' stripped."""
    if not p:
        return None
    p = str(p)
    if root:
        r = str(root).rstrip("/") + "/"
        if p.startswith(r):
            p = p[len(r):]
    while p.startswith("./"):
        p = p[2:]
    return p or None


def score(findings: list, case: dict, *, root=None) -> dict:
    """One case's confusion row. `findings` are normalized findings (eval.normalize: {file, ...});
    flagged = any finding whose file is the case's file (after norm_path, then the L1 same-file rule,
    under which an absolute path inside the tree also matches by suffix)."""
    target = case["file"]
    flagged = any(_same_file(norm_path(f.get("file"), root), target)
                  for f in findings or [] if isinstance(f, dict))
    real = bool(case["real"])
    return {"case_id": case["case_id"], "real": real, "flagged": flagged,
            "tp": int(real and flagged), "fp": int(not real and flagged),
            "tn": int(not real and not flagged), "fn": int(real and not flagged)}


def youden(rows: list):
    """Youden J = TPR - FPR over score() rows; None when there is no real case or no trap case (J is
    undefined there -- never a made-up 0)."""
    tp, fn = sum(r["tp"] for r in rows), sum(r["fn"] for r in rows)
    fp, tn = sum(r["fp"] for r in rows), sum(r["tn"] for r in rows)
    if tp + fn == 0 or fp + tn == 0:
        return None
    return tp / (tp + fn) - fp / (fp + tn)


# ---- the sample file (eval/dataset/owasp_sample.json) --------------------------------------------

def load_sample(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("benchmarks"), list):
        raise ValueError(f'{path}: OWASP sample must be {{"benchmarks": [...], ...}}')
    return data


def validate_sample(data) -> list:
    """Human-readable errors (empty = clean): seed present, benchmark ids unique, every pinned_sha a
    full 40-hex commit, case fields typed, categories known to CASE_PROMPT, and case_ids unique within
    each benchmark (the run key is (repo, commit, case_id), so the two benchmarks may share an id)."""
    from eval.arms.prompt import OWASP_CATEGORIES
    if not isinstance(data, dict) or not isinstance(data.get("benchmarks"), list):
        return ['OWASP sample must be {"benchmarks": [...], ...}']
    errs = []
    if not isinstance(data.get("seed"), int) or isinstance(data.get("seed"), bool):
        errs.append("seed must be an integer")
    seen_b = set()
    for i, b in enumerate(data["benchmarks"]):
        if not isinstance(b, dict):
            errs.append(f"benchmark {i}: not an object")
            continue
        label = f"benchmark {b.get('id') or i}"
        for k in ("id", "repo_url", "benchmark_version"):
            if not isinstance(b.get(k), str) or not b[k]:
                errs.append(f"{label}: missing or empty {k}")
        if b.get("id") in seen_b:
            errs.append(f"{label}: duplicate benchmark id")
        seen_b.add(b.get("id"))
        if not isinstance(b.get("pinned_sha"), str) or not _SHA.fullmatch(b["pinned_sha"]):
            errs.append(f"{label}: pinned_sha must be a full 40-hex commit sha, got {b.get('pinned_sha')!r}")
        cases = b.get("cases")
        if not isinstance(cases, list) or not cases:
            errs.append(f"{label}: cases must be a non-empty list")
            continue
        seen_c = set()
        for j, c in enumerate(cases):
            if not isinstance(c, dict):
                errs.append(f"{label}: case {j} is not an object")
                continue
            cid = c.get("case_id")
            if not isinstance(cid, str) or not _CASE_ID.fullmatch(cid):
                errs.append(f"{label}: case {j}: case_id must be BenchmarkTestNNNNN, got {cid!r}")
            elif cid in seen_c:
                errs.append(f"{label}: duplicate case_id {cid}")
            seen_c.add(cid)
            if not isinstance(c.get("real"), bool):
                errs.append(f"{label}: {cid}: real must be true/false")
            for k in ("cwe", "file", "entry"):
                if not isinstance(c.get(k), str) or not c[k]:
                    errs.append(f"{label}: {cid}: missing or empty {k}")
            if c.get("category") not in OWASP_CATEGORIES:
                errs.append(f"{label}: {cid}: category {c.get('category')!r} has no CASE_PROMPT description")
    return errs


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build_sample(specs: list, *, n_per_lang: int = 60, seed: int = 0, tmp_root=None) -> dict:
    """The owasp_sample.json document. `specs` = [{id, mirror_dir, sha}] (ids from BENCHMARKS). Each
    pinned tree is exported to a temp dir, its own expected-results CSV is read (its header version
    must equal BENCHMARKS[id]['version']) and sampled, and the tree is deleted."""
    from eval import repo
    benchmarks = []
    for spec in specs:
        meta = BENCHMARKS[spec["id"]]
        work = tempfile.mkdtemp(prefix="orion-owasp-sample-", dir=tmp_root)
        try:
            tree = os.path.join(work, "tree")
            repo.export_tree(spec["mirror_dir"], spec["sha"], tree)
            csvs = sorted(f for f in os.listdir(tree) if _ANSWER_CSV.fullmatch(f))
            if len(csvs) != 1:
                raise ValueError(f"{spec['id']}@{spec['sha']}: expected one expectedresults*.csv at the "
                                 f"tree root, found {csvs}")
            csv_path = os.path.join(tree, csvs[0])
            version, rows = read_expected(csv_path)
            if version != meta["version"]:
                raise ValueError(f"{spec['id']}@{spec['sha']}: {csvs[0]} is version {version!r}, "
                                 f"the study uses {meta['version']!r}")
            cases = sample(csv_path, n_per_lang=n_per_lang, seed=seed)
            benchmarks.append({"id": spec["id"], "language": meta["language"], "benchmark_version": version,
                               "repo_url": meta["repo_url"], "pinned_sha": spec["sha"],
                               "expected_results": csvs[0], "expected_results_sha256": _sha256(csv_path),
                               "csv_cases": len(rows), "cases": cases})
        finally:
            shutil.rmtree(work, ignore_errors=True)
    return {"version": 1, "generated": date.today().isoformat(), "seed": seed, "n_per_lang": n_per_lang,
            "note": "OWASP Benchmark false-alarm set (spec 5.4): one targeted-judgement run per case. "
                    "Built by `python -m eval.owasp` from each repo's own expected-results CSV at "
                    "pinned_sha; file/entry read from that tree.",
            "benchmarks": benchmarks}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Write the OWASP Benchmark sample (eval/dataset/owasp_sample.json).")
    ap.add_argument("--java-mirror", required=True)
    ap.add_argument("--java-sha", required=True)
    ap.add_argument("--python-mirror", required=True)
    ap.add_argument("--python-sha", required=True)
    ap.add_argument("--n-per-lang", type=int, default=60)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="eval/dataset/owasp_sample.json")
    args = ap.parse_args(argv)
    data = build_sample([{"id": "owasp-java", "mirror_dir": args.java_mirror, "sha": args.java_sha},
                         {"id": "owasp-python", "mirror_dir": args.python_mirror, "sha": args.python_sha}],
                        n_per_lang=args.n_per_lang, seed=args.seed)
    errs = validate_sample(data)
    if errs:
        for e in errs:
            print(e, flush=True)
        return 2
    with open(args.out, "w") as f:
        json.dump(data, f, indent=1)
        f.write("\n")
    for b in data["benchmarks"]:
        print(f"{b['id']}@{b['pinned_sha'][:12]} ({b['expected_results']}, {b['csv_cases']} cases): "
              f"{len(b['cases'])} sampled", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
