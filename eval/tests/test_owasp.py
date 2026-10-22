import json
import os

import pytest

from eval import owasp

JAVA_DIR = "src/main/java/org/owasp/benchmark/testcode"


def _java_case(tree, name, category="pathtraver"):
    d = tree / JAVA_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.java").write_text(
        "package org.owasp.benchmark.testcode;\n"
        f'@WebServlet(value = "/{category}-00/{name}")\n'
        f"public class {name} extends HttpServlet {{\n"
        "    @Override\n"
        "    public void doGet(HttpServletRequest request, HttpServletResponse response)\n"
        "            throws ServletException, IOException {\n"
        "        doPost(request, response);\n"
        "    }\n"
        "    @Override\n"
        "    public void doPost(HttpServletRequest request, HttpServletResponse response)\n"
        "            throws ServletException, IOException {\n"
        "    }\n"
        "}\n")


def _python_case(tree, name, category="sqli"):
    d = tree / "testcode"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.py").write_text(
        "def init(app):\n\n"
        f"\t@app.route('/benchmark/{category}-00/{name}', methods=['GET'])\n"
        f"\tdef {name}_get():\n"
        f"\t\treturn {name}_post()\n\n"
        f"\t@app.route('/benchmark/{category}-00/{name}', methods=['POST'])\n"
        f"\tdef {name}_post():\n"
        "\t\treturn ''\n")


def test_sample_is_balanced_real_trap_within_category(tmp_path):
    csv = tmp_path / "j.csv"
    rows = ["# header"] + [f"BenchmarkTest{i:05d},pathtraver,{'true' if i%2 else 'false'},22" for i in range(1, 41)]
    csv.write_text("\n".join(rows) + "\n")
    for i in range(1, 41):  # the layout sample() reads file/entry from (ruling 1: never guessed)
        _java_case(tmp_path, f"BenchmarkTest{i:05d}")
    s = owasp.sample(str(csv), n_per_lang=10, seed=0)
    reals = sum(1 for c in s if c["real"]) ; traps = len(s) - reals
    assert abs(reals - traps) <= 1          # balanced within the category
    assert all(c["case_id"].startswith("BenchmarkTest") and c["file"] for c in s)


def test_strip_answers_removes_expected_results(tmp_path):
    (tmp_path / "expectedresults-1.2.csv").write_text("x")
    (tmp_path / "src").mkdir(); (tmp_path / "src" / "BenchmarkTest00001.java").write_text("class A{}")
    removed = owasp.strip_answers(str(tmp_path))
    assert removed and not (tmp_path / "expectedresults-1.2.csv").exists()
    assert (tmp_path / "src" / "BenchmarkTest00001.java").exists()


def test_score_and_youden():
    cases = [{"case_id": "a", "real": True, "file": "A.java"}, {"case_id": "b", "real": False, "file": "B.java"}]
    rows = [owasp.score([{"file": "A.java"}], cases[0]), owasp.score([], cases[1])]
    assert rows[0]["tp"] == 1 and rows[1]["tn"] == 1
    assert owasp.youden(rows) == 1.0


# ---- sample: layout, stratification, determinism ----------------------------------------------

def _csv(path, rows, version="1.2"):
    path.write_text(f"# test name, category, real vulnerability, cwe, Benchmark version: {version}, 2016-06-1\n"
                    + "".join(f"{n},{c},{'true' if r else 'false'},{w}\n" for n, c, r, w in rows))
    return str(path)


def test_sample_resolves_file_and_entry_from_the_java_layout(tmp_path):
    _java_case(tmp_path, "BenchmarkTest00001")
    _java_case(tmp_path, "BenchmarkTest00002")
    csv = _csv(tmp_path / "expectedresults-1.2.csv",
               [("BenchmarkTest00001", "pathtraver", True, 22), ("BenchmarkTest00002", "pathtraver", False, 22)])
    s = owasp.sample(csv, n_per_lang=2, seed=0)
    by_id = {c["case_id"]: c for c in s}
    c1 = by_id["BenchmarkTest00001"]
    assert c1 == {"case_id": "BenchmarkTest00001", "category": "pathtraver", "real": True, "cwe": "CWE-22",
                  "file": f"{JAVA_DIR}/BenchmarkTest00001.java",
                  "entry": "POST /pathtraver-00/BenchmarkTest00001 -> BenchmarkTest00001.doPost"}
    assert by_id["BenchmarkTest00002"]["real"] is False


def test_sample_resolves_file_and_entry_from_the_python_layout(tmp_path):
    _python_case(tmp_path, "BenchmarkTest00007")
    (tmp_path / "templates" / "web" / "sqli-00").mkdir(parents=True)   # same name, not a source file
    (tmp_path / "templates" / "web" / "sqli-00" / "BenchmarkTest00007.html").write_text("<html/>")
    csv = _csv(tmp_path / "expectedresults-0.1.csv", [("BenchmarkTest00007", "sqli", True, 89)], "0.1")
    (c,) = owasp.sample(csv, n_per_lang=1, seed=0)
    assert c["file"] == "testcode/BenchmarkTest00007.py"
    assert c["entry"] == "POST /benchmark/sqli-00/BenchmarkTest00007 -> BenchmarkTest00007_post"


def test_sample_refuses_a_case_whose_source_file_is_missing(tmp_path):
    csv = _csv(tmp_path / "expectedresults-1.2.csv", [("BenchmarkTest00001", "pathtraver", True, 22)])
    with pytest.raises(ValueError, match="BenchmarkTest00001"):
        owasp.sample(csv, n_per_lang=1, seed=0)


def _multi(tmp_path, n=12):
    rows = []
    for cat, w in (("sqli", 89), ("xss", 79), ("cmdi", 78)):
        for i in range(n):
            name = f"BenchmarkTest{len(rows) + 1:05d}"
            rows.append((name, cat, i % 3 == 0, w))   # a third real: real and trap pools differ in size
            _java_case(tmp_path, name, cat)
    return _csv(tmp_path / "expectedresults-1.2.csv", rows)


def test_sample_stratifies_by_category_and_balances_each(tmp_path):
    csv = _multi(tmp_path)
    s = owasp.sample(csv, n_per_lang=10, seed=0)
    assert len(s) == 10 and len({c["case_id"] for c in s}) == 10
    per = {}
    for c in s:
        per.setdefault(c["category"], []).append(c["real"])
    assert sorted(len(v) for v in per.values()) == [3, 3, 4]       # 10 over 3 categories
    for v in per.values():
        assert abs(sum(v) - (len(v) - sum(v))) <= 1                # real/trap at most 1 apart
    reals = sum(c["real"] for c in s)
    assert abs(reals - (len(s) - reals)) <= 1                      # and overall


def test_sample_is_deterministic_for_a_seed(tmp_path):
    csv = _multi(tmp_path)
    a = owasp.sample(csv, n_per_lang=10, seed=0)
    assert a == owasp.sample(csv, n_per_lang=10, seed=0)
    assert any(owasp.sample(csv, n_per_lang=10, seed=s) != a for s in (1, 2, 3))


def test_sample_refuses_when_a_pool_is_too_small_to_balance(tmp_path):
    rows = [(f"BenchmarkTest{i:05d}", "sqli", i == 1, 89) for i in range(1, 9)]   # one real case
    for n, *_ in rows:
        _java_case(tmp_path, n, "sqli")
    csv = _csv(tmp_path / "expectedresults-1.2.csv", rows)
    with pytest.raises(ValueError, match="sqli"):
        owasp.sample(csv, n_per_lang=6, seed=0)


def test_read_expected_parses_version_and_rows(tmp_path):
    csv = _csv(tmp_path / "e.csv", [("BenchmarkTest00001", "sqli", False, 89)], "0.1")
    version, rows = owasp.read_expected(csv)
    assert version == "0.1"
    assert rows == [{"case_id": "BenchmarkTest00001", "category": "sqli", "real": False, "cwe": "CWE-89"}]


def test_read_expected_refuses_a_bad_real_column(tmp_path):
    (tmp_path / "e.csv").write_text("# h\nBenchmarkTest00001,sqli,maybe,89\n")
    with pytest.raises(ValueError, match="maybe"):
        owasp.read_expected(str(tmp_path / "e.csv"))


# ---- strip_answers -----------------------------------------------------------------------------

def test_strip_answers_removes_metadata_scorecards_and_results_but_never_build_files(tmp_path):
    t = tmp_path
    for rel in ("pom.xml", "requirements.txt", "setup.py", "src/main/webapp/WEB-INF/web.xml",
                f"{JAVA_DIR}/BenchmarkTest00001.java", "src/config/local/benchmark.xml",
                "results/pom.xml",                       # a build-file name is kept even here
                "expectedresults-1.2.csv", "sub/ExpectedResults-0.1.csv",
                f"{JAVA_DIR}/BenchmarkTest00001.xml",
                "results/Benchmark_1.2-findbugs.xml", "results/.placeholder",
                "scorecard/Benchmark_v1.2_Scorecard_for_PMD.csv", "scorecard/img/x.png"):
        p = t / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    removed = owasp.strip_answers(str(t))
    assert removed == sorted([
        "expectedresults-1.2.csv", "sub/ExpectedResults-0.1.csv", f"{JAVA_DIR}/BenchmarkTest00001.xml",
        "results/.placeholder", "results/Benchmark_1.2-findbugs.xml",
        "scorecard/Benchmark_v1.2_Scorecard_for_PMD.csv", "scorecard/img/x.png"])
    for kept in ("pom.xml", "requirements.txt", "setup.py", "src/main/webapp/WEB-INF/web.xml",
                 f"{JAVA_DIR}/BenchmarkTest00001.java", "src/config/local/benchmark.xml", "results/pom.xml"):
        assert (t / kept).exists(), kept
    assert not (t / "scorecard").exists()                    # emptied answer dir is gone too
    assert owasp.strip_answers(str(t)) == []                 # idempotent


def test_strip_answers_never_removes_pom_xml(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    (tmp_path / "expectedresults-1.2.csv").write_text("x")
    assert owasp.strip_answers(str(tmp_path)) == ["expectedresults-1.2.csv"]
    assert (tmp_path / "pom.xml").read_text() == "<project/>"


def test_strip_answers_only_treats_top_level_results_dirs_as_answers(tmp_path):
    p = tmp_path / "src" / "results" / "Results.java"
    p.parent.mkdir(parents=True)
    p.write_text("class Results{}")
    assert owasp.strip_answers(str(tmp_path)) == []
    assert p.exists()


# ---- score / youden ----------------------------------------------------------------------------

CASE = {"case_id": "BenchmarkTest00001", "real": True,
        "file": f"{JAVA_DIR}/BenchmarkTest00001.java"}


@pytest.mark.parametrize("found", [
    f"{JAVA_DIR}/BenchmarkTest00001.java",
    f"./{JAVA_DIR}/BenchmarkTest00001.java",
    f"/private/tmp/orion-eval-trees/plain-opus5/owasp-java/abc/BenchmarkTest00001/1/tree/{JAVA_DIR}/BenchmarkTest00001.java",
    "BenchmarkTest00001.java",
])
def test_score_flags_a_finding_in_the_case_file_after_normalising(found):
    assert owasp.score([{"file": found}], CASE)["flagged"] is True


@pytest.mark.parametrize("found", [f"{JAVA_DIR}/BenchmarkTest00002.java", None, ""])
def test_score_ignores_findings_in_other_files_or_without_a_file(found):
    row = owasp.score([{"file": found}], CASE)
    assert row == {"case_id": "BenchmarkTest00001", "real": True, "flagged": False,
                   "tp": 0, "fp": 0, "tn": 0, "fn": 1}


def test_score_strips_a_given_tree_root():
    found = "/t/tree/" + CASE["file"]
    assert owasp.norm_path(found, root="/t/tree") == CASE["file"]
    assert owasp.score([{"file": found}], CASE, root="/t/tree/")["flagged"] is True


def test_score_trap_flagged_is_a_false_positive():
    row = owasp.score([{"file": "B.java"}], {"case_id": "b", "real": False, "file": "B.java"})
    assert (row["tp"], row["fp"], row["tn"], row["fn"]) == (0, 1, 0, 0)


def test_youden_is_tpr_minus_fpr():
    rows = [{"tp": 1, "fp": 0, "tn": 0, "fn": 0}, {"tp": 0, "fp": 0, "tn": 0, "fn": 1},
            {"tp": 0, "fp": 1, "tn": 0, "fn": 0}, {"tp": 0, "fp": 0, "tn": 1, "fn": 0},
            {"tp": 0, "fp": 0, "tn": 1, "fn": 0}, {"tp": 0, "fp": 0, "tn": 1, "fn": 0}]
    assert owasp.youden(rows) == pytest.approx(0.5 - 0.25)


@pytest.mark.parametrize("rows", [
    [],
    [{"tp": 1, "fp": 0, "tn": 0, "fn": 0}],                    # no trap cases: FPR undefined
    [{"tp": 0, "fp": 0, "tn": 1, "fn": 0}],                    # no real cases: TPR undefined
])
def test_youden_is_none_when_undefined(rows):
    assert owasp.youden(rows) is None


# ---- case_flows --------------------------------------------------------------------------------

class _Graph:
    """tools.run_cypher's view of Neo4j (EXPLAIN, then the query): three CandidateFlows, whose path
    nodes sit in the given files."""

    def __init__(self, paths):
        self.paths = paths   # flow rank -> [(uid, file)]

    def run_cypher(self, scan_id, query, *, limit=None, **kw):
        if query.startswith("EXPLAIN"):
            return {"query_type": "r"}
        if "CandidateFlow" in query:
            rows = [{"rank": r, "source_uid": p[0][0], "sink_uid": p[-1][0], "sink_category": "sql",
                     "path_uids": json.dumps([u for u, _ in p])} for r, p in sorted(self.paths.items())]
            self.flow_limit = limit
            return {"rows": rows, "row_count": len(rows)}
        import re
        files = {u: f for p in self.paths.values() for u, f in p}
        rows = [{"uid": u, "file": files[u], "function": "doPost", "line": 3, "code": "q(x)"}
                for u in re.findall(r"'(u\d+)'", query)]
        return {"rows": rows, "row_count": len(rows)}


def test_case_flows_keeps_only_flows_whose_path_touches_the_case_file():
    case_file = CASE["file"]
    g = _Graph({0: [("u1", "src/helpers/Utils.java"), ("u2", "src/helpers/Utils.java")],
                1: [("u3", "src/helpers/Utils.java"), ("u4", case_file)],          # sink in the case
                2: [("u5", case_file), ("u6", "src/helpers/Db.java")],              # source in the case
                3: [("u7", f"{JAVA_DIR}/BenchmarkTest00010.java")]})
    flows = owasp.case_flows(g, "s1", CASE)
    assert [f["rank"] for f in flows] == [1, 2]
    assert [n["file"] for n in flows[0]["nodes"]] == ["src/helpers/Utils.java", case_file]
    assert flows[0]["flow_id"] == "F1"                       # flow_slice shape, as discover_lm takes it
    assert g.flow_limit >= 300                               # every CandidateFlow of the scan is read


def test_case_flows_is_empty_when_no_flow_touches_the_case():
    g = _Graph({0: [("u1", "src/helpers/Utils.java")]})
    assert owasp.case_flows(g, "s1", CASE) == []


def test_case_flow_limit_covers_every_candidate_flow_pathfind_persists():
    from orion.graph import pathfind
    assert owasp.CASE_FLOW_LIMIT >= pathfind._MAX_FLOWS


# ---- the sample file ---------------------------------------------------------------------------

def _sample_file(**over):
    case = {"case_id": "BenchmarkTest00001", "category": "sqli", "real": True, "cwe": "CWE-89",
            "file": "testcode/BenchmarkTest00001.py",
            "entry": "POST /benchmark/sqli-00/BenchmarkTest00001 -> BenchmarkTest00001_post"}
    bench = {"id": "owasp-python", "language": "python", "benchmark_version": "0.1",
             "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkPython",
             "pinned_sha": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba", "cases": [case]}
    data = {"version": 1, "seed": 0, "n_per_lang": 60, "benchmarks": [bench]}
    for k, v in over.items():
        if k in bench:
            bench[k] = v
        else:
            data[k] = v
    return data


def test_validate_sample_accepts_a_good_file():
    assert owasp.validate_sample(_sample_file()) == []


def test_validate_sample_refuses_duplicate_case_ids():
    data = _sample_file()
    cases = data["benchmarks"][0]["cases"]
    cases.append(dict(cases[0]))
    assert any("duplicate case_id BenchmarkTest00001" in e for e in owasp.validate_sample(data))


@pytest.mark.parametrize("sha", [None, "", "HEAD", "f129148"])
def test_validate_sample_refuses_a_missing_or_unpinned_sha(sha):
    assert any("pinned_sha" in e for e in owasp.validate_sample(_sample_file(pinned_sha=sha)))


def test_validate_sample_refuses_an_unknown_category_and_a_missing_seed():
    data = _sample_file()
    data["benchmarks"][0]["cases"][0]["category"] = "nosuch"
    del data["seed"]
    errs = owasp.validate_sample(data)
    assert any("nosuch" in e for e in errs) and any("seed" in e for e in errs)


def test_validate_sample_allows_the_same_case_id_in_two_benchmarks():
    data = _sample_file()
    java = dict(data["benchmarks"][0], id="owasp-java", language="java",
                repo_url="https://github.com/OWASP-Benchmark/BenchmarkJava",
                cases=[dict(data["benchmarks"][0]["cases"][0], file=f"{JAVA_DIR}/BenchmarkTest00001.java")])
    data["benchmarks"].append(java)
    assert owasp.validate_sample(data) == []                 # the run key is (repo, commit, case_id)
    data["benchmarks"][1]["id"] = "owasp-python"
    assert any("duplicate benchmark id" in e for e in owasp.validate_sample(data))


def test_load_sample_reads_the_committed_file():
    path = os.path.join(os.path.dirname(owasp.__file__), "dataset", "owasp_sample.json")
    data = owasp.load_sample(path)
    assert owasp.validate_sample(data) == []
    assert data["seed"] == 0
    assert {b["id"]: len(b["cases"]) for b in data["benchmarks"]} == {"owasp-java": 60, "owasp-python": 60}
    for b in data["benchmarks"]:
        per = {}
        for c in b["cases"]:
            per.setdefault(c["category"], []).append(c["real"])
        assert all(abs(sum(v) - (len(v) - sum(v))) <= 1 for v in per.values())
