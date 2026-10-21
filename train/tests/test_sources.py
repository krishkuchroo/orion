import gzip
import json
import zipfile

from train import sources

SHA1 = "a" * 40
SHA2 = "b" * 40
SHA3 = "c" * 40


def _zip(tmp_path, records, name="all.zip"):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return str(p)


def _ghsa(gid, *, published="2025-01-02T10:00:00Z", refs=(), aliases=("CVE-2025-1",), cwes=("CWE-79",),
          eco="npm", pkg="pkg", ranges=(), withdrawn=None):
    rec = {"id": gid, "published": published, "aliases": list(aliases),
           "affected": [{"package": {"ecosystem": eco, "name": pkg}, "ranges": list(ranges)}],
           "references": [{"type": t, "url": u} for t, u in refs],
           "database_specific": {"github_reviewed": True, "cwe_ids": list(cwes)}}
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


# ---- small helpers ----------------------------------------------------------------------------

def test_norm_cwe_and_cwe_class():
    assert sources.norm_cwe("CWE-022") == "CWE-22"
    assert sources.norm_cwe(79) == "CWE-79"
    assert sources.norm_cwe("NVD-CWE-noinfo") is None
    assert sources.cwe_class(["CWE-20", "CWE-79"]) == "dataflow"
    assert sources.cwe_class(["CWE-943"]) == "dataflow"       # close relative (NoSQL injection)
    assert sources.cwe_class(["CWE-1336"]) == "dataflow"      # template injection
    assert sources.cwe_class(["CWE-20"]) == "other"
    assert sources.cwe_class([]) == "unknown"                  # no CWE at all is not silently "other"


def test_norm_repo_github_only():
    assert sources.github_repo("https://github.com/Owner/Repo.git") == "owner/repo"
    assert sources.github_repo("https://github.com/o/r/commit/abc1234") == "o/r"
    assert sources.github_repo("https://github.com/advisories/GHSA-xxxx") is None
    assert sources.github_repo("https://gitlab.com/o/r") is None


def test_language_from_files():
    assert sources.language_from_files(["src/a.ts", "README.md"]) == "js"
    assert sources.language_from_files(["a.py", "tests/test_a.py"]) == "py"
    assert sources.language_from_files(["src/main/java/A.java", "pom.xml"]) == "java"
    assert sources.language_from_files(["a.py", "b.js"]) == "mixed"
    assert sources.language_from_files(["x.php"]) == "php"
    assert sources.language_from_files(["README.md", "templates/x.html"]) is None


# ---- OSV ----------------------------------------------------------------------------------------

def test_osv_pairs_extracts_commit_fix_fields(tmp_path):
    z = _zip(tmp_path, [_ghsa("GHSA-aaaa-bbbb-cccc", refs=[
        ("ADVISORY", "https://nvd.nist.gov/vuln/detail/CVE-2025-1"),
        ("WEB", f"https://github.com/Owner/Repo/commit/{SHA1}"),
        ("WEB", f"https://github.com/Owner/Repo/commit/{SHA2}")])])
    [p] = sources.osv_pairs(z)
    assert p["id"] == "CVE-2025-1" and p["cve"] == "CVE-2025-1" and p["ghsa"] == "GHSA-aaaa-bbbb-cccc"
    assert p["source"] == "osv-npm" and p["source_id"] == "GHSA-aaaa-bbbb-cccc"
    assert p["repo"] == "owner/repo" and p["fix_sha"] == SHA1 and p["fix_shas"] == [SHA1, SHA2]
    assert p["cwe"] == ["CWE-79"] and p["cwe_class"] == "dataflow"
    assert p["language"] == "js" and p["language_basis"] == "ecosystem"
    assert p["advisory_published"] == "2025-01-02"
    assert p["packages"] == [["npm", "pkg"]]
    assert set(p["aliases"]) == {"CVE-2025-1", "GHSA-aaaa-bbbb-cccc"}
    assert p["fix_commit_date"] is None and p["n_files"] is None and p["enrich_status"] == "pending"


def test_osv_skips_malware_and_withdrawn_and_counts(tmp_path):
    z = _zip(tmp_path, [{"id": "MAL-2025-1", "published": "2025-01-01T00:00:00Z"},
                        _ghsa("GHSA-wwww", withdrawn="2025-02-01T00:00:00Z"),
                        _ghsa("GHSA-keep", refs=[("WEB", f"https://github.com/o/r/commit/{SHA1}")])])
    stats = {}
    rows = sources.osv_pairs(z, stats=stats)
    assert [r["source_id"] for r in rows] == ["GHSA-keep"]
    assert stats["skipped_malware"] == 1 and stats["skipped_withdrawn"] == 1


def test_osv_prefers_git_range_fix_then_fix_typed_ref(tmp_path):
    rec = _ghsa("PYSEC-2021-1", eco="PyPI", aliases=("CVE-2021-9",), cwes=(), refs=[
        ("WEB", f"https://github.com/o/r/commit/{SHA2}"),
        ("FIX", f"https://github.com/o/r/commit/{SHA3}")],
        ranges=[{"type": "GIT", "repo": "https://github.com/o/r", "events": [{"introduced": "0"}, {"fixed": SHA1}]}])
    rec["database_specific"] = {}
    [p] = sources.osv_pairs(_zip(tmp_path, [rec]))
    assert p["fix_sha"] == SHA1 and p["fix_shas"] == [SHA1, SHA3, SHA2]
    assert p["language"] == "py" and p["source"] == "osv-pypi" and p["cwe_class"] == "unknown"


def test_osv_pull_request_links(tmp_path):
    pr_only = _ghsa("GHSA-pr", aliases=("CVE-2025-2",), refs=[("WEB", "https://github.com/o/r/pull/12")])
    pr_commit = _ghsa("GHSA-prc", aliases=("CVE-2025-3",), refs=[("WEB", f"https://github.com/o/r/pull/3/commits/{SHA1}")])
    nothing = _ghsa("GHSA-none", aliases=("CVE-2025-4",), refs=[("WEB", "https://example.com/blog")])
    rows = {r["source_id"]: r for r in sources.osv_pairs(_zip(tmp_path, [pr_only, pr_commit, nothing]))}
    assert rows["GHSA-pr"]["fix_sha"] is None and rows["GHSA-pr"]["fix_pr"] == 12 and rows["GHSA-pr"]["repo"] == "o/r"
    assert rows["GHSA-prc"]["fix_sha"] == SHA1
    assert rows["GHSA-none"]["repo"] is None and rows["GHSA-none"]["fix_sha"] is None


def test_post_cutoff_leak_sets(tmp_path):
    recs = [
        _ghsa("GHSA-on", published="2026-05-31T00:00:00Z", pkg="onpkg",
              refs=[("WEB", "https://github.com/On/Cutoff/issues/4"), ("WEB", "https://github.com/advisories/GHSA-on")]),
        _ghsa("GHSA-pre", published="2026-05-30T23:59:59Z", pkg="prepkg",
              refs=[("WEB", f"https://github.com/pre/repo/commit/{SHA1}")]),
        _ghsa("GHSA-wd", published="2026-07-01T00:00:00Z", withdrawn="2026-07-02T00:00:00Z",
              refs=[("WEB", "https://github.com/withdrawn/repo")]),
        _ghsa("GHSA-git", published="2026-08-01T00:00:00Z",
              ranges=[{"type": "GIT", "repo": "https://github.com/git/range", "events": [{"fixed": SHA2}]}]),
        {"id": "MAL-2026-9", "published": "2026-09-01T00:00:00Z",
         "affected": [{"package": {"ecosystem": "npm", "name": "evil"}}],
         "references": [{"type": "WEB", "url": "https://github.com/mal/repo"}]},
    ]
    leak = sources.post_cutoff(_zip(tmp_path, recs))
    assert leak["repos"] == {"on/cutoff", "withdrawn/repo", "git/range"}
    assert ("npm", "onpkg") in leak["packages"] and ("npm", "prepkg") not in leak["packages"]
    assert ("npm", "evil") not in leak["packages"]
    assert leak["malware_repos"] == {"mal/repo"}
    assert sources.post_cutoff_repos(_zip(tmp_path, recs, "b.zip")) == leak["repos"]


# ---- ready-made + other datasets ----------------------------------------------------------------

def test_readymade_cwe_bench_java(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "advisory").mkdir()
    (tmp_path / "data" / "project_info.csv").write_text(
        "id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,github_tag,github_url,"
        "advisory_id,buggy_commit_id,fix_commit_ids\n"
        f"1,Ow__Re_CVE-2020-1_1.0,CVE-2020-1,CWE-022,Path Traversal,Ow,Re,1.0,https://github.com/Ow/Re,"
        f"GHSA-1111,{SHA3},{SHA1};{SHA2}\n")
    (tmp_path / "advisory" / "Ow__Re_CVE-2020-1_1.0.json").write_text(
        json.dumps({"id": "GHSA-1111", "published": "2021-03-04T00:00:00Z", "aliases": ["CVE-2020-1"]}))
    [p] = sources.readymade("cwe-bench-java", str(tmp_path))
    assert p["id"] == "CVE-2020-1" and p["ghsa"] == "GHSA-1111" and p["source"] == "cwe-bench-java"
    assert p["repo"] == "ow/re" and p["fix_sha"] == SHA1 and p["fix_shas"] == [SHA1, SHA2] and p["vuln_sha"] == SHA3
    assert p["cwe"] == ["CWE-22"] and p["language"] == "java" and p["advisory_published"] == "2021-03-04"


def test_readymade_openssf(tmp_path):
    (tmp_path / "CVEs").mkdir()
    (tmp_path / "CVEs" / "CVE-2018-1.json").write_text(json.dumps({
        "CVE": "CVE-2018-1", "state": "PUBLISHED", "repository": "https://github.com/lo/dash.git",
        "prePatch": {"commit": SHA1, "weaknesses": [{"location": {"file": "a.js", "line": 3}, "explanation": "x"}]},
        "postPatch": {"commit": SHA2}, "CWEs": ["CWE-078", "CWE-400"]}))
    (tmp_path / "CVEs" / "CVE-2018-2.json").write_text(json.dumps({"CVE": "CVE-2018-2", "state": "REJECTED"}))
    stats = {}
    [p] = sources.readymade("openssf", str(tmp_path), stats=stats)
    assert p["repo"] == "lo/dash" and p["vuln_sha"] == SHA1 and p["fix_sha"] == SHA2
    assert p["cwe"] == ["CWE-78", "CWE-400"] and p["cwe_class"] == "dataflow" and p["language"] == "js"
    assert p["weaknesses"] == [{"file": "a.js", "line": 3, "explanation": "x"}]
    assert p["advisory_published"] is None
    assert stats["skipped_state:REJECTED"] == 1


def test_readymade_vul4j(tmp_path):
    f = tmp_path / "v.csv"
    f.write_text("no,vul_id,cve_id,cwe_id,cwe_name,owasp_id,repo_slug,human_patch\n"
                 f"2,VUL4J-2,CVE-2017-5662,CWE-611,XXE,A4,apache/batik,https://github.com/apache/xmlgraphics-batik/commit/{SHA1}\n"
                 f"3,VUL4J-3,NA,Not Mapping,,,o/r,https://github.com/o/r/commit/{SHA2}\n")
    a, b = sources.readymade("vul4j", str(f))
    assert a["id"] == "CVE-2017-5662" and a["repo"] == "apache/xmlgraphics-batik" and a["fix_sha"] == SHA1
    assert a["cwe"] == ["CWE-611"] and a["language"] == "java"
    assert b["id"] == "VUL4J-3" and b["cve"] is None and b["cwe"] == [] and b["cwe_class"] == "unknown"


def test_sap_kb(tmp_path):
    for vid, body in {
        "CVE-2018-1": f"vulnerability_id: CVE-2018-1\nfixes:\n- id: DEFAULT_BRANCH\n  commits:\n  - id: {SHA1}\n"
                      f"    repository: https://github.com/Ping/ldapsdk\nartifacts:\n- id: pkg:maven/com.u/ldap@3.2.1\n"
                      f"  affected: true\n",
        "CVE-2018-2": f"vulnerability_id: CVE-2018-2\nfixes:\n- id: x\n  commits:\n  - id: {SHA2}\n"
                      f"    repository: https://gitbox.apache.org/repos/asf/foo\n",
        "CVE-2018-3": f"vulnerability_id: CVE-2018-3\nfixes:\n- id: x\n  commits:\n  - id: {SHA3}\n"
                      f"    repository: https://github.com/o/r\n",
    }.items():
        (tmp_path / "statements" / vid).mkdir(parents=True)
        (tmp_path / "statements" / vid / "statement.yaml").write_text(body)
    rows = {r["id"]: r for r in sources.sap_kb(str(tmp_path))}
    a, b, c = rows["CVE-2018-1"], rows["CVE-2018-2"], rows["CVE-2018-3"]
    assert a["repo"] == "ping/ldapsdk" and a["fix_sha"] == SHA1 and a["language"] == "java"
    assert a["language_basis"] == "purl" and a["packages"] == [["maven", "com.u:ldap"]]
    assert b["repo"] is None and b["repo_url"] == "https://gitbox.apache.org/repos/asf/foo"
    assert c["language"] is None and c["cwe_class"] == "unknown"


def test_crossvul_groups_commits_per_cve_and_repo(tmp_path):
    f = tmp_path / "metadata.json"
    f.write_text(json.dumps([
        {"cwe": "CWE-79", "cve": "CVE-2018-9", "url": f"https://github.com/o/r/commit/{SHA1}",
         "files": [{"database_name": "bad_0_0", "original_name": "a.py"}, {"database_name": "good_0_0", "original_name": "a.py"}]},
        {"cwe": "CWE-79", "cve": "CVE-2018-9", "url": f"https://github.com/o/r/commit/{SHA2}",
         "files": [{"database_name": "bad_1_0", "original_name": "b.py"}]},
        {"cwe": "None", "cve": "CVE-2018-8", "url": f"https://github.com/c/c/commit/{SHA3}",
         "files": [{"database_name": "bad_2_0", "original_name": "x.c"}]},
    ]))
    rows = {r["id"]: r for r in sources.crossvul(str(f))}
    assert rows["CVE-2018-9"]["fix_shas"] == [SHA1, SHA2] and rows["CVE-2018-9"]["language"] == "py"
    assert rows["CVE-2018-8"]["language"] == "c" and rows["CVE-2018-8"]["cwe"] == []


_DUMP = """PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "fixes" (
"cve_id" TEXT,
  "hash" TEXT,
  "repo_url" TEXT
);
INSERT INTO fixes VALUES('CVE-2019-1','{s1}','https://github.com/O/R');
INSERT INTO fixes VALUES('CVE-2019-1','{s2}','https://github.com/O/R');
INSERT INTO fixes VALUES('CVE-2019-2','{s3}','https://gitlab.com/x/y');
CREATE TABLE IF NOT EXISTS "commits" (
"hash" TEXT,
  "repo_url" TEXT,
  "author_date" TEXT,
  "committer_date" TEXT,
  "msg" TEXT
);
INSERT INTO commits VALUES('{s1}','https://github.com/O/R','2019-03-02 10:00:00+00:00','2019-03-03 01:00:00+02:00','second');
INSERT INTO commits VALUES('{s2}','https://github.com/O/R','2019-01-01 10:00:00+00:00','2019-01-01 10:00:00+00:00','it''s
multi-line);
INSERT INTO fixes VALUES(''fake'');
done');
CREATE TABLE IF NOT EXISTS "file_change" (
"file_change_id" TEXT,
  "hash" TEXT,
  "filename" TEXT,
  "old_path" TEXT,
  "new_path" TEXT,
  "code_before" TEXT,
  "programming_language" TEXT
);
INSERT INTO file_change VALUES('1','{s2}','a.py','src/a.py','src/a.py','x = ''1''
y = 2',NULL);
INSERT INTO file_change VALUES('2','{s2}','test_a.py','tests/test_a.py','tests/test_a.py',NULL,'Python');
INSERT INTO file_change VALUES('3','{s1}','b.py','None','src/b.py',NULL,'Python');
CREATE TABLE IF NOT EXISTS "cve" (
"cve_id" TEXT,
  "published_date" TEXT,
  "description" TEXT
);
INSERT INTO cve VALUES('CVE-2019-1','2019-04-05T17:29Z','desc');
CREATE TABLE IF NOT EXISTS "cwe_classification" (
"cve_id" TEXT,
  "cwe_id" TEXT
);
INSERT INTO cwe_classification VALUES('CVE-2019-1','CWE-89');
CREATE TABLE IF NOT EXISTS "repository" (
"repo_url" TEXT,
  "repo_language" TEXT
);
INSERT INTO repository VALUES('https://github.com/O/R','Python');
COMMIT;
""".format(s1=SHA1, s2=SHA2, s3=SHA3)


def test_cvefixes_parses_sqlite_dump_without_executing_it(tmp_path):
    f = tmp_path / "dump.sql.gz"
    with gzip.open(f, "wt") as g:
        g.write(_DUMP)
    rows = {r["id"]: r for r in sources.cvefixes(str(f))}
    a = rows["CVE-2019-1"]
    assert a["repo"] == "o/r" and a["fix_shas"] == [SHA2, SHA1] and a["fix_sha"] == SHA2   # earliest commit first
    assert a["advisory_published"] == "2019-04-05" and a["cwe"] == ["CWE-89"] and a["cwe_class"] == "dataflow"
    assert a["language"] == "py" and a["enrich_status"] == "ok" and a["enrich_basis"] == "cvefixes"
    assert a["fix_commit_date"] == "2019-01-01" and a["n_files"] == 1 and a["n_files_total"] == 2
    assert a["n_files_lang"] == 1
    b = rows["CVE-2019-2"]
    assert b["repo"] is None and b["repo_url"] == "https://gitlab.com/x/y"


def test_fill_advisory_dates_from_alias_index():
    rows = [{"id": "CVE-1", "aliases": ["CVE-1", "GHSA-1"], "advisory_published": "2021-05-01", "source": "osv-npm"},
            {"id": "PYSEC-1", "aliases": ["PYSEC-1", "CVE-1"], "advisory_published": "2020-01-01", "source": "osv-pypi"},
            {"id": "CVE-1", "aliases": ["CVE-1"], "advisory_published": None, "source": "vul4j"},
            {"id": "CVE-2", "aliases": ["CVE-2"], "advisory_published": None, "source": "vul4j"}]
    idx = sources.advisory_date_index(rows)
    out = sources.fill_advisory_dates(rows, idx)
    assert out[2]["advisory_published"] == "2020-01-01" and out[2]["advisory_published_basis"] == "alias_index"
    assert out[3]["advisory_published"] is None
    assert out[0]["advisory_published"] == "2021-05-01"          # a row's own date is never overwritten


def test_osv_row_uses_the_exports_ecosystem_for_multi_ecosystem_advisories(tmp_path):
    rec = _ghsa("GHSA-multi", refs=[("WEB", f"https://github.com/o/r/commit/{SHA1}")])
    rec["affected"] = [{"package": {"ecosystem": "crates.io", "name": "x"}}, {"package": {"ecosystem": "npm", "name": "y"}}]
    [p] = sources.osv_pairs(_zip(tmp_path, [rec]), ecosystem="npm")
    assert p["source"] == "osv-npm" and p["language"] == "js"


def test_post_cutoff_reports_fix_link_repos_separately(tmp_path):
    rec = _ghsa("GHSA-x", published="2026-07-01T00:00:00Z",
                refs=[("WEB", f"https://github.com/fix/repo/commit/{SHA1}"), ("WEB", "https://github.com/up/stream/issues/1")])
    leak = sources.post_cutoff(_zip(tmp_path, [rec]))
    assert leak["repos"] == {"fix/repo", "up/stream"} and leak["repos_fix_links"] == {"fix/repo"}


# ---- sources added 2026-10-18 (coordinator request) ---------------------------------------------

def test_cwe_bench_java_v2_layout_with_fix_methods_and_source_sink(tmp_path):
    (tmp_path / "project_info.csv").write_text(
        "id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,github_tag,github_url,"
        "advisory_id,buggy_commit_id,fix_commit_ids\n"
        f"1,kc_CVE-2025-1_1,CVE-2025-1,CWE-79,XSS,keycloak,keycloak,1,https://github.com/keycloak/keycloak,,{SHA3},{SHA1}\n")
    (tmp_path / "fix_info.csv").write_text(
        "project_slug,cve_id,github_username,github_repository_name,commit,file,class,class_start,class_end,method,"
        f"method_start,method_end,signature\nkc_CVE-2025-1_1,CVE-2025-1,keycloak,keycloak,{SHA1},A.java,A,1,90,run,10,20,void run()\n")
    (tmp_path / "fix_info_source_sink.csv").write_text(
        "project_slug,cve_id,github_username,github_repository_name,commit,file,class,class_start,class_end,method,"
        "method_start,method_end,signature,Done,Link,Source,Source Line,Sink,Sink Line\n"
        f"keycloak_CVE-2025-1_1,CVE-2025-1,keycloak,keycloak,{SHA1},A.java,A,1,90,run,10,20,void run(),1,x,userCtx,12,setNote(x),17\n")
    [p] = sources.readymade("cwe-bench-java", str(tmp_path))
    assert p["repo"] == "keycloak/keycloak" and p["fix_sha"] == SHA1 and p["advisory_published"] is None
    assert p["fix_methods"] == [{"commit": SHA1, "file": "A.java", "class": "A", "method": "run",
                                 "method_start": "10", "method_end": "20"}]
    assert p["source_sink"] == [{"file": "A.java", "method": "run", "source": "userCtx", "source_line": "12",
                                 "sink": "setNote(x)", "sink_line": "17"}]


def test_vulcan_keeps_source_sink_locations(tmp_path):
    rev = tmp_path / "reviews"
    rev.mkdir()
    (rev / "1003_GHSA-vfp9.json").write_text(json.dumps({
        "advisory": {"id": "GHSA-vfp9", "npm_id": "1003", "cve": "CVE-2018-3733", "cwe": "CWE-79"},
        "correct_cwe": "CWE-22",
        "correct_package_link": "https://registry.npmjs.org/@sc/crud-file-server/-/crud-file-server-0.8.0.tgz",
        "vulnerability": {"vulnerability_location": [{"source": {"file": "a.js", "lineno": 6, "code": "x"},
                                                      "sink": {"file": "a.js", "lineno": 91, "code": "y"}}]},
        "patch": [{"url": [f"https://github.com/omph/crud/commit/{SHA1}"]}, {"file_path": "patches/x.patch"}]}))
    [p] = sources.vulcan(str(rev))
    assert p["id"] == "CVE-2018-3733" and p["ghsa"] == "GHSA-vfp9" and "npm:1003" in p["aliases"]
    assert p["cwe"] == ["CWE-22"] and p["advisory_cwe"] == "CWE-79" and p["cwe_class"] == "dataflow"
    assert p["repo"] == "omph/crud" and p["fix_sha"] == SHA1 and p["language"] == "js"
    assert p["packages"] == [["npm", "@sc/crud-file-server"]] and p["package_version"] == "0.8.0"
    assert p["locations"][0]["sink"]["lineno"] == 91


def test_secbench_js(tmp_path):
    for cls, name, body in [
        ("path-traversal", "here_3.1.0", {"id": "", "dependencies": {"@v/here": "3.1.0"},
                                          "links": {"source1": "https://security.snyk.io/vuln/SNYK-JS-X-1",
                                                    "source2": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"},
                                          "fixedVersion": "3.2.2", "fixCommit": f"https://github.com/v/here/commit/{SHA1}",
                                          "sink": "lib/read-file.js:11:19"}),
        ("redos", "ms_1.0", {"id": "CVE-2017-9", "dependencies": {"ms": "1.0"}, "links": {}, "fixedVersion": "n/a",
                             "fixCommit": "n/a", "sink": ""}),
    ]:
        (tmp_path / cls / name).mkdir(parents=True)
        (tmp_path / cls / name / "package.json").write_text(json.dumps(body))
    rows = {r["source_id"]: r for r in sources.secbench_js(str(tmp_path))}
    a, b = rows["path-traversal/here_3.1.0"], rows["redos/ms_1.0"]
    assert a["id"] == "GHSA-aaaa-bbbb-cccc" and a["repo"] == "v/here" and a["fix_sha"] == SHA1
    assert a["packages"] == [["npm", "@v/here"]] and a["package_version"] == "3.1.0"
    assert a["vuln_class"] == "path-traversal" and a["cwe"] == [] and a["cwe_class"] == "dataflow"
    assert a["cwe_class_basis"] == "vuln_class" and a["sink_location"] == "lib/read-file.js:11:19"
    assert b["fix_sha"] is None and b["cwe_class"] == "other" and b["id"] == "CVE-2017-9"


def test_javavulbench_groups_methods_per_cve_and_repo(tmp_path):
    f = tmp_path / "benchmark.jsonl"
    base = {"cve_id": "CVE-2023-7171", "cwe_ids": ["CWE-79"], "repo_full_name": "Ow/Novel", "commit_sha": SHA1,
            "published_date": "2023-12-29T18:15:39.517000", "file_path": "A.java", "method_name": "save",
            "start_line": 82, "end_line": 92, "vulnerable_lines": [83]}
    f.write_text("\n".join(json.dumps(dict(base, label=l)) for l in ("vulnerable", "patched", "not_vulnerable")) + "\n")
    [p] = sources.javavulbench(str(f))
    assert p["repo"] == "ow/novel" and p["fix_sha"] == SHA1 and p["advisory_published"] == "2023-12-29"
    assert p["cwe"] == ["CWE-79"] and p["language"] == "java"
    assert p["vuln_methods"] == [{"file": "A.java", "method": "save", "start_line": 82, "end_line": 92,
                                  "vulnerable_lines": [83]}]


def test_repopairbench(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text(json.dumps({"id": "00c7", "project_name": "gradio", "repo_url": "https://github.com/gradio-app/gradio",
                             "commit_hash": SHA1, "language": "python", "cve_ids": ["CVE-2021-43831"],
                             "cwe_ids": ["CWE-22"], "vuln_data": "{'file_path': 'gradio/networking.py', 'code_before': 'x'}"}) + "\n")
    [p] = sources.repopairbench(str(f))
    assert p["id"] == "CVE-2021-43831" and p["repo"] == "gradio-app/gradio" and p["language"] == "py"
    assert p["fix_file"] == "gradio/networking.py"


def test_pyvul_rows_are_tagged_llm_assisted(tmp_path):
    u1 = f"https://github.com/Plotly/Dash/commit/{SHA1}"
    u2 = f"https://github.com/o/r/commit/{SHA2}"
    (tmp_path / "commit_level_dataset.out").write_text(f"{u1}\n{u2}\n")
    (tmp_path / "commits_cwe_map.json").write_text(json.dumps({u1: "CWE-79", u2: "CWE-362"}))
    (tmp_path / "github_adv_src_links.json").write_text(json.dumps(
        {"CWE-79": [{"id": "GHSA-547x", "src_links": [u1], "repo_link": "https://github.com/plotly/dash"}]}))
    (tmp_path / "huntr_reports_with_src").write_text(json.dumps(
        {"https://huntr.com/b/1": {"cve": "CVE-2024-5", "cwe": "CWE-362: Race", "repo_link": "https://github.com/o/r",
                                   "fix_commit": f"https://www.github.com/o/r/commit/{SHA2}"}}))
    (tmp_path / "snyk_reports_with_src").write_text(json.dumps({}))
    rows = {r["repo"]: r for r in sources.pyvul(str(tmp_path))}
    assert rows["plotly/dash"]["id"] == "GHSA-547x" and rows["plotly/dash"]["cwe"] == ["CWE-79"]
    assert rows["o/r"]["id"] == "CVE-2024-5" and rows["o/r"]["cwe"] == ["CWE-362"]
    assert all(r["llm_assisted_labels"] is True and r["source"] == "pyvul" for r in rows.values())


SHA4 = "d" * 40


def _copy(table, cols, rows):
    """One pg_dump COPY block; ``rows`` hold already-escaped COPY text fields."""
    return "\n".join([f"COPY public.{table} ({', '.join(cols)}) FROM stdin;", *("\t".join(r) for r in rows), "\\.", ""])


_PG_DUMP = "\n".join([
    "-- PostgreSQL database dump",
    "SET statement_timeout = 0;",
    "CREATE TABLE public.fixes (\n    cve_id text,\n    hash text\n);",
    _copy("commits", ["hash", "repo_url", "msg", "author_date", "committer_date"], [
        [SHA1, "https://github.com/O/R", "second\\tfix\\nline", "2021-03-02 10:00:00+00", "2021-03-03 01:00:00+02"],
        [SHA2, "https://github.com/O/R", "first", "2021-01-01 10:00:00+00", "2021-01-01 10:00:00+00"],
        [SHA3, "https://github.com/o/p", "prospector find", "2021-05-01 00:00:00+00", "2021-05-01 00:00:00+00"],
        [SHA4, "https://github.com/O/R", "unrelated", "2021-02-01 00:00:00+00", "2021-02-01 00:00:00+00"]]),
    _copy("cve", ["cve_id", "published_date", "description"], [
        ["CVE-2021-1", "2021-04-05T17:29:00.000", "a\\\\b"], ["CVE-2021-2", "2021-06-01T00:00:00.000", "x"],
        ["GHSA-aaaa-bbbb-cccc", "2021-07-01T00:00:00.000", "x"]]),
    _copy("cwe_classification", ["cve_id", "cwe_id"], [["CVE-2021-1", "CWE-89"], ["CVE-2021-2", "NVD-CWE-Other"]]),
    _copy("file_change", ["file_change_id", "hash", "filename", "old_path", "new_path", "diff", "programming_language"], [
        ["1", SHA2, "a.py", "src/a.py", "src/a.py", "@@ -1 +1 @@\\n-x\\n+y", "Ruby"],   # a wrong guess is ignored
        ["2", SHA2, "test_a.py", "tests/test_a.py", "tests/test_a.py", "\\N", "Python"],
        ["3", SHA1, "b.py", "\\N", "src/b.py", "+z", "\\N"],
        ["4", SHA3, "c.js", "lib/c.js", "lib/c.js", "+w", "JavaScript"]]),
    _copy("fixes", ["cve_id", "hash", "repo_url", "rel_type", "score", "extraction_status"], [
        ["CVE-2021-1", SHA1, "https://github.com/O/R", "direct", "1337", "COMPLETED"],
        ["CVE-2021-1", SHA2, "https://github.com/O/R", "direct", "1337", "COMPLETED"],
        ["CVE-2021-1", SHA4, "https://github.com/O/R", "prospector", "200", "COMPLETED"],   # direct links win
        ["CVE-2021-2", SHA3, "https://github.com/o/p", "prospector", "120", "COMPLETED"],
        ["CVE-2021-3", SHA3, "https://github.com/o/q", "prospector", "40", "NOT_STARTED"],  # below 65: never a row
        ["GHSA-aaaa-bbbb-cccc", SHA4, "https://gitlab.com/x/y", "direct", "1337", "COMPLETED"]]),
    _copy("method_change", ["method_change_id", "file_change_id", "name"], [["9", "1", "f"]]),
    _copy("repository", ["repo_url", "repo_language"], [["https://github.com/O/R", "Python"]]),
])


def test_copy_field_unescapes_postgres_text_format():
    assert sources._copy_field("\\N") is None
    assert sources._copy_field("a\\tb\\nc\\\\d\\101\\x42") == "a\tb\nc\\dAB"
    assert sources._copy_field("plain") == "plain"


def test_morefixes_parses_postgres_copy_dump_without_loading_it(tmp_path):
    f = tmp_path / "dump.sql.gz"
    with gzip.open(f, "wt") as g:
        g.write(_PG_DUMP)
    st: dict = {}
    rows = {r["id"]: r for r in sources.morefixes(str(f), stats=st)}
    assert set(rows) == {"CVE-2021-1", "CVE-2021-2", "GHSA-aaaa-bbbb-cccc"}
    a = rows["CVE-2021-1"]
    assert a["source"] == "morefixes" and a["repo"] == "o/r"
    assert a["fix_shas"] == [SHA2, SHA1] and a["fix_sha"] == SHA2           # advisory links only, earliest first
    assert a["fix_link"] == "advisory" and not a.get("heuristic_fix_link")
    assert a["advisory_published"] == "2021-04-05" and a["cwe"] == ["CWE-89"] and a["cwe_class"] == "dataflow"
    assert a["language"] == "py" and a["enrich_status"] == "ok" and a["enrich_basis"] == "morefixes"
    assert a["language_basis"] == "fix_file_extensions"
    assert a["fix_commit_date"] == "2021-01-01" and a["n_files"] == 1 and a["n_files_total"] == 2
    assert a["n_files_lang"] == 1 and a["fix_files"] == ["src/a.py"]
    b = rows["CVE-2021-2"]
    assert b["heuristic_fix_link"] is True and b["fix_link"] == "prospector" and b["fix_score"] == 120
    assert b["fix_sha"] == SHA3 and b["language"] == "js" and b["cwe"] == [] and b["cwe_class"] == "unknown"
    g = rows["GHSA-aaaa-bbbb-cccc"]
    assert g["ghsa"] == "GHSA-aaaa-bbbb-cccc" and g["cve"] is None
    assert g["repo"] is None and g["repo_url"] == "https://gitlab.com/x/y"
    assert st["fix_links_below_min_score"] == 1 and st["groups_heuristic_only"] == 1


def test_iter_copy_dump_strips_crlf_line_ends():
    dump = _copy("cwe_classification", ["cve_id", "cwe_id"], [["CVE-1", "CWE-79"], ["CVE-2", "a\\rb"]])
    raw = dump.replace("\n", "\r\n").encode().splitlines(keepends=True)
    got = list(sources.iter_copy_dump(raw, {"cwe_classification": ("cve_id", "cwe_id")}))
    assert got == [("cwe_classification", {"cve_id": "CVE-1", "cwe_id": "CWE-79"}),
                   ("cwe_classification", {"cve_id": "CVE-2", "cwe_id": "a\rb"})]
