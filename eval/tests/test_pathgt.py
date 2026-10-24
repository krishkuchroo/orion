import json
import os

import pytest

from eval import pathgt
from train.fixmap import GraphReadError

V, P = "X:vulnerable", "X:patched"
HUNK = {"file": "a.js", "old_file": "a.js", "old_start": 10, "old_end": 10, "new_start": 10, "new_end": 11}

# vulnerable scan: handler (a.js:1) calls src at line 3, sink call u2 at line 10 inside sinkfn (a.js:8)
V_CALLS = [{"uid": "src", "f": "a.js", "l": 3, "name": "req.query"},
           {"uid": "u2", "f": "a.js", "l": 10, "name": "exec"}]
P_CALLS = [{"uid": "psrc", "f": "a.js", "l": 3, "name": "req.query"},
           {"uid": "pu2", "f": "a.js", "l": 11, "name": "exec"}]
METHODS = [{"fn": "handler", "f": "a.js", "l": 1}, {"fn": "sinkfn", "f": "a.js", "l": 8}]
FLOW = {"uid": "fl", "source_uid": "src", "sink_uid": "u2", "sink_category": "exec",
        "path_uids": json.dumps(["src", "u2"]), "rank": 0}
PFLOW = {"uid": "pfl", "source_uid": "psrc", "sink_uid": "pu2", "sink_category": "exec",
         "path_uids": json.dumps(["psrc", "pu2"]), "rank": 0}
ENTRY = {"uid": "ep", "kind": "handler", "method_full_name": "handler", "exposure": "reachable"}


class DB:
    def __init__(self, flows, calls, entries, methods=None, error=None):
        self.f, self.calls, self.e = flows, calls, entries
        self.m = METHODS if methods is None else methods
        self.error = error

    def run_cypher(self, scan_id, query, limit=50):
        assert "{scan_id:$scan_id}" in query
        if self.error:
            return {"error": self.error}
        if "CandidateFlow" in query:
            return {"rows": self.f.get(scan_id, [])}
        if "EntryPoint" in query:
            return {"rows": self.e}
        if "CpgMethod" in query:
            return {"rows": self.m}
        return {"rows": self.calls.get(scan_id, [])}


def _db(vflows=(FLOW,), pflows=(), entries=(ENTRY,), **kw):
    return DB({V: list(vflows), P: list(pflows)}, {V: V_CALLS, P: P_CALLS}, list(entries), **kw)


def test_flow_gone_on_patched_yields_entry_points():
    cp = pathgt.candidate_paths(_db(), V, P, [HUNK])
    assert cp["flows_gone_on_patched"] == ["fl"] and cp["flows_through_fix"] == ["fl"]
    assert cp["accepted_entry_points"][0]["uid"] == "ep"
    assert cp["accepted_entry_points"][0]["method_full_name"] == "handler"
    assert "fl" in cp["accepted_entry_points"][0]["evidence"]
    assert cp["graph_missed"] is False and cp["error"] is None
    assert cp["sink_uid"] == "u2"
    assert cp["fix_sites"][0]["file"] == "a.js" and cp["fix_sites"][0]["method_full_name"] == "sinkfn"


def test_flow_surviving_on_patched_is_not_gone():
    cp = pathgt.candidate_paths(_db(pflows=(PFLOW,)), V, P, [HUNK])
    assert cp["flows_through_fix"] == ["fl"] and cp["flows_gone_on_patched"] == []
    assert cp["accepted_entry_points"] == [] and cp["graph_missed"] is False


def test_unresolved_flow_is_separate_from_gone():
    bad = {**FLOW, "uid": "fl2", "source_uid": "nope"}
    cp = pathgt.candidate_paths(_db(vflows=(FLOW, bad)), V, P, [HUNK])
    assert cp["flows_gone_on_patched"] == ["fl"] and cp["flows_unresolved"] == ["fl2"]


def test_entry_in_other_method_not_accepted():
    other = {"uid": "ep2", "kind": "http", "method_full_name": "elsewhere"}
    cp = pathgt.candidate_paths(_db(entries=(ENTRY, other)), V, P, [HUNK])
    assert [e["uid"] for e in cp["accepted_entry_points"]] == ["ep"]


def test_fixsite_without_flow_is_graph_missed():
    cp = pathgt.candidate_paths(_db(vflows=()), V, P, [HUNK])
    assert cp["graph_missed"] is True and cp["reason"] == "no_flow_through_site"
    assert cp["accepted_entry_points"] == [] and cp["sink_uid"] is None


def test_no_site_nodes_is_graph_missed():
    far = {**HUNK, "old_start": 500, "old_end": 500}
    cp = pathgt.candidate_paths(_db(), V, P, [far])
    assert cp["graph_missed"] is True and cp["reason"] == "no_site_nodes"


def test_graph_error_returns_record_with_error():
    cp = pathgt.candidate_paths(_db(error="boom"), V, P, [HUNK])
    assert "boom" in cp["error"] and cp["graph_missed"] is True
    assert cp["accepted_entry_points"] == []
    json.dumps(cp)


def test_to_manifest_fields():
    mf = pathgt.to_manifest_fields(pathgt.candidate_paths(_db(), V, P, [HUNK]))
    assert set(mf) == {"fix_sites", "fix_sites_patched", "sink_or_protected_operation",
                       "accepted_entry_points", "entry_evidence", "labelers", "graph_missed"}
    assert mf["labelers"] == [] and mf["graph_missed"] is False
    assert mf["fix_sites"][0]["function"] == "sinkfn" and mf["fix_sites"][0]["line"] == 10
    assert mf["sink_or_protected_operation"]["sink_uid"] == "u2"
    assert mf["accepted_entry_points"][0] == {"uid": "ep", "kind": "handler",
                                              "method_full_name": "handler", "file": "a.js", "line": 1}
    assert isinstance(mf["entry_evidence"], str) and "ep" in mf["entry_evidence"]
    json.dumps(mf)


def test_to_manifest_fields_missed():
    mf = pathgt.to_manifest_fields(pathgt.candidate_paths(_db(vflows=()), V, P, [HUNK]))
    assert mf["graph_missed"] is True and mf["accepted_entry_points"] == []
    assert mf["sink_or_protected_operation"] is None and mf["labelers"] == []


# ---- real Joern full-name formats (eval.names; the names come from real CPGs, see test_names.py) ----

def test_to_manifest_fields_reduces_real_java_and_js_full_names():
    java = "org.sasanlabs.Application.main:void(java.lang.String[])"
    js = "app/data/user-dao.js::program:UserDAO:getUserById"
    mf = pathgt.to_manifest_fields({"fix_sites": [
        {"file": "A.java", "line": 3, "end": 4, "method_full_name": java},
        {"file": "u.js", "line": 9, "end": 9, "method_full_name": js},
        {"file": "u.js", "line": 1, "end": 1, "method_full_name": "app/data/benefits-dao.js::program"}],
        "graph_missed": False})
    assert [s["function"] for s in mf["fix_sites"]] == ["main", "getUserById", None]
    assert mf["fix_sites"][0]["method_full_name"] == java       # the full name is kept for labelers


def test_entry_points_carry_the_methods_declaration_line_from_a_real_js_scan_shape():
    handler = "a.js::program:handler"
    methods = [{"fn": handler, "f": "a.js", "l": 1}, {"fn": "a.js::program:sinkfn", "f": "a.js", "l": 8}]
    entry = dict(ENTRY, method_full_name=handler)
    cp = pathgt.candidate_paths(_db(entries=(entry,), methods=methods), V, P, [HUNK])
    (ep,) = cp["accepted_entry_points"]
    assert (ep["method_full_name"], ep["file"], ep["line"]) == (handler, "a.js", 1)
    mf = pathgt.to_manifest_fields(cp)
    assert mf["fix_sites"][0]["function"] == "sinkfn"


# ---- E5 minors (final review): a read error is never "no flow"; all-unresolved has its own reason ---

class FlakyFlowsDB(DB):
    """The vulnerable scan's CandidateFlow read answers once, then fails (a dropped connection)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.flow_reads = 0

    def run_cypher(self, scan_id, query, limit=50):
        if "CandidateFlow" in query and scan_id == V:
            self.flow_reads += 1
            if self.flow_reads > 1:
                return {"error": "SessionExpired: connection dropped"}
        return super().run_cypher(scan_id, query, limit)


def test_a_flow_read_error_after_the_first_read_is_query_error_not_no_flow():
    db = FlakyFlowsDB({V: [FLOW], P: []}, {V: V_CALLS, P: P_CALLS}, [ENTRY])
    cp = pathgt.candidate_paths(db, V, P, [HUNK])
    assert cp["reason"] == "query_error" and "connection dropped" in cp["error"]
    assert cp["reason"] != "no_flow_through_site"


def test_the_first_flow_read_failing_is_query_error():
    class FailFlows(DB):
        def run_cypher(self, scan_id, query, limit=50):
            if "CandidateFlow" in query:
                return {"error": "ServiceUnavailable: down"}
            return super().run_cypher(scan_id, query, limit)
    cp = pathgt.candidate_paths(FailFlows({V: [FLOW]}, {V: V_CALLS, P: P_CALLS}, [ENTRY]), V, P, [HUNK])
    assert cp["reason"] == "query_error" and cp["graph_missed"] is True


def test_every_through_flow_unresolved_has_its_own_reason():
    bad = {**FLOW, "uid": "fl2", "source_uid": "nope"}
    cp = pathgt.candidate_paths(_db(vflows=(bad,)), V, P, [HUNK])
    assert cp["flows_through_fix"] == ["fl2"] and cp["flows_unresolved"] == ["fl2"]
    assert cp["flows_gone_on_patched"] == [] and cp["reason"] == "all_flows_unresolved"
    assert cp["accepted_entry_points"] == []


def test_survived_plus_unresolved_is_still_no_flow_gone_on_patched():
    bad = {**FLOW, "uid": "fl2", "source_uid": "nope"}
    cp = pathgt.candidate_paths(_db(vflows=(FLOW, bad), pflows=(PFLOW,)), V, P, [HUNK])
    assert cp["flows_unresolved"] == ["fl2"] and cp["reason"] == "no_flow_gone_on_patched"



# ---- I3: the patched side's fix sites (fixmap.fix_sites(side="patched")) --------------------------

def test_patched_side_sites_use_the_patched_commits_lines():
    cp = pathgt.candidate_paths(_db(), V, P, [HUNK])
    (ps,) = cp["fix_sites_patched"]
    assert (ps["file"], ps["side"], ps["start"], ps["end"]) == ("a.js", "patched", 10, 11)
    assert ps["call_uids"] == ["pu2"]                          # the PATCHED scan's call
    mf = pathgt.to_manifest_fields(cp)
    assert mf["fix_sites_patched"] == [{"file": "a.js", "line": 10, "end_line": 11, "function": "sinkfn",
                                        "method_full_name": "sinkfn"}]
    assert mf["fix_sites"][0]["end_line"] == 10                 # the vulnerable side: old lines


def test_patched_sites_are_proposed_even_when_the_graph_missed_the_flow():
    cp = pathgt.candidate_paths(_db(vflows=()), V, P, [HUNK])
    assert cp["graph_missed"] is True and cp["fix_sites_patched"]


def test_a_patched_only_read_error_is_query_error():
    class PatchedDown(DB):
        def run_cypher(self, scan_id, query, limit=50):
            if scan_id == P:
                return {"error": "ServiceUnavailable: down"}
            return super().run_cypher(scan_id, query, limit)
    cp = pathgt.candidate_paths(PatchedDown({V: [FLOW]}, {V: V_CALLS, P: P_CALLS}, [ENTRY]), V, P, [HUNK])
    assert cp["reason"] == "query_error" and cp["fix_sites_patched"] == []


# ---- I10: the driver (python -m eval.pathgt); builders, graph, mirror and hunks injected -----------

ROW = {"id": "CVE-1", "repo_url": "https://github.com/acme/app", "tier": "headline", "kind": "dataflow",
       "vulnerable_commit": "v" * 40, "patched_commit": "p" * 40, "cwe": "CWE-78", "fix_sites": [],
       "sink_or_protected_operation": None, "accepted_entry_points": [], "entry_evidence": None,
       "labelers": [], "graph_missed": None}


def _injected(tmp_path, *, build=None, graph=None, hunks=None, mirror=None, export=None):
    seen = {"trees": [], "exports": [], "mirrors": []}

    def default_build(tree):
        seen["trees"].append(tree)
        assert os.path.isfile(os.path.join(tree, "a.js"))
        return V if len(seen["trees"]) == 1 else P

    def default_export(mdir, sha, dest, **kw):
        seen["exports"].append((mdir, sha))
        os.makedirs(dest)
        open(os.path.join(dest, "a.js"), "w").write("x")
    kw = dict(mirror_root=str(tmp_path / "mirrors"), tmp_root=str(tmp_path / "tmp"),
              builder=build or default_build, open_db=graph or (lambda: _db()),
              hunks=hunks or (lambda mdir, v, p: [HUNK]),
              _mirror=mirror or (lambda url, d: seen["mirrors"].append((url, d))),
              _export=export or default_export)
    (tmp_path / "tmp").mkdir(exist_ok=True)
    return kw, seen


def test_propose_row_builds_both_commits_keeps_the_scans_and_proposes_fields(tmp_path):
    kw, seen = _injected(tmp_path)
    rec = pathgt.propose_row(dict(ROW), **kw)
    assert rec["result"] == "proposed" and rec["error"] is None
    assert seen["mirrors"] == [("https://github.com/acme/app", str(tmp_path / "mirrors" / "acme__app"))]
    assert [sha for _, sha in seen["exports"]] == ["v" * 40, "p" * 40]
    assert (rec["vulnerable"]["scan_id"], rec["patched"]["scan_id"]) == (V, P)
    assert rec["n_hunks"] == 1 and rec["n_flows_gone_on_patched"] == 1
    assert rec["fields"]["fix_sites"][0]["function"] == "sinkfn" and rec["fields"]["fix_sites_patched"]
    assert rec["fields"]["labelers"] == []
    assert os.listdir(tmp_path / "tmp") == []                     # the trees are gone, the scans kept
    json.dumps(rec)


@pytest.mark.parametrize("where,expect", [("mirror", "not_checked"), ("hunks", "not_checked"),
                                          ("export", "not_checked"), ("neo4j", "not_checked"),
                                          ("joern", "not_checked"), ("build", "build_failed")])
def test_propose_row_classifies_failures_like_the_precheck(tmp_path, where, expect):
    from neo4j.exceptions import ServiceUnavailable
    from eval import infra

    def boom(*a, **k):
        raise {"neo4j": ServiceUnavailable("down"), "joern": infra.InfraError("Joern binaries not found"),
               "build": RuntimeError("joern-parse failed (rc=1)")}.get(where, OSError("git failed"))
    over = {"mirror": dict(mirror=boom), "hunks": dict(hunks=boom), "export": dict(export=boom),
            "neo4j": dict(build=boom), "joern": dict(build=boom), "build": dict(build=boom)}[where]
    kw, _ = _injected(tmp_path, **over)
    rec = pathgt.propose_row(dict(ROW), **kw)
    assert rec["result"] == expect and rec["fields"] is None and rec["error"]


@pytest.mark.parametrize("error,expect", [("ServiceUnavailable: down", "not_checked"),
                                          ("CypherSyntaxError: bad", "query_error")])
def test_propose_row_graph_read_errors(tmp_path, error, expect):
    kw, _ = _injected(tmp_path, graph=lambda: _db(error=error))
    rec = pathgt.propose_row(dict(ROW), **kw)
    assert rec["result"] == expect and rec["fields"] is None and error.split(":")[0] in rec["error"]


def _cli(tmp_path, monkeypatch, *args, rows=None, outcome=None, preflight=()):
    man = tmp_path / "manifest.json"
    man.write_text(json.dumps({"repos": rows if rows is not None else [dict(ROW)]}, indent=1) + "\n")
    calls = []
    real = pathgt.propose_row

    def fake(row, **kw):
        calls.append(row["id"])
        kw2, _ = _injected(tmp_path)
        return outcome(row) if outcome else real(row, **kw2)
    monkeypatch.setattr(pathgt, "propose_row", fake)
    monkeypatch.setattr(pathgt, "_preflight", lambda: list(preflight))
    monkeypatch.setattr(pathgt, "_orion_commit", lambda: "deadbeef")
    rc = pathgt.main(["--manifest", str(man), *args])
    report = tmp_path / "pathgt_report.json"
    return rc, man, calls, (json.loads(report.read_text()) if report.exists() else None)


def test_cli_dry_run_writes_only_the_report(tmp_path, monkeypatch):
    rc, man, calls, report = _cli(tmp_path, monkeypatch)
    before = json.dumps({"repos": [dict(ROW)]}, indent=1) + "\n"
    assert rc == 0 and calls == ["CVE-1"] and man.read_text() == before          # manifest byte-identical
    rec = report["rows"]["CVE-1"]
    assert rec["result"] == "proposed" and rec["orion_commit"] == "deadbeef" and rec["fields"]["fix_sites"]


def test_cli_write_merges_fields_and_never_touches_a_labeled_row(tmp_path, monkeypatch):
    signed = dict(ROW, id="CVE-2", labelers=["krish"], fix_sites=[{"file": "human.js", "line": 1}])
    rc, man, calls, report = _cli(tmp_path, monkeypatch, "--write", rows=[dict(ROW), signed])
    assert rc == 0 and calls == ["CVE-1"]                                       # CVE-2 never even built
    rows = {r["id"]: r for r in json.loads(man.read_text())["repos"]}
    assert rows["CVE-1"]["fix_sites"][0]["function"] == "sinkfn" and rows["CVE-1"]["fix_sites_patched"]
    assert rows["CVE-1"]["labelers"] == [] and rows["CVE-1"]["pathgt"]["vulnerable_scan_id"] == V
    assert rows["CVE-2"] == signed                                              # untouched
    assert report["rows"]["CVE-2"]["result"] == "skipped_labeled"


def test_cli_write_leaves_a_not_checked_row_alone(tmp_path, monkeypatch):
    down = {"result": "not_checked", "error": "mirror: OSError: git failed", "fields": None,
            "vulnerable": {"scan_id": None}, "patched": {"scan_id": None}}
    rc, man, _, report = _cli(tmp_path, monkeypatch, "--write", outcome=lambda row: dict(down))
    assert rc == 0 and json.loads(man.read_text())["repos"] == [ROW]
    assert report["rows"]["CVE-1"]["result"] == "not_checked"


def test_cli_preflight_failure_touches_nothing(tmp_path, monkeypatch, capsys):
    rc, man, calls, report = _cli(tmp_path, monkeypatch, "--write", preflight=["Neo4j at bolt://x is not usable"])
    assert rc == 1 and calls == [] and report is None
    assert json.loads(man.read_text())["repos"] == [ROW]
    assert "not ready" in capsys.readouterr().out


def test_cli_unknown_id_and_rerun_history(tmp_path, monkeypatch):
    rc, _, calls, _ = _cli(tmp_path, monkeypatch, "--id", "CVE-9")
    assert rc == 2 and calls == []
    _cli(tmp_path, monkeypatch)
    rc, _, _, report = _cli(tmp_path, monkeypatch)
    assert rc == 0 and len(report["rows"]["CVE-1"]["history"]) == 1           # the earlier record kept
