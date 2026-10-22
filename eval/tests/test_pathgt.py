import json

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
    assert set(mf) == {"fix_sites", "sink_or_protected_operation", "accepted_entry_points",
                       "entry_evidence", "labelers", "graph_missed"}
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
