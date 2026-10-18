import json

from orion.lm import slice as sl
from orion.lm import tools


class StubDB:
    def __init__(self, flows, calls):
        self.flows = flows
        self.calls = calls
        self.queries = []

    def run_cypher(self, scan_id, query, limit=50, **kw):
        # Same contract as GraphDB.run_cypher(..., bounded=True): every answer reports the query type.
        self.queries.append(query)
        if "CandidateFlow" in query:
            return {"row_count": len(self.flows), "rows": self.flows, "query_type": "r"}
        return {"row_count": len(self.calls), "rows": self.calls, "query_type": "r"}  # CpgCall lookup


def test_candidate_flows_parses_path_uids():
    flows = [{"rank": 0, "source_uid": "s", "sink_uid": "k", "sink_category": "code_exec",
              "path_uids": json.dumps(["u1", "u2"])}]
    out = sl.candidate_flows(StubDB(flows, []), "s")
    assert out[0]["path_uids"] == ["u1", "u2"]


def test_flow_slice_skips_missing_uid():
    calls = [{"uid": "u1", "name": "exec", "code": "exec(x)", "method_full_name": "m",
              "file_path": "a.js", "line": 10}]  # u2 is absent from the graph
    flow = {"rank": 0, "sink_category": "code_exec", "path_uids": ["u1", "u2"]}
    s = sl.flow_slice(StubDB([], calls), "s", flow)
    assert [n["file"] for n in s["nodes"]] == ["a.js"]
    assert s["flow_id"] == "F0"


def test_flow_slice_keeps_path_order_and_scoped_escaped_query():
    calls = [{"uid": "b", "code": "B", "method_full_name": "m", "file_path": "b.js", "line": 2},
             {"uid": "a'x", "code": "A", "method_full_name": "m", "file_path": "a.js", "line": 1}]
    db = StubDB([], calls)
    s = sl.flow_slice(db, "s", {"rank": 3, "path_uids": ["a'x", "b"]})
    assert [n["code"] for n in s["nodes"]] == ["A", "B"]
    assert s["flow_id"] == "F3"
    assert set(s["nodes"][0]) == {"file", "function", "line", "code"}
    # db.queries also holds the tool's own "EXPLAIN " pre-flight of each query
    assert all(tools.is_scoped(q.removeprefix("EXPLAIN ")) for q in db.queries)


def test_flow_slice_empty_path_no_query():
    db = StubDB([], [])
    assert sl.flow_slice(db, "s", {"rank": 1, "path_uids": []})["nodes"] == []
    assert db.queries == []


def test_pruned_schema_is_nonempty_str():
    p = sl.pruned_schema()
    assert isinstance(p, str) and "CpgCall" in p
    for gone in ("Dependency", "CpgModule", "OBSERVED_CALL", "RUNTIME"):
        assert gone not in p
    for kept in ("CandidateFlow", "FLOWS_TO", "ENTERS_AT", "CONTAINS_CALL", "RESOLVES_TO", "CENTRALITY"):
        assert kept in p
    assert "Every node pattern must carry {scan_id:$scan_id}." in p
