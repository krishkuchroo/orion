"""Cross-task contract (final review I3 / m10): an F0 manifest row + the E5 fields eval.pathgt
proposes from a scan with REAL Joern full-name shapes -> manifest.validate(require_labels=True) ->
manifest.answer_keys -> normalize -> match.match_run -> matches -> report.efficiency / far."""
import json

import pytest

from eval import db, manifest, match, normalize, pathgt, report

V, P = "scan:vulnerable", "scan:patched"
HANDLER = "routes/index.js::program:handler"     # jssrc shape (see eval/tests/test_names.py)
SINKFN = "routes/index.js::program:sinkfn"
HUNK = {"file": "routes/index.js", "old_file": "routes/index.js", "old_start": 10, "old_end": 10,
        "new_start": 10, "new_end": 11}


class Graph:
    """Both scans of one pair, at the level fixmap/pathgt read them (run_cypher rows)."""
    calls = {V: [{"uid": "src", "f": "routes/index.js", "l": 3, "name": "req.query"},
                 {"uid": "snk", "f": "routes/index.js", "l": 10, "name": "exec"}],
             P: [{"uid": "psrc", "f": "routes/index.js", "l": 3, "name": "req.query"},
                 {"uid": "psnk", "f": "routes/index.js", "l": 11, "name": "exec"}]}
    methods = [{"fn": HANDLER, "f": "routes/index.js", "l": 1}, {"fn": SINKFN, "f": "routes/index.js", "l": 8}]
    flows = {V: [{"uid": "fl", "source_uid": "src", "sink_uid": "snk", "sink_category": "exec",
                  "path_uids": json.dumps(["src", "snk"]), "rank": 0}], P: []}

    def run_cypher(self, scan_id, query, limit=50):
        assert "{scan_id:$scan_id}" in query
        if "CandidateFlow" in query:
            return {"rows": self.flows[scan_id]}
        if "EntryPoint" in query:
            return {"rows": [{"uid": "ep", "kind": "handler", "method_full_name": HANDLER}]}
        if "CpgMethod" in query:
            return {"rows": self.methods}
        return {"rows": self.calls[scan_id]}


def _row():
    """An F0 row (eval/dataset/mine.py shape) with E5's proposed fields merged in, then signed."""
    row = {"id": "CVE-2026-0001", "cve": "CVE-2026-0001", "repo": "acme/app",
           "repo_url": "https://github.com/acme/app", "language": "js", "cwe": "CWE-78",
           "cwes": ["CWE-78"], "kind": "dataflow", "tier": "headline",
           "vulnerable_commit": "v" * 40, "patched_commit": "p" * 40, "fix_sites": [],
           "sink_or_protected_operation": None, "accepted_entry_points": [], "entry_evidence": None,
           "guard": None, "labelers": [], "agreement": None, "graph_missed": None}
    row.update(pathgt.to_manifest_fields(pathgt.candidate_paths(Graph(), V, P, [HUNK])))
    return row


def _run(conn, kind, sha, findings, tokens):
    rid = db.start_run(conn, arm="plain-opus5", repo="CVE-2026-0001", tier="headline", run_no=1,
                       model_tag="m", cli_versions="", orion_commit="c", commit_kind=kind, commit_sha=sha)
    db.finish_run(conn, rid, "ok")
    db.log_agent_call(conn, rid, session_id="s", stage="run", input_tokens=tokens, output_tokens=0,
                      cache_read=0, cache_write=0, turns_used=1, turn_limit=None, peak_context=None,
                      exit_reason="ok", error_head=None)
    row = _row()
    row["labelers"] = ["krish"]
    match.write_matches(conn, rid, match.match_run(findings, manifest.answer_keys(row, kind)))
    return rid


def test_an_unlabeled_row_is_refused_until_its_sites_are_signed():
    row = _row()
    assert row["fix_sites"][0]["function"] == "sinkfn"          # the real full name reduced (I4)
    assert row["fix_sites_patched"][0]["line"] == 10 and row["fix_sites_patched"][0]["end_line"] == 11
    errs = manifest.validate({"repos": [row]}, require_labels=True)
    assert any("labelers" in e for e in errs)
    row["labelers"] = ["krish"]
    assert manifest.validate({"repos": [row]}, require_labels=True) == []
    with pytest.raises(ValueError, match="fix_sites_patched"):
        manifest.answer_keys(dict(row, fix_sites_patched=[]), "patched")


def test_row_to_report_efficiency_and_far(tmp_path):
    conn = db.connect(str(tmp_path / "t.db"))
    raw = {"file": "routes/index.js", "function": "sinkfn", "line_start": 10, "line_end": 10,
           "cwe": "CWE-78", "title": "command injection", "explanation": "req.query reaches exec",
           "path": [{"file": "routes/index.js", "function": "handler", "line": 3, "role": "source"},
                    {"file": "routes/index.js", "function": "sinkfn", "line": 10, "role": "sink"}]}
    vuln = [normalize.finding(raw, arm="plain-opus5")]
    rid = _run(conn, "vulnerable", "v" * 40, vuln, tokens=500_000)
    (m,) = match.read_matches(conn, rid)
    assert (m["vuln_id"], m["level"]) == ("CVE-2026-0001", "L2")
    pl = json.loads(m["path_level"])
    assert pl["fix_traversal"] is True and pl["entry_hit"] is True   # entry = the real JS full name
    # the patched commit: the same finding on the patched line still names the fixed code
    patched = [normalize.finding(dict(raw, line_start=11, function=None, path=[]), arm="plain-opus5")]
    _run(conn, "patched", "p" * 40, patched, tokens=1)
    assert report.efficiency(conn, "plain-opus5") == pytest.approx(1e6 * 1 / 500_000)
    assert report.far(conn, "plain-opus5") == 1.0
