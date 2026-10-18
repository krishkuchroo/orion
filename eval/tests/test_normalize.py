import json

from eval import normalize
from eval.arms import prompt


def test_plain_finding_maps_fields():
    f = normalize.finding({"file": "a.py", "function": "f", "line_start": 5, "line_end": 7,
                           "cwe": "CWE-89", "title": "t", "explanation": "e"}, arm="plain-opus5")
    assert f["file"] == "a.py" and f["line"] == 5 and f["cwe"] == "CWE-89"


def test_orion_lm_finding_reads_path():
    lead = {"file": "a.js", "function": "f", "line": 10, "cwe": "CWE-94",
            "path": [{"file": "a.js", "function": "src", "line": 2, "role": "source"}]}
    f = normalize.finding(lead, arm="orion-lm")
    assert f["path"][0]["role"] == "source"


def test_load_missing_file_is_empty(tmp_path):
    assert normalize.load_arm(str(tmp_path / "nope.json"), arm="orion-lm") == []


def test_plain_finding_shape_and_raw_text():
    f = normalize.finding({"file": "a.py", "function": "f", "line_start": 5, "line_end": 7,
                           "cwe": "CWE-89", "title": "SQLi", "explanation": "concat",
                           "path": [{"file": "a.py", "function": "g", "line": 1, "role": "source"}]},
                          arm="plain-gpt")
    assert set(f) == {"arm", "file", "function", "line", "cwe", "confidence", "path", "raw_text"}
    assert f["arm"] == "plain-gpt" and f["confidence"] is None
    assert "SQLi" in f["raw_text"] and "concat" in f["raw_text"]
    assert f["path"][0]["role"] == "source"


def test_plain_without_path_is_empty_list():
    f = normalize.finding({"file": "a.py", "function": "f", "line_start": 1, "line_end": 1,
                           "cwe": "CWE-1", "title": "t", "explanation": "e"}, arm="plain-sonnet5")
    assert f["path"] == []


def _verdict(text, evidence, **lead):
    base = {"index": 0, "shape": "A", "text": text, "evidence": evidence, "confidence": 0.8,
            "source_uid": None, "sink_uid": None, "file": None, "function": None,
            "line": None, "cwe": None, "path": None}
    base.update(lead)
    return {"lead": base, "decision": "CONFIRM", "reason": "r", "evidence": "", "sink_centrality": 0.1}


def test_claude_engine_extracts_file_line_cwe_from_text():
    v = _verdict("CWE-89 SQL injection in routes/user.js at line 42 via req.query", "")
    f = normalize.finding(v, arm="orion-lm-base")
    assert f["file"] == "routes/user.js" and f["line"] == 42 and f["cwe"] == "CWE-89"
    assert f["confidence"] == 0.8 and f["raw_text"].startswith("CWE-89 SQL")


def test_claude_engine_file_only_in_evidence():
    v = _verdict("Command injection through exec of user input", "app/core/run.py:17 exec(cmd)")
    f = normalize.finding(v, arm="orion-lm-base")
    assert f["file"] == "app/core/run.py" and f["line"] == 17 and f["cwe"] is None


def test_claude_engine_prefers_file_in_both():
    v = _verdict("Injection in lib/a.js, see also docs/x.md", "query lib/a.js:9 and other/b.js:3")
    f = normalize.finding(v, arm="orion-lm-base")
    assert f["file"] == "lib/a.js" and f["line"] == 9


def test_no_extractable_file_is_kept_with_none():
    f = normalize.finding(_verdict("Something is vaguely wrong", ""), arm="orion-lm-base")
    assert f is not None
    assert f["file"] is None and f["line"] is None and f["function"] is None and f["path"] == []


def test_lm_verdict_unwraps_lead_structured():
    v = _verdict("t", "", shape="LM", file="a.js", function="f", line=3, cwe="CWE-22",
                 path=[{"file": "a.js", "function": "s", "line": 1, "role": "source"}])
    f = normalize.finding(v, arm="orion-lm")
    assert (f["file"], f["function"], f["line"], f["cwe"]) == ("a.js", "f", 3, "CWE-22")
    assert f["path"][0]["role"] == "source" and f["raw_text"] == "t"


def test_load_arm_invalid_json_is_empty(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text("{not json")
    assert normalize.load_arm(str(p), arm="plain-opus5") == []
    assert normalize.load_arm(str(p), arm="orion-lm") == []


def test_load_arm_plain_and_orion(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"findings": [{"file": "a.py", "function": "f", "line_start": 2,
                                           "line_end": 3, "cwe": "CWE-78", "title": "t",
                                           "explanation": "e"}]}))
    out = normalize.load_arm(str(p), arm="plain-opus5")
    assert len(out) == 1 and out[0]["line"] == 2 and out[0]["arm"] == "plain-opus5"
    o = tmp_path / "o.json"
    o.write_text(json.dumps([_verdict("t", "", shape="LM", file="b.js", line=4)]))
    out = normalize.load_arm(str(o), arm="orion-lm")
    assert len(out) == 1 and out[0]["file"] == "b.js"


def test_load_arm_wrong_shape_is_empty(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"findings": "nope"}))
    assert normalize.load_arm(str(p), arm="plain-gpt") == []
    p.write_text(json.dumps({"unexpected": 1}))
    assert normalize.load_arm(str(p), arm="orion-lm") == []


def test_validate_path_optional_and_typed():
    base = {"file": "a.py", "function": "f", "line_start": 1, "line_end": 2,
            "cwe": "CWE-89", "title": "t", "explanation": "e"}
    assert prompt.validate_findings({"findings": [base]}) == []
    ok = dict(base, path=[{"file": "a.py", "function": "f", "line": 1, "role": "sink"}])
    assert prompt.validate_findings({"findings": [ok]}) == []
    assert prompt.validate_findings({"findings": [dict(base, path="x")]})
    assert prompt.validate_findings({"findings": [dict(base, path=["x"])]})
    assert "path" in prompt.FINDINGS_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert "path" not in prompt.FINDINGS_SCHEMA["properties"]["findings"]["items"]["required"]
    assert '"path"' in prompt.TASK_PROMPT


def test_library_names_do_not_beat_real_file():
    v = _verdict("The Express.js app in routes/contributions.js is injectable", "")
    assert normalize.finding(v, arm="orion-lm-base")["file"] == "routes/contributions.js"
    v = _verdict("Node.js eval of user input", "app.js:12 eval(x)")
    f = normalize.finding(v, arm="orion-lm-base")
    assert f["file"] == "app.js" and f["line"] == 12
    assert normalize.finding(_verdict("Node.js is vulnerable", ""), arm="orion-lm-base")["file"] is None


def test_line_forms():
    assert normalize.finding(_verdict("bug in a/b.py lines 42-50", ""), arm="orion-lm-base")["line"] == 42
    assert normalize.finding(_verdict("bug in a/b.py L42", ""), arm="orion-lm-base")["line"] == 42


def test_cwe_from_evidence_and_normalised():
    assert normalize.finding(_verdict("t", "CWE 89 here"), arm="orion-lm-base")["cwe"] == "CWE-89"
    assert normalize.finding(_verdict("CWE-089 x", ""), arm="orion-lm-base")["cwe"] == "CWE-89"


def test_path_null_invalid_and_cross_shape_load(tmp_path):
    base = {"file": "a.py", "function": "f", "line_start": 1, "line_end": 2,
            "cwe": "CWE-89", "title": "t", "explanation": "e"}
    assert prompt.validate_findings({"findings": [dict(base, path=None)]})
    p = tmp_path / "x.json"
    p.write_text(json.dumps([base]))
    assert normalize.load_arm(str(p), arm="plain-opus5") == []
    p.write_text(json.dumps({"findings": []}))
    assert normalize.load_arm(str(p), arm="orion-lm") == []
