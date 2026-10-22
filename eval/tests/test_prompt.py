from eval.arms import prompt


def test_prompt_mentions_output_file_and_is_frozen_nonempty():
    assert "findings.json" in prompt.TASK_PROMPT
    assert len(prompt.TASK_PROMPT) > 200  # a real instruction, not a stub


def test_schema_has_the_seven_fields_plus_optional_path():
    props = prompt.FINDINGS_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert set(props) == {"file", "function", "line_start", "line_end", "cwe", "title", "explanation", "path"}


def test_validate_accepts_good_and_rejects_bad():
    good = {"findings": [{"file": "a.py", "function": "f", "line_start": 1, "line_end": 2,
                          "cwe": "CWE-89", "title": "t", "explanation": "e"}]}
    assert prompt.validate_findings(good) == []
    bad = {"findings": [{"file": "a.py"}]}
    assert prompt.validate_findings(bad)  # non-empty problem list
    assert prompt.validate_findings({}) == ["missing 'findings' list"]


# ---- CASE_PROMPT (OWASP targeted judgement, Task F2) -------------------------------------------
import hashlib

import pytest

CASE = {"case_id": "BenchmarkTest00001", "category": "pathtraver", "real": True, "cwe": "CWE-22",
        "file": "testcode/BenchmarkTest00001.py",
        "entry": "POST /benchmark/pathtraver-00/BenchmarkTest00001 -> BenchmarkTest00001_post"}


def test_task_prompt_is_byte_identical_to_the_frozen_text():
    assert hashlib.sha256(prompt.TASK_PROMPT.encode()).hexdigest() == \
        "0a4596460310ffa2e10c99a5148b9e4bd59a7a89b465dd8560ec3ee6a15d23fd"


def test_case_prompt_fills_file_entry_and_plain_category():
    text = prompt.case_prompt(CASE)
    assert ("Judge whether testcode/BenchmarkTest00001.py (entry POST /benchmark/pathtraver-00/"
            "BenchmarkTest00001 -> BenchmarkTest00001_post) contains an exploitable path traversal "
            "vulnerability. Write findings.json with zero or one finding.") in text
    assert "$" not in text and "pathtraver vulnerability" not in text
    assert text == prompt.case_prompt(dict(CASE, real=False))     # the answer never reaches the agent


def test_case_prompt_uses_the_task_prompt_findings_schema_with_path():
    start = prompt.TASK_PROMPT.index('{"findings": [{"file"')
    end = prompt.TASK_PROMPT.index("\n\nReport only")
    shape = prompt.TASK_PROMPT[start:end]
    assert '"path": [{"file"' in shape and shape in prompt.CASE_PROMPT
    assert shape in prompt.case_prompt(CASE)


def test_every_owasp_category_has_a_plain_description():
    java = {"cmdi", "crypto", "hash", "ldapi", "pathtraver", "securecookie", "sqli", "trustbound",
            "weakrand", "xpathi", "xss"}
    python = {"cmdi", "codeinj", "deserialization", "hash", "ldapi", "pathtraver", "redirect",
              "securecookie", "sqli", "trustbound", "weakrand", "xpathi", "xss", "xxe"}
    assert set(prompt.OWASP_CATEGORIES) == java | python
    assert prompt.OWASP_CATEGORIES["pathtraver"] == "path traversal"


def test_case_prompt_refuses_an_unknown_category():
    with pytest.raises(ValueError, match="nosuch"):
        prompt.case_prompt(dict(CASE, category="nosuch"))
