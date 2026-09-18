from eval.arms import prompt


def test_prompt_mentions_output_file_and_is_frozen_nonempty():
    assert "findings.json" in prompt.TASK_PROMPT
    assert len(prompt.TASK_PROMPT) > 200  # a real instruction, not a stub


def test_schema_has_the_seven_fields():
    props = prompt.FINDINGS_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert set(props) == {"file", "function", "line_start", "line_end", "cwe", "title", "explanation"}


def test_validate_accepts_good_and_rejects_bad():
    good = {"findings": [{"file": "a.py", "function": "f", "line_start": 1, "line_end": 2,
                          "cwe": "CWE-89", "title": "t", "explanation": "e"}]}
    assert prompt.validate_findings(good) == []
    bad = {"findings": [{"file": "a.py"}]}
    assert prompt.validate_findings(bad)  # non-empty problem list
    assert prompt.validate_findings({}) == ["missing 'findings' list"]
