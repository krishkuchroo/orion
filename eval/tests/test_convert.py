import json
from eval import convert

REAL = [  # shape of dataclasses.asdict(Verdict), as examples/apex/findings.json shows
    {"lead": {"index": 0, "shape": "A", "text": "cmd injection in run() at createFile.ts:116",
              "evidence": "MATCH ...", "confidence": "high", "source_uid": "s", "sink_uid": "k"},
     "decision": "CONFIRM", "reason": "tainted path reaches exec", "evidence": "read src",
     "sink_centrality": 0.4},
    {"lead": {"index": 1, "shape": "B", "text": "maybe", "evidence": "", "confidence": "low",
              "source_uid": None, "sink_uid": None},
     "decision": "REJECT", "reason": "no flow", "evidence": "", "sink_centrality": 0.0},
]


def test_keeps_only_confirms_with_real_fields():
    out = convert.confirmed_verdicts(REAL)
    assert len(out) == 1
    f = out[0]
    assert f["decision"] == "CONFIRM"
    assert f["reason"] == "tainted path reaches exec"
    assert "createFile.ts:116" in f["text"]
    assert f["sink_centrality"] == 0.4
    # no invented structured fields
    assert "file" not in f and "line_start" not in f


def test_load_missing_file_returns_empty(tmp_path):
    assert convert.load(str(tmp_path / "nope.json")) == []


def test_load_reads_real_json(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(REAL))
    assert len(convert.load(str(p))) == 2
