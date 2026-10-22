import json

import pytest

from eval import manifest


def _row(**kw):
    base = {"id": "r1", "repo_url": "https://x/r", "tier": "headline", "vulnerable_commit": "v",
            "patched_commit": "p", "cwe": "CWE-89", "fix_sites": [], "accepted_entry_points": [],
            "labelers": ["krish"]}
    base.update(kw)
    return base


def _errs(*rows, **kw):
    return manifest.validate({"repos": list(rows)}, **kw)


def test_validate_flags_missing_commit_pair():
    errs = manifest.validate({"repos": [{"id": "r1", "vulnerable_commit": "v"}]})
    assert any("patched_commit" in e for e in errs)


def test_load_roundtrips(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"repos": [_row()]}))
    assert manifest.load(str(p))["repos"][0]["id"] == "r1"
    assert manifest.validate(manifest.load(str(p))) == []


def test_load_checks_top_level_only(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"repos": [{"bad": 1}]}))
    assert manifest.load(str(p))["repos"] == [{"bad": 1}]  # no validate here
    p.write_text(json.dumps([1]))
    with pytest.raises(ValueError):
        manifest.load(str(p))
    p.write_text(json.dumps({"repos": {}}))
    with pytest.raises(ValueError):
        manifest.load(str(p))


def test_validate_rejects_training_repo_and_unlabeled_when_required():
    row = _row(repo="o/trained", labelers=[])
    errs = manifest.validate({"repos": [row]}, split_repos={"o/trained"}, require_labels=True)
    assert any("training" in e for e in errs) and any("labelers" in e for e in errs)


def test_empty_labelers_ok_unless_required():
    assert _errs(_row(labelers=[])) == []
    assert any("labelers" in e for e in _errs(_row(labelers=[]), require_labels=True))


def test_training_check_is_case_insensitive_and_covers_canonical_and_url():
    assert any("training" in e for e in _errs(_row(repo="O/Trained"), split_repos={"o/trained"}))
    assert any("training" in e for e in _errs(_row(repo="o/new", repo_canonical="O/Trained"),
                                              split_repos={"o/trained"}))
    assert any("training" in e for e in _errs(_row(repo_url="https://github.com/O/Trained.git"),
                                              split_repos={"o/trained"}))
    assert _errs(_row(repo="o/other"), split_repos={"o/trained"}) == []


def test_missing_required_and_wrong_types():
    errs = _errs({})
    for k in ("id", "repo_url", "tier", "vulnerable_commit", "patched_commit", "cwe",
              "fix_sites", "accepted_entry_points", "labelers"):
        assert any(k in e for e in errs), k
    assert any("fix_sites" in e for e in _errs(_row(fix_sites="x")))
    assert any("tier" in e for e in _errs(_row(tier="bogus")))
    assert any("kind" in e for e in _errs(_row(kind="other")))
    assert any("graph_missed" in e for e in _errs(_row(graph_missed="yes")))
    assert any("entry_evidence" in e for e in _errs(_row(entry_evidence=3)))
    assert any("not an object" in e for e in manifest.validate({"repos": [1]}))
    assert manifest.validate([]) and manifest.validate({"repos": 3})


def test_duplicate_ids():
    assert any("duplicate" in e for e in _errs(_row(), _row()))


def test_accepts_pathgt_shapes():
    from eval.pathgt import to_manifest_fields
    mf = to_manifest_fields({
        "fix_sites": [{"file": "a.js", "line": 3, "end": 9, "method_full_name": "a.js::program:f"}],
        "sink": {"sink_uid": "u", "sink_category": "sqli", "file": "a.js", "line": 5, "name": "query"},
        "accepted_entry_points": [{"uid": "e1", "kind": "http", "method_full_name": "m", "file": "a.js",
                                   "evidence": "route"}],
        "graph_missed": False})
    assert _errs(_row(**mf, kind="dataflow", guard=None, agreement=None, ghsa="GHSA-x", cve="CVE-1",
                      language="js")) == []
    mf2 = to_manifest_fields({"graph_missed": True})
    assert _errs(_row(**mf2)) == []


def test_bad_fix_site_and_entry_point_shapes():
    assert any("fix_sites[0]" in e for e in _errs(_row(fix_sites=["x"])))
    assert any("fix_sites[0]" in e for e in _errs(_row(fix_sites=[{"file": 3}])))
    assert any("accepted_entry_points[0]" in e for e in _errs(_row(accepted_entry_points=[5])))


def _write_split_files(tmp_path, pairs, assignment):
    pp, sp = tmp_path / "pairs.json", tmp_path / "splits.json"
    pp.write_text(json.dumps(pairs))
    sp.write_text(json.dumps({"seed": 0, "assignment": assignment, "extensions": []}))
    return str(pp), str(sp)


def test_split_repos_collects_repo_and_canonical(tmp_path):
    pp, sp = _write_split_files(
        tmp_path,
        [{"id": "a", "repo": "O/Old", "repo_canonical": "O/New"}, {"id": "b", "repo": "x/y"},
         {"id": "c", "repo": "not/assigned"}],
        {"a": "train", "b": "dev"})
    assert manifest.split_repos(pp, sp) == {"o/old", "o/new", "x/y"}


def test_split_repos_missing_file_and_missing_pair_raise(tmp_path):
    pp, sp = _write_split_files(tmp_path, [{"id": "a", "repo": "o/r"}], {"a": "train", "zz": "dev"})
    with pytest.raises(ValueError, match="zz"):
        manifest.split_repos(pp, sp)
    with pytest.raises(FileNotFoundError, match="pairs"):
        manifest.split_repos(str(tmp_path / "nope.json"), sp)
    with pytest.raises(FileNotFoundError, match="splits"):
        manifest.split_repos(pp, str(tmp_path / "nope.json"))
