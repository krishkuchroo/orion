import json

import pytest

from train import splits


def test_split_is_by_repo_and_oldcve_from_readymade_only():
    pairs = [{"id": f"P{i}", "repo": f"o/r{i % 10}", "source": "openssf" if i % 2 else "osv"} for i in range(40)]
    a = splits.assign(pairs, seed=0)
    by_repo = {}
    for p in pairs:
        by_repo.setdefault(p["repo"], set()).add(a[p["id"]])
    assert all(len(s) == 1 for s in by_repo.values())      # a repo lives in exactly one split
    src = {p["id"]: p["source"] for p in pairs}
    assert all(src[i] == "openssf" for i, s in a.items() if s == "oldcve")
    assert set(a.values()) == {"train", "dev", "oldcve"}


def test_assign_is_deterministic():
    pairs = [{"id": f"P{i}", "repo": f"o/r{i}", "source": "osv"} for i in range(30)]
    assert splits.assign(pairs, seed=3) == splits.assign(pairs, seed=3)
    assert splits.assign(pairs, seed=3) != splits.assign(pairs, seed=4)


def test_oldcve_never_takes_a_repo_that_also_has_non_readymade_pairs():
    pairs = [{"id": "A", "repo": "o/mixed", "source": "cwe-bench-java"},
             {"id": "B", "repo": "o/mixed", "source": "osv-maven"}] + \
            [{"id": f"P{i}", "repo": f"o/r{i}", "source": "osv-npm"} for i in range(10)]
    a = splits.assign(pairs, seed=0)
    assert "oldcve" not in a.values()
    assert a["A"] == a["B"]


def test_write_then_load_roundtrip_and_refusals(tmp_path):
    pairs = [{"id": f"P{i}", "repo": f"o/r{i}", "source": "openssf" if i < 5 else "osv"} for i in range(20)]
    path = tmp_path / "splits.json"
    a = splits.assign(pairs, seed=0)
    splits.write(str(path), a, seed=0)
    assert json.loads(path.read_text())["seed"] == 0
    assert splits.load(str(path), pairs) == a
    with pytest.raises(FileExistsError):
        splits.write(str(path), a, seed=0)                  # a frozen split is never overwritten
    with pytest.raises(ValueError):
        splits.load(str(path), pairs + [{"id": "NEW", "repo": "o/new", "source": "osv"}])
