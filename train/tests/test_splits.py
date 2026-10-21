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


def test_raw_spellings_of_one_canonical_repo_land_in_one_split():
    """Final review I3: a renamed repo (several raw `repo` spellings, one `repo_canonical`) is one repo."""
    pairs = [{"id": f"P{i}", "repo": f"o/r{i}", "source": "osv"} for i in range(40)]
    spellings = ["httpie/cli", "httpie/httpie", "jakubroztocil/httpie", "HTTPie/CLI"]
    pairs += [{"id": f"H{i}", "repo": r, "repo_canonical": "httpie/cli" if i % 2 else "HTTPie/cli", "source": "osv"}
              for i, r in enumerate(spellings * 3)]
    for seed in range(20):              # whichever split the repo lands in, all of its pairs go there
        a = splits.assign(pairs, seed=seed)
        assert len({a[f"H{i}"] for i in range(12)}) == 1, seed


def test_extend_keeps_every_frozen_pair_and_follows_each_repos_split(tmp_path):
    old = [{"id": f"P{i}", "repo": f"o/r{i}", "source": "openssf" if i < 5 else "osv"} for i in range(40)]
    path = tmp_path / "splits.json"
    frozen = splits.assign(old, seed=0)
    splits.write(str(path), frozen, seed=0)
    dev_repo = next(p["repo"] for p in old if frozen[p["id"]] == "dev")
    gone = old[-1]["id"]
    new = [p for p in old if p["id"] != gone] + \
          [{"id": "N-same", "repo": dev_repo.upper(), "source": "morefixes"}] + \
          [{"id": f"N{i}", "repo": f"o/new{i}", "source": "morefixes"} for i in range(20)]
    a = splits.extend(str(path), old, new, note="test")
    assert all(a[p["id"]] == frozen[p["id"]] for p in old if p["id"] != gone)   # nothing frozen moves
    assert gone not in a and a["N-same"] == "dev"
    added = [a[f"N{i}"] for i in range(20)]
    assert added.count("dev") == 3 and "oldcve" not in added                       # 15% of the 20 new repos
    data = json.loads(path.read_text())
    assert data["extensions"][-1]["note"] == "test" and data["extensions"][-1]["removed"] == [gone]
    assert data["extensions"][-1]["added"] == 21
    assert splits.load(str(path), new) == a
    with pytest.raises(ValueError):
        splits.extend(str(path), old, new, note="again")      # old_pairs no longer match the frozen set


def test_extend_refuses_a_frozen_pair_whose_repo_now_maps_to_another_split(tmp_path):
    old = [{"id": f"P{i}", "repo": f"o/r{i}", "source": "osv"} for i in range(40)]
    path = tmp_path / "splits.json"
    frozen = splits.assign(old, seed=0)
    splits.write(str(path), frozen, seed=0)
    dev_id = next(i for i, s in frozen.items() if s == "dev")
    train_repo = next(p["repo"] for p in old if frozen[p["id"]] == "train")
    moved = [dict(p, repo=train_repo) if p["id"] == dev_id else p for p in old]
    with pytest.raises(ValueError):
        splits.extend(str(path), old, moved, note="x")
