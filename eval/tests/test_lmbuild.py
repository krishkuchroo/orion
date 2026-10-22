"""eval.lmbuild: the ONE build wrapper the pre-check and the orion-lm arm share (final review I9).
Orion's own build (lmbuild._orion_build) is stubbed: no Joern, no Neo4j."""
import os
import tempfile

import pytest

from eval import infra, lmbuild
from eval.arms import lm


@pytest.fixture
def stub(monkeypatch):
    seen = {"events": []}

    def build(tree, on_event):
        from orion import config
        from orion.graph import joern_adapter
        seen.update(heap=config.JOERN_HEAP_GB, env=os.environ.get("ORION_JOERN_HEAP_GB"),
                    xmx=joern_adapter._jvm_flags(), cpg=tempfile.mkdtemp(prefix="orion_cpg_"),
                    tree=tree)
        if seen.get("fail"):
            raise RuntimeError("joern-parse failed (rc=1)")
        return "sid1"
    monkeypatch.setattr(lmbuild, "_orion_build", build)
    monkeypatch.setattr(infra, "joern_missing", lambda: [])
    return seen


def test_lm_build_pins_heap_and_temp_dir_and_reports_the_heap(tmp_path, stub, monkeypatch):
    from orion import config
    monkeypatch.delenv("ORION_JOERN_HEAP_GB", raising=False)
    before = (config.JOERN_HEAP_GB, tempfile.tempdir)
    scratch = str(tmp_path / "scratch")
    assert lmbuild.lm_build(str(tmp_path / "tree"), stub["events"].append, scratch_dir=scratch) == "sid1"
    assert stub["heap"] == "8" and stub["env"] == "8" and "-J-Xmx8g" in stub["xmx"]
    assert stub["cpg"].startswith(scratch + os.sep)               # cpg.bin & stream dir never leak
    assert (config.JOERN_HEAP_GB, tempfile.tempdir) == before     # restored
    assert "ORION_JOERN_HEAP_GB" not in os.environ
    (line,) = stub["events"]
    assert "Joern heap -Xmx8g" in line and "ORION_JOERN_HEAP_GB=8" in line and scratch in line


def test_lm_build_restores_everything_when_the_build_fails(tmp_path, stub, monkeypatch):
    from orion import config
    monkeypatch.setenv("ORION_JOERN_HEAP_GB", "3")
    before = (config.JOERN_HEAP_GB, tempfile.tempdir)
    stub["fail"] = True
    with pytest.raises(RuntimeError, match="joern-parse failed"):
        lmbuild.lm_build(str(tmp_path / "tree"), lambda e: None, scratch_dir=str(tmp_path / "s"))
    assert (config.JOERN_HEAP_GB, tempfile.tempdir) == before and os.environ["ORION_JOERN_HEAP_GB"] == "3"


def test_lm_build_refuses_without_joern_before_any_work(tmp_path, stub, monkeypatch):
    monkeypatch.setattr(infra, "joern_missing", lambda: ["/j/joern-parse"])
    with pytest.raises(infra.InfraError, match="joern-parse"):
        lmbuild.lm_build(str(tmp_path / "tree"), lambda e: None, scratch_dir=str(tmp_path / "s"))
    assert "tree" not in stub and not (tmp_path / "s").exists()


@pytest.mark.parametrize("fail", [False, True])
def test_the_arms_build_uses_lm_build_with_a_scratch_dir_next_to_the_tree(tmp_path, stub, fail):
    work = tmp_path / "token"
    tree = work / "tree"
    tree.mkdir(parents=True)
    stub["fail"] = fail
    events = []
    if fail:
        with pytest.raises(RuntimeError):
            lm._build_graph(str(tree), events.append)
    else:
        assert lm._build_graph(str(tree), events.append) == "sid1"
    scratch = os.path.dirname(stub["cpg"])
    assert os.path.dirname(scratch) == str(work)                  # next to the tree, not inside it
    assert not os.path.exists(scratch)                            # and deleted, pass or fail
    assert sorted(os.listdir(work)) == ["tree"]
    assert any("Joern heap -Xmx8g" in e for e in events)          # the heap reaches the run's events


def test_precheck_and_arm_share_one_heap_constant():
    from eval import precheck
    assert precheck.JOERN_HEAP_GB == lmbuild.JOERN_HEAP_GB == 8
