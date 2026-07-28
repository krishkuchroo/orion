"""Item 2: tunable Joern JVM heap.

Token-free tests for `joern_adapter._heap_gb` -- the `-Xmx` sizing behind `_jvm_flags`. No
subprocess, no Joern: it is pure arithmetic over config + os.sysconf, so we drive both directly.
Guards that the DEFAULT (fraction 0.75, no GB override) is behavior-preserving and that the new
knobs (exact GB override, tunable fraction) do what they say."""
from __future__ import annotations

from orion import config
from orion.graph import joern_adapter as J


def test_explicit_gb_override_wins_and_skips_ram(monkeypatch):
    """A positive JOERN_HEAP_GB is used verbatim -- even os.sysconf raising must not matter."""
    monkeypatch.setattr(config, "JOERN_HEAP_GB", "24")

    def _boom(_name):
        raise OSError("sysconf unavailable")

    monkeypatch.setattr(J.os, "sysconf", _boom)   # proves the override short-circuits RAM detection
    assert J._heap_gb() == 24
    assert J._jvm_flags() == ["-J-XX:+UseG1GC", "-J-Xmx24g"]


def test_fraction_of_ram_is_the_default_sizing(monkeypatch):
    """No GB override -> fraction * physical RAM. Fake an 8 GB box (2M pages * 4096 B)."""
    monkeypatch.setattr(config, "JOERN_HEAP_GB", "")
    monkeypatch.setattr(config, "JOERN_HEAP_FRACTION", 0.75)

    def _sysconf(name):
        return {"SC_PHYS_PAGES": 2 * 1024 * 1024, "SC_PAGE_SIZE": 4096}[name]

    monkeypatch.setattr(J.os, "sysconf", _sysconf)
    assert J._heap_gb() == 6        # 8 GB * 0.75, floored
    monkeypatch.setattr(config, "JOERN_HEAP_FRACTION", 0.5)
    assert J._heap_gb() == 4        # fraction is tunable


def test_malformed_or_nonpositive_override_falls_through(monkeypatch):
    """A non-numeric or <=0 override must not crash -- it falls back to RAM-derived sizing."""
    monkeypatch.setattr(config, "JOERN_HEAP_FRACTION", 0.75)

    def _sysconf(name):
        return {"SC_PHYS_PAGES": 2 * 1024 * 1024, "SC_PAGE_SIZE": 4096}[name]

    monkeypatch.setattr(J.os, "sysconf", _sysconf)
    for bad in ("abc", "0", "-4"):
        monkeypatch.setattr(config, "JOERN_HEAP_GB", bad)
        assert J._heap_gb() == 6    # RAM-derived, not the bad value


def test_no_ram_no_override_is_g1gc_only(monkeypatch):
    """RAM unreadable AND no override -> only G1GC, let the JVM default the heap (never a crash)."""
    monkeypatch.setattr(config, "JOERN_HEAP_GB", "")

    def _boom(_name):
        raise ValueError("no sysconf")

    monkeypatch.setattr(J.os, "sysconf", _boom)
    assert J._heap_gb() is None
    assert J._jvm_flags() == ["-J-XX:+UseG1GC"]
