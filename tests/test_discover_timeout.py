"""Reality-based discovery timeout: token-free unit tests for the pure `config.discover_timeout`
scaling helper and for `discover.discover()` threading the chosen timeout down to every shape's
`claude -p` call. NO subprocess, NO real `claude -p` call, NO Claude tokens spent.

Background: a flat 180s timeout sat below the industry p90 (~384s) for agentic coding requests and
silently killed thorough sweeps mid-turn on large graphs (5 timeouts on the ~80k-node sharpemu
scan). The floor now clears p90 and a full MAX_TURNS budget, and grows with graph size.
"""
from __future__ import annotations

from orion import claude_cli, config, discover

# Empirical anchors observed this session: sharpemu's persisted graph was ~79,945 nodes; NodeGoat is
# ~3,500. The industry p90 for agentic coding requests is ~384s; the old flat timeout was 180s.
_SHARPEMU_NODES = 79945
_NODEGOAT_NODES = 3500
_INDUSTRY_P90 = 384
_OLD_FLAT_TIMEOUT = 180


def test_floor_clears_reality_anchors():
    """The base/floor must sit above BOTH the old flat 180s and the industry p90, so a normal sweep
    (which finishes under p90) is never killed for time."""
    assert config.DISCOVER_TIMEOUT > _OLD_FLAT_TIMEOUT
    assert config.DISCOVER_TIMEOUT >= _INDUSTRY_P90


def test_missing_or_nonpositive_count_falls_back_to_floor():
    for n in (None, 0, -1, -10_000):
        assert config.discover_timeout(n) == config.DISCOVER_TIMEOUT


def test_scales_up_with_graph_size():
    """A bigger graph gets a strictly larger budget (until the cap). NodeGoat sits just above the
    floor; sharpemu is materially larger and well above the old flat timeout."""
    nodegoat = config.discover_timeout(_NODEGOAT_NODES)
    sharpemu = config.discover_timeout(_SHARPEMU_NODES)

    assert nodegoat > config.DISCOVER_TIMEOUT          # small graph still scales a little
    assert sharpemu > nodegoat                          # bigger graph -> more time
    assert sharpemu > _OLD_FLAT_TIMEOUT * 3             # sharpemu gets multiples of the old budget
    # exact arithmetic of the documented formula (floor + int(per_node * nodes)):
    assert sharpemu == config.DISCOVER_TIMEOUT + int(config.DISCOVER_TIMEOUT_PER_NODE * _SHARPEMU_NODES)


def test_capped_for_huge_graphs():
    """A pathologically large graph is clamped to the ceiling, so a stuck agent still dies."""
    assert config.discover_timeout(10_000_000) == config.DISCOVER_TIMEOUT_CAP


def test_monotonic_non_decreasing():
    prev = 0
    for n in range(0, 400_000, 5_000):
        cur = config.discover_timeout(n)
        assert cur >= prev
        assert cur <= config.DISCOVER_TIMEOUT_CAP
        prev = cur


def test_discover_threads_timeout_to_every_shape(monkeypatch):
    """discover(..., timeout=T) must pass T as the per-shape `claude -p` timeout for ALL 4 shapes --
    the scaled value computed from the graph size is what actually bounds each subprocess."""
    seen: list[int | None] = []

    def fake_run_agent(session_id, system, message, *, json_schema=None, add_dir=None,
                       extra_allowed=(), on_event=None, max_turns=None, timeout=None,
                       retries=0, retry_backoff=None):
        seen.append(timeout)
        return {"leads": []}

    monkeypatch.setattr(claude_cli, "run_agent", fake_run_agent)
    discover.discover("fake-scan-id", lambda _ev: None, timeout=777)

    assert len(seen) == len(discover.SHAPES)
    assert all(t == 777 for t in seen)


def test_discover_default_timeout_is_the_reality_floor_not_the_old_flat(monkeypatch):
    """With no explicit timeout, a shape uses the reality-based floor (config.DISCOVER_TIMEOUT), NOT
    the old 180s CALL_TIMEOUT fallback -- so even a programmatic caller without a node count is safe."""
    seen: list[int | None] = []

    def fake_run_agent(session_id, system, message, *, json_schema=None, add_dir=None,
                       extra_allowed=(), on_event=None, max_turns=None, timeout=None,
                       retries=0, retry_backoff=None):
        seen.append(timeout)
        return {"leads": []}

    monkeypatch.setattr(claude_cli, "run_agent", fake_run_agent)
    discover.discover("fake-scan-id", lambda _ev: None)

    assert seen and all(t == config.DISCOVER_TIMEOUT for t in seen)
    assert config.DISCOVER_TIMEOUT != config.CALL_TIMEOUT
