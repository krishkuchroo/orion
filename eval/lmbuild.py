"""The ONE graph build of a test commit, shared by the scale-tier pre-check (eval.precheck) and the
in-process orion-lm arm (eval/arms/lm.py), so a pre-check pass predicts the arm's build (spec 5.4:
Joern heap 8 GB, no model loaded).

  lm_build(tree, on_event, *, scratch_dir, heap_gb=JOERN_HEAP_GB) -> scan_id

builds `tree` exactly as `orion scan --engine lm` does (lm sink profile, streaming build, the OrionScan
record written by graph_build). Raises eval.infra.InfraError, before any work, when a Joern binary is
missing; anything else the build raises propagates.

What it pins, for the length of the build only (restored afterwards, also when the build fails):
  * Joern's heap: orion.config.JOERN_HEAP_GB = "8" (and ORION_JOERN_HEAP_GB=8 in os.environ, for any
    child that re-imports orion.config). Orion reads the config value at call time
    (joern_adapter._heap_gb -> -J-Xmx8g for joern-parse and the streaming joern script).
  * Joern's temp files. orion's joern_adapter.ensure_cpg (cpg.bin), graph_build's streaming work dir
    and joern_adapter's greadlink shim are made with tempfile.mkdtemp() / gettempdir() and take NO
    directory parameter, so tempfile.tempdir points at `scratch_dir` while the build runs (a context
    manager; orion/ is not changed). The CALLER chooses `scratch_dir` (lm_build creates it) and
    deletes it afterwards; it must not be inside the tree (Joern parses the tree). This is
    process-global for the build's duration: the runner is single-threaded then (the orion-lm
    watchdog starts after the build).
The heap actually passed to Joern (joern_adapter._heap_gb() under the pin) and the scratch dir are
reported as one text line through `on_event`, so they land in the run's events / the pre-check log.
"""
import contextlib
import os
import tempfile

from eval import infra

JOERN_HEAP_GB = 8   # spec 5.4: the pre-check's heap, and so the arm's
_HEAP_ENV = "ORION_JOERN_HEAP_GB"


@contextlib.contextmanager
def joern_settings(scratch_dir: str, heap_gb: int = JOERN_HEAP_GB):
    """Pin Joern's heap and point Python's temp dir at `scratch_dir`; restore both on exit."""
    from orion import config
    old_heap, old_tmp, old_env = config.JOERN_HEAP_GB, tempfile.tempdir, os.environ.get(_HEAP_ENV)
    config.JOERN_HEAP_GB, tempfile.tempdir = str(heap_gb), scratch_dir
    os.environ[_HEAP_ENV] = str(heap_gb)
    try:
        yield
    finally:
        config.JOERN_HEAP_GB, tempfile.tempdir = old_heap, old_tmp
        if old_env is None:
            os.environ.pop(_HEAP_ENV, None)
        else:
            os.environ[_HEAP_ENV] = old_env


def _orion_build(tree: str, on_event) -> str:
    """Orion's own lm-profile build of `tree` (no semantic index: the lm engine's tools are run_cypher /
    read_code only, and the embedding model would only add memory); returns its scan_id."""
    from orion import graph_build
    from orion.graph import profiles
    profile = profiles.with_lm_sinks(profiles.select_profile(tree))
    scan_id = graph_build.scan_id_for(tree, profile=profile)
    graph_build.build(tree, None, on_event, stream=True, queue_size=64, scan_id=scan_id, profile=profile)
    return scan_id


def lm_build(tree: str, on_event, *, scratch_dir: str, heap_gb: int = JOERN_HEAP_GB) -> str:
    """Build `tree` (see the module doc) and return its scan_id."""
    missing = infra.joern_missing()
    if missing:
        from orion import config
        raise infra.InfraError(f"Joern binaries not found: {', '.join(missing)} (JOERN_HOME={config.JOERN_HOME})")
    os.makedirs(scratch_dir, exist_ok=True)
    with joern_settings(scratch_dir, heap_gb):
        from orion.graph import joern_adapter
        gb = joern_adapter._heap_gb()
        on_event(f"graph build: Joern heap {'-Xmx%dg' % gb if gb else 'JVM default'} "
                 f"({_HEAP_ENV}={heap_gb}); Joern temp files in {scratch_dir} (deleted after the build)")
        return _orion_build(tree, on_event)
