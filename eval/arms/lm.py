"""The in-process Orion-LM arms (`orion-lm`, `orion-lm-base`): Orion's own local model, run inside the
eval process. No `orion scan` subprocess, no Claude, no network.

One run = build (or reuse) the scan's graph -> load the model -> `orion.lm.engine.discover_lm` ->
write the leads as `findings.json`. The two arms differ only in the model path (`model_tag`).

Rules this module is built around:
  * Joern and the model are never resident together (16 GB machine): the graph build runs and
    finishes first, the model is loaded after it, and released (references dropped, MLX cache
    cleared) once discovery returns.
  * The arm writes nothing to `eval/runs.db`: it hands its steps and token blocks back in the
    ArmResult and `run.run_one` logs them (the one launcher contract).
  * Never fabricated: no leads -> `[]` in findings.json (a valid file, scored as a miss); a crash
    -> no findings file at all; a step without token counts -> None usage fields.

Resources: the arm is in-process, so `on_start` gets THIS process (pid = os.getpid()). PhaseSampler
sums the process and its children, so Joern (joern-parse, a child process) is counted, but the peak RSS
also includes the runner's own baseline (Python, imported modules, anything a previous run left
allocated), and Neo4j (Docker) is not in it. Measured 2026-10-22 on M4 / mlx 0.32.4 / psutil 7.2.2:
psutil RSS does NOT include MLX's Metal allocations (a 1 GiB mx array left RSS flat while
mx.get_active_memory() read 1024 MB). The model's memory is therefore reported separately, as an
event line with MLX's own peak (`mx.get_peak_memory`), when MLX is the backend.

Seams (tests replace them; nothing in the tests touches Neo4j, Joern, MLX or a model):
`_build_graph`, `_scan_problem`, `_load_model`, `_discover`, `_free_model_memory`.
"""
import gc
import os
import sys
import threading
import time
import traceback
import types

from orion.cli import lm_verdicts, write_verdicts_json   # stdlib-only module; heavy deps are lazy
from orion.monitor import _format_event as _event_line   # the line `orion scan` prints per event

from . import ArmResult

DEFAULT_HUNG_SECONDS = 3600   # 60 min with no step or event (protocol: a run is `hung`, not killed)


# ---- seams --------------------------------------------------------------------------------------

def _build_graph(repo_dir: str, on_event) -> str:
    """Build `repo_dir` with the lm sink profile through Orion's own build path, exactly as
    `orion scan --engine lm` does (streaming build, the OrionScan record written by graph_build), and
    return its scan_id (`scan_id_for(..., profile=...)`). No semantic index: the lm engine's tools
    are run_cypher / read_code only, and the embedding model would only add memory."""
    from orion import graph_build
    from orion.graph import profiles
    profile = profiles.with_lm_sinks(profiles.select_profile(repo_dir))
    scan_id = graph_build.scan_id_for(repo_dir, profile=profile)
    graph_build.build(repo_dir, None, on_event, stream=True, queue_size=64, scan_id=scan_id,
                      profile=profile)
    return scan_id


def _scan_problem(scan_id: str, repo_dir: str):
    """Why a cached scan must not be reused (its OrionScan record is missing, incomplete or has
    another profile), or None. Same gate as `orion scan --scan-id ... --engine lm`."""
    from orion.graph import scans
    return scans.check_usable(scan_id, engine="lm", repo=repo_dir)


def _load_model(path: str, **sampling):
    from orion.lm import model
    return model.load(path, **sampling)


def _discover(scan_id, repo_dir, on_event, **kw):
    from orion.lm import engine
    return engine.discover_lm(scan_id, repo_dir, on_event, **kw)


def _free_model_memory() -> None:
    """Collect the dropped model and return MLX's buffer cache to the OS. MLX is only touched when
    it is already imported (i.e. the model was an MLX one); nothing is imported here."""
    gc.collect()
    mx = sys.modules.get("mlx.core")
    if mx is not None and hasattr(mx, "clear_cache"):
        mx.clear_cache()


def _flows_for(case_id):
    """Task F2 hook: the OWASP case mode turns `case_id` into slice-shaped flows. Until then every
    run reads the scan's own CandidateFlows (None)."""
    return None


# ---- helpers ------------------------------------------------------------------------------------

def _usage_block(step: dict) -> dict:
    """One normalized usage block (usage._FIELDS) for one prompter step. The local model reports
    prompt_tokens = cached + prefilled, so uncached_in = prompt - cached and cache_read = cached;
    it writes no billed cache (cache_write = 0). usage.total() then gives prompt + completion, the
    frontier arms' T. A count the step lacks stays None -- never guessed."""
    prompt, cached, out = step.get("prompt_tokens"), step.get("cached_tokens"), step.get("completion_tokens")
    return {
        "uncached_in": prompt - cached if prompt is not None and cached is not None else None,
        "cache_read": cached,
        "cache_write": 0 if prompt is not None else None,
        "out": out,
        "reasoning": None,
    }


def _format_event(ev) -> str:
    return _event_line(ev) if isinstance(ev, dict) else str(ev)


def _mlx_peak_mb():
    mx = sys.modules.get("mlx.core")
    fn = getattr(mx, "get_peak_memory", None) if mx is not None else None
    return fn() / (1024 * 1024) if fn is not None else None


class _Watchdog:
    """Sets `stop` once `hung_seconds` pass with no `touch()`. The prompter then forces a final
    answer and the run is recorded `hung`. It only sets the event: it never calls on_line (the
    SQLite connection behind it belongs to the runner's thread)."""

    def __init__(self, hung_seconds: float, stop: threading.Event):
        self.hung_seconds = float(hung_seconds)
        self.stop = stop
        self.fired = False
        self._last = time.monotonic()
        self._done = threading.Event()
        self._poll = max(0.01, min(5.0, self.hung_seconds / 4))
        self._thread = threading.Thread(target=self._loop, name="orion-lm-watchdog", daemon=True)

    def touch(self) -> None:
        self._last = time.monotonic()

    def _loop(self) -> None:
        while not self._done.wait(self._poll):
            if time.monotonic() - self._last >= self.hung_seconds:
                self.fired = True
                self.stop.set()
                return

    def __enter__(self):
        self.touch()
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._done.set()
        self._thread.join(timeout=2.0)
        return False


def _write_findings(json_out: str, leads, on_line):
    """findings.json as `orion scan --engine lm --json` writes it; json_out, or None (a miss) if the
    write fails -- never raises, so the run's steps and tokens still reach run_one."""
    try:
        os.makedirs(os.path.dirname(json_out) or ".", exist_ok=True)
        n = write_verdicts_json(json_out, lm_verdicts(leads))
    except Exception as e:
        on_line(f"warning: could not write findings.json ({e!r}); scored as a miss")
        return None
    on_line(f"orion-lm: wrote {n} lead(s) to {json_out}")
    return json_out


# ---- the arm ------------------------------------------------------------------------------------

def orion_lm_arm(*, arm, repo_dir, model_tag, json_out, on_line, on_start, graph_cache, run_no,
                 repo_id, commit_sha, case_id=None, hung_seconds=DEFAULT_HUNG_SECONDS,
                 **_ignored) -> ArmResult:
    """Run one orion-lm / orion-lm-base attempt in-process and return its ArmResult.

    arm          "orion-lm" | "orion-lm-base" (they differ only in the model path)
    repo_dir     the exported tree (no .git); graph source and the engine's read_code sandbox
    model_tag    the local model path (run.main's --lm-model / --lm-base-model); must exist
    json_out     where findings.json goes (the run dir)
    on_line      progress sink (run_one turns each line into an event)
    on_start     called once with an object whose .pid is this process, before the build
    graph_cache  {(repo_id, commit_sha): scan_id}, shared across the runner's runs, so both arms and
                 all run numbers of one commit reuse one graph
    run_no       the run number; it is the model's sampling seed (spec §6)
    repo_id, commit_sha  the cache key
    case_id      accepted and passed to the F2 case hook (`_flows_for`); flows stay None for now
    hung_seconds watchdog limit: that long with no step or event sets `stop` -> status "hung"
    _ignored     effort / usage_log / base_env from the shared launcher kwargs (unused here)

    Status: "ok"; "hung" (watchdog fired; the forced final's leads are still written); "crashed"
    (discovery raised: traceback head to on_line, no findings file). A missing model path raises
    ValueError before anything runs; a build or model-load failure propagates to run_one.
    """
    if not model_tag or not os.path.exists(model_tag):
        raise ValueError(f"{arm}: model path {model_tag!r} does not exist "
                         "(pass --lm-model / --lm-base-model to eval.run)")
    if on_start is not None:
        on_start(types.SimpleNamespace(pid=os.getpid()))

    watchdog = None

    def on_event(ev) -> None:
        if watchdog is not None:
            watchdog.touch()
        on_line(_format_event(ev))

    # 1. graph: reuse this commit's scan when its record still says it is usable, else build it.
    key = (repo_id, commit_sha)
    scan_id = graph_cache.get(key)
    if scan_id is not None:
        problem = _scan_problem(scan_id, repo_dir)
        if problem:
            on_line(f"orion-lm: cached graph not reusable ({problem}); rebuilding")
            scan_id = None
        else:
            on_line(f"orion-lm: reusing graph scan_id {scan_id} for {repo_id}@{commit_sha}")
    if scan_id is None:
        on_line(f"orion-lm: building graph for {repo_id}@{commit_sha} (lm sink profile)")
        scan_id = _build_graph(repo_dir, on_event)
        graph_cache[key] = scan_id
        on_line(f"orion-lm: graph built, scan_id {scan_id}")

    # 2. model: loaded only now, after Joern is gone; seed = run number.
    on_line(f"orion-lm: loading model {model_tag} (seed {run_no})")
    mx = sys.modules.get("mlx.core")
    if mx is not None and hasattr(mx, "reset_peak_memory"):
        mx.reset_peak_memory()
    model = _load_model(model_tag, seed=run_no)
    backend = getattr(model, "backend", None)
    on_line(f"orion-lm: model loaded (backend {backend or 'unknown'})")

    # 3. discovery, in-process, under the watchdog.
    steps: list = []

    def on_step(step) -> None:
        if watchdog is not None:
            watchdog.touch()
        steps.append(dict(step))

    stop = threading.Event()
    status, leads = "ok", None
    try:
        with _Watchdog(hung_seconds, stop) as watchdog:
            try:
                leads = _discover(scan_id, repo_dir, on_event, model=model, on_step=on_step,
                                  stop=stop, flows=_flows_for(case_id))
            except Exception as exc:
                status = "crashed"
                on_line(f"orion-lm: discovery crashed ({exc.__class__.__name__}: {exc}); "
                        f"{traceback.format_exc()}"[:2000])
        if status == "ok" and watchdog.fired:
            status = "hung"
            on_line(f"orion-lm: hung: no step or event for {hung_seconds}s; stop was set and the "
                    "prompter forced a final answer")
    finally:
        model = None
        _free_model_memory()
    peak = _mlx_peak_mb() if backend == "mlx" else None
    if peak is not None:
        on_line(f"orion-lm: mlx peak memory {peak:.1f} MB (Metal buffers; not in resources.peak_rss_mb)")

    # 4. findings: none for a crash (leads unknown), else every lead -- possibly [] -- as --json.
    findings_path = None if status == "crashed" else _write_findings(json_out, list(leads or []), on_line)
    return ArmResult(status=status, findings_path=findings_path,
                     usage=[_usage_block(s) for s in steps], steps=steps)
