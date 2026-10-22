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
  * `discover_lm` never raises for a graph or model failure (it emits an `error` event and returns),
    so the arm reads those failures from its events (`_DiscoveryHealth`): a failed flow read, or every
    batch failing, is "crashed" -- never an "ok" run that merely found nothing.
  * The same holds one step earlier: a pathfind failure at build time is kept in the scan's OrionScan
    record and leaves the graph with no CandidateFlows. The arm reads the record for a fresh build
    and for a cached reuse alike (`_pathfind_error`); such a run is "crashed" before the model loads.

Resources: the arm is in-process, so `on_start` gets THIS process (pid = os.getpid()). PhaseSampler
sums the process and its children, so Joern (joern-parse, a child process) is counted, but the peak RSS
also includes the runner's own baseline (Python, imported modules, anything a previous run left
allocated), and Neo4j (Docker) is not in it. Measured 2026-10-22 on M4 / mlx 0.32.4 / psutil 7.2.2:
psutil RSS does NOT include MLX's Metal allocations (a 1 GiB mx array left RSS flat while
mx.get_active_memory() read 1024 MB). The model's memory is therefore reported separately, as an
event line with MLX's own peak (`mx.get_peak_memory`), when MLX is the backend.

OWASP case mode (Task F2): given an OWASP `case`, discovery judges only that case. The arm reads the
scan's CandidateFlows whose path touches the case's file (`eval.owasp.case_flows`) after the build and
before the model loads, and passes them as `discover_lm(..., flows=...)`. No flow touches the file ->
flows [] -> a genuine "nothing flagged" (ok, `[]`); a failed read of those flows is "crashed", like a
failed flow read inside discover_lm.

Seams (tests replace them; nothing in the tests touches Neo4j, Joern, MLX or a model):
`_build_graph`, `_scan_problem`, `_pathfind_error`, `_case_flows`, `_load_model`, `_discover`,
`_free_model_memory`.
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


def _pathfind_error(scan_id: str):
    """The error the build's pathfind step left in the scan's OrionScan record, or None when the
    CandidateFlows were computed. graph_build._precompute turns a pathfind exception into
    {"error": ...}, mark_complete stores it under counts.precompute.pathfind and no CandidateFlow is
    persisted (`orion reanalyze` replaces the entry with a fresh summary). A scan with no record at all
    cannot be confirmed, so that is reported as a problem too (fails closed)."""
    from orion.graph import scans
    rec = scans.get_record(scan_id)
    if rec is None:
        return f"scan {scan_id} has no {scans.RECORD} record; its CandidateFlows cannot be confirmed"
    counts = rec.get("counts")
    precompute = counts.get("precompute") if isinstance(counts, dict) else None
    pathfind = precompute.get("pathfind") if isinstance(precompute, dict) else None
    if isinstance(pathfind, dict) and pathfind.get("error"):
        return str(pathfind["error"])
    return None


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


def _case_flows(scan_id: str, case: dict) -> list:
    """OWASP case mode: the scan's CandidateFlows whose path touches `case['file']`, slice-shaped
    (eval.owasp.case_flows over a GraphDB opened and closed here). Raises on a graph error."""
    from orion.graphdb import GraphDB
    from eval import owasp
    db = GraphDB()
    try:
        return owasp.case_flows(db, scan_id, case)
    finally:
        db.close()


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


# The step kinds that end a prompter session normally: `run_session` records exactly one of them right
# before it returns (orion/lm/prompter.py). A batch whose session raised records none.
_SESSION_END_KINDS = frozenset({"final", "forced_final", "context_overflow"})


class _DiscoveryHealth:
    """What failed inside `discover_lm`, read from its events and steps. The engine turns a failed flow
    read and every per-batch session exception into an `error` event and still returns (possibly no)
    leads, so without this a run whose every batch failed would look like a clean "found nothing".

    Relies on exactly these conventions (pinned by the real-engine tests in eval/tests/test_arms_lm.py):
      * orion/lm/engine.py `error` event with turn=None -- "loading CandidateFlows failed: ..." (the
        flow read failed; no batch ran). Any turn-less discover error is treated the same way.
      * orion/lm/engine.py `error` event with turn=N -- "batch N (...) failed: ..." (that batch's
        session raised, e.g. model.generate failed; it produced no leads).
      * orion/lm/prompter.py: a session that returns normally records one `_SESSION_END_KINDS` step.
    """

    def __init__(self):
        self.run_errors: list = []        # details of turn-less discover errors
        self.failed_batches: set = set()  # turns of failed batches
        self.finished_batches = 0         # sessions that returned normally

    def see_event(self, ev) -> None:
        if not isinstance(ev, dict) or ev.get("phase") != "discover" or ev.get("event") != "error":
            return
        if ev.get("turn") is None:
            self.run_errors.append(ev.get("detail") or "")
        else:
            self.failed_batches.add(ev["turn"])

    def see_step(self, step) -> None:
        if isinstance(step, dict) and step.get("kind") in _SESSION_END_KINDS:
            self.finished_batches += 1

    def crash_reason(self):
        """Why discovery must be recorded "crashed", or None."""
        if self.run_errors:
            return f"discovery failed before any batch ran: {self.run_errors[0]}"
        if self.failed_batches and not self.finished_batches:
            return f"all {len(self.failed_batches)} batch(es) failed; no session finished"
        return None

    def partial_summary(self):
        """A line for a run where only some batches failed (it stays ok/hung), or None."""
        if self.failed_batches and self.finished_batches:
            n = len(self.failed_batches)
            return (f"{n} of {n + self.finished_batches} batches failed "
                    "(their flows produced no leads)")
        return None


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
                 repo_id, commit_sha, case_id=None, case=None, hung_seconds=DEFAULT_HUNG_SECONDS,
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
    case_id      the run's OWASP case id ("" / None for a manifest row); recorded by run_one
    case         an OWASP case (eval/dataset/owasp_sample.json) or None: judge only its flows
                 (`_case_flows`); None works the scan's own top CandidateFlows
    hung_seconds watchdog limit: that long with no step or event sets `stop` -> status "hung"
    _ignored     effort / usage_log / base_env from the shared launcher kwargs (unused here)

    Status: "ok" (some batches may have failed: a summary line says how many); "hung" (watchdog
    fired; the forced final's leads are still written); "crashed" (discovery raised -- traceback head
    to on_line -- or, read from its events, the flow read failed or every batch failed -- or the scan
    record says pathfind failed at build -- or the case's flows could not be read; no findings file in
    any of these). A missing model path
    raises ValueError before anything runs; a build or model-load failure propagates to run_one.
    """
    if not model_tag or not os.path.exists(model_tag):
        raise ValueError(f"{arm}: model path {model_tag!r} does not exist "
                         "(pass --lm-model / --lm-base-model to eval.run)")
    if on_start is not None:
        on_start(types.SimpleNamespace(pid=os.getpid()))

    watchdog = None
    health = _DiscoveryHealth()

    def on_event(ev) -> None:
        if watchdog is not None:
            watchdog.touch()
        health.see_event(ev)
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
    # A graph whose pathfind failed holds no CandidateFlows: discovery would report a clean "found
    # nothing". Crashed instead, before the model is loaded (fresh build and cached reuse alike).
    flow_error = _pathfind_error(scan_id)
    if flow_error:
        on_line(f"orion-lm: discovery crashed: scan {scan_id} has no usable CandidateFlows "
                f"({flow_error}); rebuild it or run "
                f"`orion reanalyze --scan-id {scan_id} --engine lm`")
        return ArmResult(status="crashed", findings_path=None, usage=[], steps=[])
    flows = None   # None: discover_lm reads the scan's top CandidateFlows itself
    if case is not None:
        try:
            flows = _case_flows(scan_id, case)
        except Exception as exc:
            on_line(f"orion-lm: discovery crashed: loading the flows of case {case.get('case_id')} "
                    f"failed ({exc.__class__.__name__}: {exc})"[:2000])
            return ArmResult(status="crashed", findings_path=None, usage=[], steps=[])
        on_line(f"orion-lm: case {case.get('case_id')}: {len(flows)} CandidateFlow(s) touch {case['file']}")

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
        health.see_step(step)
        steps.append(dict(step))

    stop = threading.Event()
    status, leads = "ok", None
    try:
        with _Watchdog(hung_seconds, stop) as watchdog:
            try:
                leads = _discover(scan_id, repo_dir, on_event, model=model, on_step=on_step,
                                  stop=stop, flows=flows)
            except Exception as exc:
                status = "crashed"
                on_line(f"orion-lm: discovery crashed ({exc.__class__.__name__}: {exc}); "
                        f"{traceback.format_exc()}"[:2000])
        reason = health.crash_reason() if status == "ok" else None
        if reason:
            status = "crashed"
            on_line(f"orion-lm: discovery crashed: {reason}")
        if status == "ok" and watchdog.fired:
            status = "hung"
            on_line(f"orion-lm: hung: no step or event for {hung_seconds}s; stop was set and the "
                    "prompter forced a final answer")
    finally:
        model = None
        _free_model_memory()
    partial = health.partial_summary() if status != "crashed" else None
    if partial:
        on_line(f"orion-lm: {partial}")
    peak = _mlx_peak_mb() if backend == "mlx" else None
    if peak is not None:
        on_line(f"orion-lm: mlx peak memory {peak:.1f} MB (Metal buffers; not in resources.peak_rss_mb)")

    # 4. findings: none for a crash (no trustworthy result), else every lead -- possibly [] -- as --json.
    findings_path = None if status == "crashed" else _write_findings(json_out, list(leads or []), on_line)
    return ArmResult(status=status, findings_path=findings_path,
                     usage=[_usage_block(s) for s in steps], steps=steps)
