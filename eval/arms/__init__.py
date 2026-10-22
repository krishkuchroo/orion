from dataclasses import dataclass, field


@dataclass
class ArmResult:
    """What every arm hands back to the runner (the single launcher contract).

    status:        "ok" | "crashed" | "hung" (what the process did; a missing findings
                   file does NOT change it -- that is a miss, not an error)
    findings_path: the per-run copy of the arm's findings file, or None when the arm
                   wrote none / wrote an invalid one
    usage:         normalized token blocks (usage.normalize_usage), one per model call
                   summary the arm's own usage.jsonl carried; [] when nothing was logged
    steps:         optional per-step rows for in-process arms (Task F3); each dict holds
                   db.log_step's keyword fields
    phases:        resources rows the arm measured itself, before its `run` phase began (the
                   in-process arm's graph build: {"phase": "build", "wall_seconds", "peak_rss_mb"});
                   run_one logs each one. [] when there was none (a cached graph, a plain arm)
    mlx_peak_mb:   MLX's own peak memory for the run phase (mx.get_peak_memory; Metal buffers that
                   psutil's peak_rss_mb does not see), or None when the backend is not MLX / said
                   nothing; run_one stores it in the run row's resources.mlx_peak_mb

    An arm that RAISES may attach the phases it measured as `exc.arm_phases` (PHASES_ATTR): run_one
    logs them too.
    """
    status: str
    findings_path: "str | None"
    usage: "list[dict]" = field(default_factory=list)
    steps: "list[dict] | None" = None
    phases: "list[dict]" = field(default_factory=list)
    mlx_peak_mb: "float | None" = None


PHASES_ATTR = "arm_phases"
