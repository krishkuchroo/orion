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
    """
    status: str
    findings_path: "str | None"
    usage: "list[dict]" = field(default_factory=list)
    steps: "list[dict] | None" = None
