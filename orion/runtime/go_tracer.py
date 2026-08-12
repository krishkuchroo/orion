"""Go tracer: `go build -cover` + `go tool covdata textfmt`.

Go's coverage is line-based already (no byte offsets), so there is no call tree here in v1 -- Go
enrichment is props-only (`executed`/`hit_count`), no OBSERVED_CALL edges, exactly as §3 of the spec
says a language with no call-tree source behaves. (`go tool pprof` on an execution trace is the
stage-2 source for Go edges.)

`parse_covdata_textfmt` is PURE over the tool's text output; only `collect` runs the tool.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from .base import Hit, RuntimeTrace

COVERDATA_SUBDIR = "covdata"


def parse_covdata_textfmt(text: str, module_prefix: str = "") -> RuntimeTrace:
    """Parse `go tool covdata textfmt` output into a RuntimeTrace (coverage only).

    Textfmt lines look like:
        github.com/acme/app/handler.go:12.34,15.2 3 1
    i.e. `file:startLine.startCol,endLine.endCol numStmts count`. A count > 0 marks every line in
    [startLine, endLine] executed. `module_prefix` (the go module path) is stripped so `file_path`
    is repo-relative to match graph nodes. Malformed lines are skipped."""
    per_line: dict[tuple[str, int], int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("mode:"):
            continue
        try:
            location, _numstmts, count_s = line.rsplit(" ", 2)
            count = int(count_s)
            file_part, span = location.split(":", 1)
            start_span, end_span = span.split(",", 1)
            start_line = int(start_span.split(".", 1)[0])
            end_line = int(end_span.split(".", 1)[0])
        except (ValueError, IndexError):
            continue
        if count <= 0:
            continue
        rel = file_part
        if module_prefix and rel.startswith(module_prefix):
            rel = rel[len(module_prefix):].lstrip("/")
        for ln in range(start_line, end_line + 1):
            key = (rel, ln)
            per_line[key] = per_line.get(key, 0) + count
    return RuntimeTrace(coverage=tuple(Hit(f, l, c) for (f, l), c in per_line.items()))


class GoCoverTracer:
    """Tracer instance for Go exe targets."""

    def __init__(self, module_prefix: str = "") -> None:
        self._module_prefix = module_prefix

    def build_flags(self) -> list[str]:
        return ["-cover"]

    def launch_env(self, work: Path) -> dict[str, str]:
        d = work / COVERDATA_SUBDIR
        d.mkdir(parents=True, exist_ok=True)
        return {"GOCOVERDIR": str(d)}

    def reset(self, work: Path) -> None:
        pass

    def collect(self, work: Path, repo: str) -> RuntimeTrace:
        d = work / COVERDATA_SUBDIR
        if not d.is_dir() or not any(d.iterdir()):
            return RuntimeTrace()
        try:
            out = subprocess.run(
                ["go", "tool", "covdata", "textfmt", "-i", str(d), "-o", "/dev/stdout"],
                capture_output=True, text=True, timeout=120, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return RuntimeTrace()
        if out.returncode != 0:
            return RuntimeTrace()
        return parse_covdata_textfmt(out.stdout, self._module_prefix)
