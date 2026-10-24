"""Run a training command and kill it before the Mac runs out of memory.

Why: the 2026-10-23 Qwen3.5-4B smoke run froze a 16 GB M4 (forced reboot, no crash report). Unsloth's MLX trainer
wires up to ~85% of Metal's recommended working set (~9.7 GB here) and that memory cannot be paged out, while
~10 GB of apps plus the Stage 1 build were already resident, so macOS swapped until it stopped responding.

What it does: refuses to start next to another heavy job (Stage 1/2 builds, Joern, another training run); runs the
command in its own process group (Unsloth's MLX worker is a spawned child); samples free memory
(`kern.memorystatus_level`), swap (`vm.swapusage`) and the command's own memory (`top`'s MEM: its physical footprint,
which includes MLX's unified GPU memory, unlike RSS) every `--interval` seconds; kills the whole group when free
memory drops under `--min-free-pct`, swap grows more than `--max-swap-growth-mb` past its value at launch, or the
command itself goes over `--max-proc-mem-mb` (0 = no cap). Output is tee'd to `--log`, samples to `<log>.mem.csv`.
The thresholds are starting values, not measured ones.

    python -m train.guard --log train/runs/qwen35-c1/train.log --max-proc-mem-mb 7168 -- \
        ~/.unsloth/studio/unsloth_studio/bin/python -m train.mlx_train --data ... --out ...
"""
from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Callable

KILLED_EXIT = 137
HEAVY = re.compile(r"train\.stage[12]\b|joern|unsloth train|mlx_lm\.lora")


def parse_swap_used_mb(text: str) -> float:
    """`sysctl vm.swapusage` -> MB used ("used = 3235.62M" or "used = 1.50G")."""
    m = re.search(r"used = ([\d.]+)([MG])", text)
    if not m:
        raise ValueError(f"unrecognised vm.swapusage: {text!r}")
    return float(m.group(1)) * (1024 if m.group(2) == "G" else 1)


def parse_top_mem_mb(text: str) -> float | None:
    """`top -stats mem` value -> MB ("1248K", "19M", "2.3G", "512B"); None when unreadable."""
    m = re.fullmatch(r"([\d.]+)([BKMG])\+?-?", text.strip())
    if not m:
        return None
    return float(m.group(1)) * {"B": 1 / 1048576, "K": 1 / 1024, "M": 1, "G": 1024}[m.group(2)]


def proc_mem_mb(pid: int) -> float | None:
    out = subprocess.run(["top", "-l", "1", "-pid", str(pid), "-stats", "mem"], capture_output=True, text=True)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
    return parse_top_mem_mb(lines[-1]) if lines and out.returncode == 0 else None


def sample() -> dict:
    level = subprocess.run(["sysctl", "-n", "kern.memorystatus_level"], capture_output=True, text=True, check=True)
    swap = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True, check=True)
    return {"free_pct": int(level.stdout.strip()), "swap_used_mb": parse_swap_used_mb(swap.stdout)}


def kill_reason(s: dict, *, baseline_swap_mb: float, min_free_pct: int, max_swap_growth_mb: float,
                max_proc_mem_mb: float = 0) -> str | None:
    if max_proc_mem_mb and (s.get("proc_mem_mb") or 0) > max_proc_mem_mb:
        return f"command memory {s['proc_mem_mb']:.0f} MB > {max_proc_mem_mb:.0f} MB"
    if s["free_pct"] < min_free_pct:
        return f"free memory {s['free_pct']}% < {min_free_pct}%"
    grown = s["swap_used_mb"] - baseline_swap_mb
    if grown > max_swap_growth_mb:
        return f"swap grew {grown:.0f} MB > {max_swap_growth_mb:.0f} MB since launch"
    return None


def heavy_jobs(ps_text: str, *, skip: set[int]) -> list[tuple[int, str]]:
    """(pid, command) of heavy jobs in `ps -axo pid=,command=` output, minus `skip`."""
    out = []
    for line in ps_text.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        if pid.isdigit() and int(pid) not in skip and HEAVY.search(cmd) and "train.guard" not in cmd:
            out.append((int(pid), cmd.strip()))
    return out


def _kill_group(proc: subprocess.Popen, grace: float) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=grace)
            if sig is signal.SIGTERM:
                # The direct child is gone; make sure no grandchild (the MLX worker) outlived it.
                os.killpg(proc.pid, signal.SIGKILL)
            return
        except subprocess.TimeoutExpired:
            continue
        except ProcessLookupError:
            return


def run(cmd: list[str], *, log: str, sample: Callable[[], dict] = sample,
        proc_mem: Callable[[int], float | None] = proc_mem_mb, min_free_pct: int = 10,
        max_swap_growth_mb: float = 2048, max_proc_mem_mb: float = 0, interval: float = 1.0,
        grace: float = 15.0) -> int:
    """Run `cmd` under the memory guard; return its exit code, or KILLED_EXIT when the guard killed it."""
    os.makedirs(os.path.dirname(log) or ".", exist_ok=True)
    base = sample()
    t0 = time.monotonic()
    with open(log, "a", encoding="utf-8") as logf, open(log + ".mem.csv", "w", encoding="utf-8") as csv:
        csv.write("t_s,free_pct,swap_used_mb,proc_mem_mb\n")
        cap = f" or command > {max_proc_mem_mb:.0f} MB" if max_proc_mem_mb else ""
        header = (f"guard: start {time.strftime('%Y-%m-%d %H:%M:%S')} free {base['free_pct']}% "
                  f"swap {base['swap_used_mb']:.0f} MB; kill at free < {min_free_pct}% or swap "
                  f"+{max_swap_growth_mb:.0f} MB{cap}\nguard: cmd {' '.join(cmd)}\n")
        sys.stdout.write(header)
        logf.write(header)
        logf.flush()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)

        def tee() -> None:
            for raw in iter(proc.stdout.readline, b""):
                line = raw.decode("utf-8", "replace")
                sys.stdout.write(line)
                sys.stdout.flush()
                logf.write(line)
                logf.flush()

        reader = threading.Thread(target=tee, daemon=True)
        reader.start()
        reason, peak = None, 0.0
        try:
            while proc.poll() is None:
                s = {**sample(), "proc_mem_mb": proc_mem(proc.pid)}
                peak = max(peak, s["proc_mem_mb"] or 0)
                pm = "" if s["proc_mem_mb"] is None else f"{s['proc_mem_mb']:.0f}"
                csv.write(f"{time.monotonic() - t0:.1f},{s['free_pct']},{s['swap_used_mb']:.0f},{pm}\n")
                csv.flush()
                reason = kill_reason(s, baseline_swap_mb=base["swap_used_mb"], min_free_pct=min_free_pct,
                                     max_swap_growth_mb=max_swap_growth_mb, max_proc_mem_mb=max_proc_mem_mb)
                if reason:
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            reason = "Ctrl-C"
        if reason:
            _kill_group(proc, grace)
        else:
            _kill_group(proc, 0.1)  # the child exited; reap any orphaned grandchild in its group
        reader.join(timeout=5)
        code = KILLED_EXIT if reason else proc.returncode
        footer = (f"guard: killed ({reason})" if reason else f"guard: exit {code}") + f"; command peak {peak:.0f} MB\n"
        sys.stdout.write(footer)
        logf.write(footer)
    return code


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="python -m train.guard", description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True)
    ap.add_argument("--min-free-pct", type=int, default=10)
    ap.add_argument("--max-swap-growth-mb", type=float, default=2048)
    ap.add_argument("--max-proc-mem-mb", type=float, default=0, help="kill when the command itself goes over this")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--force", action="store_true", help="start even if another heavy job is running")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- command ...")
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        ap.error("give the command after --")
    ps = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, check=True).stdout
    busy = heavy_jobs(ps, skip={os.getpid(), os.getppid()})
    if busy and not a.force:
        for pid, c in busy:
            print(f"guard: heavy job running: {pid} {c[:120]}", file=sys.stderr)
        sys.exit("guard: refusing to start; stop those first (or pass --force)")
    sys.exit(run(cmd, log=a.log, min_free_pct=a.min_free_pct, max_swap_growth_mb=a.max_swap_growth_mb,
                 max_proc_mem_mb=a.max_proc_mem_mb, interval=a.interval))


if __name__ == "__main__":
    main()
