import os
import sys

from train import guard

SWAP = "total = 4096.00M  used = 3235.62M  free = 860.38M  (encrypted)"


def test_parse_swap_used_mb():
    assert guard.parse_swap_used_mb(SWAP) == 3235.62


def test_parse_swap_used_mb_reads_gigabytes():
    assert guard.parse_swap_used_mb("total = 8.00G  used = 1.50G  free = 6.50G") == 1536.0


def test_kill_reason_none_while_healthy():
    assert guard.kill_reason({"free_pct": 40, "swap_used_mb": 3300}, baseline_swap_mb=3200,
                             min_free_pct=10, max_swap_growth_mb=2048) is None


def test_kill_reason_on_low_free_memory():
    assert "free memory 9%" in guard.kill_reason({"free_pct": 9, "swap_used_mb": 0}, baseline_swap_mb=0,
                                                 min_free_pct=10, max_swap_growth_mb=2048)


def test_kill_reason_on_swap_growth_not_absolute_swap():
    """Swap already in use at launch is not the run's doing; only growth past the baseline counts."""
    healthy = {"free_pct": 50, "swap_used_mb": 5000}
    assert guard.kill_reason(healthy, baseline_swap_mb=4000, min_free_pct=10, max_swap_growth_mb=2048) is None
    assert "swap grew" in guard.kill_reason({**healthy, "swap_used_mb": 6100}, baseline_swap_mb=4000,
                                            min_free_pct=10, max_swap_growth_mb=2048)


def test_parse_top_mem_mb():
    assert guard.parse_top_mem_mb("1248K") == 1248 / 1024
    assert guard.parse_top_mem_mb("19M") == 19
    assert guard.parse_top_mem_mb("2.5G") == 2560
    assert guard.parse_top_mem_mb("6912M+") == 6912
    assert guard.parse_top_mem_mb("n/a") is None


def test_kill_reason_on_command_memory_cap():
    """The 7 GB training budget is enforced on the command itself, not on the whole machine."""
    s = {"free_pct": 50, "swap_used_mb": 0, "proc_mem_mb": 7300}
    assert "command memory 7300 MB" in guard.kill_reason(s, baseline_swap_mb=0, min_free_pct=10,
                                                         max_swap_growth_mb=2048, max_proc_mem_mb=7168)
    assert guard.kill_reason(s, baseline_swap_mb=0, min_free_pct=10, max_swap_growth_mb=2048) is None


def test_heavy_jobs_finds_builds_and_training_but_not_itself():
    ps = "\n".join([
        "101 /x/python -m train.stage1",
        "102 java -Xmx8g -jar joern-cli.jar",
        "103 /u/bin/unsloth train -c a.yaml",
        "104 /x/python -m train.guard -- unsloth train -c a.yaml",
        "105 /Applications/Visual Studio Code.app/Contents/MacOS/Electron",
    ])
    assert [pid for pid, _ in guard.heavy_jobs(ps, skip={104})] == [101, 102, 103]


def test_run_kills_the_whole_process_group(tmp_path):
    """The MLX worker is a spawned grandchild; killing only the direct child would leave it running."""
    pidfile = tmp_path / "grandchild.pid"
    script = (f"import subprocess,sys,time;"
              f"p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
              f"open({str(pidfile)!r},'w').write(str(p.pid));print('started',flush=True);time.sleep(60)")
    samples = iter([{"free_pct": 50, "swap_used_mb": 0}] * 3 + [{"free_pct": 1, "swap_used_mb": 0}] * 100)
    log = tmp_path / "run.log"
    code = guard.run([sys.executable, "-c", script], log=str(log), sample=lambda: next(samples),
                     proc_mem=lambda pid: 123.0, min_free_pct=10, max_swap_growth_mb=2048, interval=0.2, grace=2)
    assert code == guard.KILLED_EXIT
    gpid = int(pidfile.read_text())
    try:
        os.kill(gpid, 0)
        alive = True
    except ProcessLookupError:
        alive = False
    assert not alive
    text = log.read_text()
    assert "started" in text and "guard: killed" in text and "command peak 123 MB" in text
    assert (tmp_path / "run.log.mem.csv").read_text().startswith("t_s,free_pct,swap_used_mb,proc_mem_mb")
