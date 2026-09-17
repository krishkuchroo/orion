import os
import time
from eval.resources import PhaseSampler


def test_sampler_measures_own_process_and_wall():
    with PhaseSampler(os.getpid(), interval=0.05) as s:
        blob = [0] * 1_000_000  # allocate to move RSS
        time.sleep(0.2)
        del blob
    assert s.wall_seconds >= 0.15
    assert s.peak_rss_mb is None or s.peak_rss_mb > 0


def test_sampler_survives_dead_pid():
    with PhaseSampler(2_000_000_000, interval=0.05) as s:  # pid that cannot exist
        pass
    assert s.peak_rss_mb is None or s.peak_rss_mb >= 0
