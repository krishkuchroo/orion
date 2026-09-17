import threading
import time


class PhaseSampler:
    def __init__(self, pid: int, interval: float = 1.0):
        self.pid = pid
        self.interval = interval
        self.peak_rss_mb = None
        self.wall_seconds = 0.0
        self._stop = threading.Event()
        self._t = None
        self._start = None

    def _sample_once(self):
        try:
            import psutil
            p = psutil.Process(self.pid)
            total = p.memory_info().rss
            for c in p.children(recursive=True):
                try:
                    total += c.memory_info().rss
                except psutil.Error:
                    pass
            mb = total / (1024 * 1024)
            if self.peak_rss_mb is None or mb > self.peak_rss_mb:
                self.peak_rss_mb = mb
        except Exception:
            pass  # psutil missing or process gone; leave peak as-is

    def _loop(self):
        while not self._stop.is_set():
            self._sample_once()
            self._stop.wait(self.interval)

    def __enter__(self):
        self._start = time.monotonic()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._t:
            self._t.join(timeout=2.0)
        self.wall_seconds = time.monotonic() - self._start
        return False
