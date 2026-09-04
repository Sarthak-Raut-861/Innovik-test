"""
TrustPulse AI — In-process observability counters.

These are non-sensitive operational metrics used for /health and structured logs.
They are intentionally simple (in-process) for Phase 2; production hardening may
replace them with Prometheus/OTel.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import DefaultDict, Dict


class MetricsRegistry:
    def __init__(self) -> None:
        self._counters: DefaultDict[str, int] = defaultdict(int)
        self._gauges: DefaultDict[str, float] = defaultdict(float)
        self._lock = Lock()
        self._started_at = time.time()

    def incr(self, metric: str, value: int = 1) -> None:
        with self._lock:
            self._counters[metric] += value

    def set_gauge(self, metric: str, value: float) -> None:
        with self._lock:
            self._gauges[metric] = float(value)

    def snapshot(self, as_dict: bool = False) -> Dict[str, object]:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
        combined: Dict[str, object] = {
            "uptime_seconds": round(time.time() - self._started_at, 2),
        }
        combined.update({f"counter_{k}": v for k, v in counters.items()})
        combined.update({f"gauge_{k}": v for k, v in gauges.items()})
        combined["counters"] = counters if not as_dict else counters
        return combined

    def counters_snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counters)


metrics = MetricsRegistry()
