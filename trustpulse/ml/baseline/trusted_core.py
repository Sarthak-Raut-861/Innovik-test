"""Trusted Core baseline.

The Trusted Core is the stable, slowly-moving behavioral reference for a
user+device pair. It is deliberately hard to move:

* updates use a small EMA alpha (prototype default 0.05);
* it is never updated from a suspicious / blocked / contained session;
* promotion of learned drift happens only through :mod:`adaptive_shadow`.

All statistics live in the *transformed* feature space (see
``feature_extraction.features.transform``).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from trustpulse_ml.feature_extraction.features import initial_std

DEFAULT_TRUSTED_ALPHA = 0.05
MIN_STD = 0.05


@dataclass
class Baseline:
    """A mean/std profile over canonical behavioral features."""

    means: Dict[str, float] = field(default_factory=dict)
    stds: Dict[str, float] = field(default_factory=dict)
    observation_count: int = 0
    version: int = 1
    rejected_observations: int = 0  # observations refused by the promotion gate

    # ------------------------------------------------------------------ serialisation
    def to_dict(self) -> Dict[str, Any]:
        return {
            "means": dict(self.means),
            "stds": dict(self.stds),
            "observation_count": self.observation_count,
            "version": self.version,
            "rejected_observations": self.rejected_observations,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Baseline":
        if not isinstance(data, dict):
            return cls()
        return cls(
            means={k: float(v) for k, v in (data.get("means") or {}).items() if _finite(v)},
            stds={k: float(v) for k, v in (data.get("stds") or {}).items() if _finite(v)},
            observation_count=int(data.get("observation_count") or 0),
            version=int(data.get("version") or 1),
            rejected_observations=int(data.get("rejected_observations") or 0),
        )

    def is_empty(self) -> bool:
        return not self.means or self.observation_count == 0

    def feature_names(self) -> list[str]:
        return sorted(self.means.keys())


class TrustedCore:
    """Slow-learning, promotion-gated behavioral baseline."""

    def __init__(self, alpha: float = DEFAULT_TRUSTED_ALPHA) -> None:
        self.alpha = max(0.001, min(0.9, alpha))

    # ------------------------------------------------------------------ updates
    def update(
        self,
        current: Baseline,
        observation: Dict[str, float],
        alpha: Optional[float] = None,
    ) -> Baseline:
        """Fold one derived observation into the core. Returns a NEW baseline."""
        step = self.alpha if alpha is None else max(0.001, min(0.9, alpha))
        clean = {k: float(v) for k, v in observation.items() if _finite(v)}
        if not clean:
            return current

        if current.is_empty():
            return Baseline(
                means=dict(clean),
                stds={k: initial_std(k, v) for k, v in clean.items()},
                observation_count=1,
                version=1,
                rejected_observations=current.rejected_observations,
            )

        means = dict(current.means)
        stds = dict(current.stds)
        for key, value in clean.items():
            old_mean = means.get(key)
            if old_mean is None:
                means[key] = value
                stds[key] = initial_std(key, value)
                continue
            new_mean = (1 - step) * old_mean + step * value
            deviation = abs(value - new_mean)
            old_std = stds.get(key, initial_std(key, new_mean))
            means[key] = new_mean
            stds[key] = max(MIN_STD, (1 - step) * old_std + step * deviation)

        return Baseline(
            means=means,
            stds=stds,
            observation_count=current.observation_count + 1,
            version=current.version + 1,
            rejected_observations=current.rejected_observations,
        )

    def record_rejection(self, current: Baseline) -> Baseline:
        """Counts a refused observation without touching the statistics."""
        return Baseline(
            means=dict(current.means),
            stds=dict(current.stds),
            observation_count=current.observation_count,
            version=current.version,
            rejected_observations=current.rejected_observations + 1,
        )


def baseline_distance(left: Baseline, right: Baseline) -> float:
    """Mean absolute difference in transformed space over shared features.

    Returns 0.0 for identical profiles. Returns ``float('inf')`` when the two
    baselines share no features, which callers treat as "incomparable".
    """
    shared = sorted(set(left.means) & set(right.means))
    if not shared:
        return float("inf")
    total = 0.0
    for name in shared:
        a = left.means[name]
        b = right.means[name]
        if _finite(a) and _finite(b):
            total += abs(a - b)
    return total / len(shared)


def _finite(value: Any) -> bool:
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False
