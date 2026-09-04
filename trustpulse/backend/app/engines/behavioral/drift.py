"""
TrustPulse AI — Behavioral Drift Detection Engine.

Detects gradual or abrupt divergence between candidate observations and the
trusted baseline. Drift alone is evidence, not a decision.
"""

import math
from typing import Any, Dict, Optional, Tuple

from app.engines.behavioral.similarity import SimilarityEngine


class DriftEngine:
    @staticmethod
    def evaluate_drift(
        candidate_baseline: Optional[Dict[str, Any]],
        trusted_baseline: Optional[Dict[str, Any]],
    ) -> Tuple[float, bool]:
        """Returns (drift_magnitude [0-1], is_significant_drift)."""
        if not candidate_baseline or not trusted_baseline:
            return 0.0, False

        cand_means = _to_float(candidate_baseline.get("means", {}))
        trust_means = _to_float(trusted_baseline.get("means", {}))
        trust_stds = _to_float(trusted_baseline.get("stds", {}))

        if not cand_means or not trust_means:
            return 0.0, False

        z_dist = SimilarityEngine.compute_z_score_distance(cand_means, trust_means, trust_stds)
        feature_z = _max_z(cand_means, trust_means, trust_stds)
        # Combine average directional drift with the strongest feature deviation so
        # a concentrated change (e.g. all typing features shifted together) is detected.
        combined_z = 0.65 * z_dist + 0.35 * feature_z
        drift_magnitude = min(1.0, combined_z / 3.0)
        is_significant = drift_magnitude >= 0.6
        return round(drift_magnitude, 4), is_significant


def _max_z(candidate: Dict[str, float], trusted: Dict[str, float], stds: Dict[str, float]) -> float:
    common = set(candidate.keys()) & set(trusted.keys())
    if not common:
        return 0.0
    max_z = 0.0
    for k in common:
        std = stds.get(k, 0.0)
        if not math.isfinite(std) or std <= 0.001:
            std = max(1.0, abs(trusted[k]) * 0.2)
        max_z = max(max_z, abs(candidate[k] - trusted[k]) / std)
    return min(max_z, 5.0)


def _to_float(value: Any) -> Dict[str, float]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, float] = {}
    for k, v in value.items():
        try:
            f = float(v)
            if math.isfinite(f):
                out[str(k)] = f
        except (TypeError, ValueError):
            continue
    return out
