"""
TrustPulse AI - Behavioral Drift Detection Engine
"""

from typing import Dict, Any, Optional, Tuple
from app.engines.behavioral.similarity import SimilarityEngine


class DriftEngine:
    """
    Evaluates drift between candidate baseline observations and the trusted baseline.
    Differentiates between natural gradual adaptation and abrupt session hijacking.
    """

    @staticmethod
    def evaluate_drift(
        candidate_baseline: Optional[Dict[str, Any]],
        trusted_baseline: Optional[Dict[str, Any]],
    ) -> Tuple[float, bool]:
        """
        Returns (drift_magnitude [0.0 - 1.0], is_significant_drift [bool]).
        """
        if not candidate_baseline or not trusted_baseline:
            return 0.0, False

        cand_means = candidate_baseline.get("means", {})
        trust_means = trusted_baseline.get("means", {})
        trust_stds = trusted_baseline.get("stds", {})

        if not cand_means or not trust_means:
            return 0.0, False

        z_dist = SimilarityEngine.compute_z_score_distance(cand_means, trust_means, trust_stds)
        drift_magnitude = min(1.0, z_dist / 3.0)
        is_significant = drift_magnitude >= 0.6

        return drift_magnitude, is_significant
