"""
TrustPulse AI - Behavioral Baseline Management Engine
"""

from typing import Dict, Any, Optional, Tuple
from app.engines.behavioral.similarity import SimilarityEngine
from app.core.logging import logger


class BaselineEngine:
    """
    Manages Trusted vs Candidate behavioral baselines.
    Strictly protects trusted baselines from being poisoned by unverified or suspicious sessions.
    """

    @staticmethod
    def update_rolling_baseline(
        current_baseline: Optional[Dict[str, Any]],
        new_features: Dict[str, float],
        alpha: float = 0.15,
    ) -> Dict[str, Any]:
        """
        Updates a baseline using exponential moving average (EMA) for means and variance.
        """
        if not current_baseline or "means" not in current_baseline:
            # Initialize new baseline
            means = {k: v for k, v in new_features.items()}
            stds = {k: max(1.0, abs(v) * 0.2) for k, v in new_features.items()}
            return {
                "means": means,
                "stds": stds,
                "observation_count": 1,
            }

        means = dict(current_baseline["means"])
        stds = dict(current_baseline.get("stds", {}))
        count = current_baseline.get("observation_count", 1) + 1

        for k, v in new_features.items():
            if k in means:
                old_mean = means[k]
                new_mean = (1 - alpha) * old_mean + alpha * v
                diff = abs(v - new_mean)
                old_std = stds.get(k, max(1.0, abs(new_mean) * 0.2))
                new_std = (1 - alpha) * old_std + alpha * diff
                means[k] = new_mean
                stds[k] = max(0.5, new_std)
            else:
                means[k] = v
                stds[k] = max(1.0, abs(v) * 0.2)

        return {
            "means": means,
            "stds": stds,
            "observation_count": count,
        }

    @staticmethod
    def can_promote_to_trusted(
        session_confidence: int,
        has_active_incident: bool,
        has_suspicious_action: bool,
        policy_allows_learning: bool = True,
    ) -> bool:
        """
        Baseline Protection Gate:
        A candidate baseline can ONLY be promoted into the trusted baseline if:
        1. Session confidence is sufficiently high (>= 80)
        2. No active security incident is open
        3. No suspicious action has been executed
        4. Learning policy is enabled
        """
        if not policy_allows_learning:
            return False
        if has_active_incident or has_suspicious_action:
            return False
        return session_confidence >= 80

    @staticmethod
    def promote_candidate(
        trusted_baseline: Optional[Dict[str, Any]],
        candidate_baseline: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Merges validated candidate baseline observations into the trusted baseline."""
        if not trusted_baseline:
            return dict(candidate_baseline)

        cand_means = candidate_baseline.get("means", {})
        return BaselineEngine.update_rolling_baseline(trusted_baseline, cand_means, alpha=0.25)
