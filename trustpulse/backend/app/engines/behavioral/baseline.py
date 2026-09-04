"""
TrustPulse AI — Behavioral Baseline Management Engine.

Implements the trusted/candidate baseline model.

  * Candidate baseline absorbs new behavioral observations.
  * Trusted baseline ONLY updates when a guarded promotion gate passes:
      - session confidence sufficiently high
      - no open incident
      - no suspicious / blocked / isolated action
      - server policy allows learning
"""

from typing import Any, Dict, Optional, Tuple

from app.core.config import settings


class BaselineEngine:
    @staticmethod
    def update_rolling_baseline(
        current_baseline: Optional[Dict[str, Any]],
        new_features: Dict[str, float],
        alpha: float = 0.15,
    ) -> Dict[str, Any]:
        """Updates an EMA baseline. Initializes a new baseline when absent."""
        if not current_baseline or "means" not in current_baseline:
            means = {k: v for k, v in new_features.items() if _finite(v)}
            stds = {k: max(1.0, abs(v) * 0.2) for k, v in means.items()}
            return {"means": means, "stds": stds, "observation_count": 1, "version": 1}

        means = dict(current_baseline.get("means", {}))
        stds = dict(current_baseline.get("stds", {}))
        count = int(current_baseline.get("observation_count", 1)) + 1

        for k, v in new_features.items():
            if not _finite(v):
                continue
            if k in means:
                old_mean = means[k]
                new_mean = (1 - alpha) * old_mean + alpha * v
                diff = abs(v - new_mean)
                old_std = stds.get(k, max(1.0, abs(new_mean) * 0.2))
                means[k] = new_mean
                stds[k] = max(0.5, (1 - alpha) * old_std + alpha * diff)
            else:
                means[k] = v
                stds[k] = max(1.0, abs(v) * 0.2)

        return {
            "means": means,
            "stds": stds,
            "observation_count": count,
            "version": int(current_baseline.get("version", 1)),
        }

    @staticmethod
    def can_promote_to_trusted(
        session_confidence: int,
        has_active_incident: bool,
        has_suspicious_action: bool,
        policy_allows_learning: bool = True,
        observation_count: Optional[int] = None,
    ) -> bool:
        """Promotion gate for the trusted baseline."""
        if not policy_allows_learning:
            return False
        if has_active_incident or has_suspicious_action:
            return False
        if session_confidence < settings.BASELINE_PROMOTE_MIN_CONFIDENCE:
            return False
        if observation_count is not None and observation_count < settings.MIN_TRUSTED_OBSERVATIONS:
            return False
        return True

    @staticmethod
    def promote_candidate(
        trusted_baseline: Optional[Dict[str, Any]],
        candidate_baseline: Dict[str, Any],
        alpha: float = 0.25,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Promotes a validated candidate into the trusted baseline.

        Returns (new_trusted_baseline, previous_trusted_baseline_for_rollback).
        """
        previous = dict(trusted_baseline) if trusted_baseline else None
        if not trusted_baseline:
            return dict(candidate_baseline), previous

        cand_means = dict(candidate_baseline.get("means", {}))
        updated = BaselineEngine.update_rolling_baseline(trusted_baseline, cand_means, alpha=alpha)
        return updated, previous

    @staticmethod
    def rollback_in_memory(
        trusted_baseline: Optional[Dict[str, Any]],
        previous_baseline: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Convenience helper; rollback is also persisted by the repository."""
        return dict(previous_baseline) if previous_baseline else trusted_baseline


def _finite(value: float) -> bool:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    import math

    return math.isfinite(v)
