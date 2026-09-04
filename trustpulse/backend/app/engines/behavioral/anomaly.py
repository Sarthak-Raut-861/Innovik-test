"""
TrustPulse AI — Short-Term Behavioral Anomaly Engine.

Uses transparent statistical methods:
  * robust z-score (with MAD-based spread when available)
  * Mahalanobis-style normalized distance
  * cosine similarity as a secondary signal
  * feature-specific anomaly codes

Returns evidence only. It never returns a security decision, and missing
features are treated as "no evidence", not as malicious or trusted.
"""

import math
from typing import Any, Dict, List, Optional, Tuple

from app.engines.behavioral.similarity import SimilarityEngine


class AnomalyEngine:
    @staticmethod
    def evaluate_features(
        observed_features: Dict[str, Any],
        trusted_baseline: Optional[Dict[str, Any]],
    ) -> Tuple[float, bool, List[str]]:
        """Returns (anomaly_score [0-1], is_anomaly, reason_codes)."""
        if (
            not trusted_baseline
            or not isinstance(trusted_baseline, dict)
            or "means" not in trusted_baseline
        ):
            return 0.0, False, ["COLD_START_NO_BASELINE"]

        obs_vec = SimilarityEngine.extract_feature_vector(observed_features)
        obs_vec = _sanitize(obs_vec)
        if not obs_vec:
            return 0.0, False, ["NO_INTERACTION_FEATURES"]

        means = _sanitize(_as_float_dict(trusted_baseline.get("means", {})))
        stds = _sanitize(_as_float_dict(trusted_baseline.get("stds", {})))

        z_dist = SimilarityEngine.compute_z_score_distance(obs_vec, means, stds)
        cos_sim = SimilarityEngine.compute_cosine_similarity(obs_vec, means)

        reason_codes: List[str] = []
        _check_feature_anomalies(obs_vec, means, stds, reason_codes)

        # z-dist normalized: 0 -> 0, ~3 -> 1
        normalized_z = min(1.0, z_dist / 3.0)
        cos_dissim = 1.0 - cos_sim
        anomaly_score = max(0.0, min(1.0, normalized_z * 0.7 + cos_dissim * 0.3))

        is_anomaly = anomaly_score >= 0.5 or len(reason_codes) >= 2
        if is_anomaly:
            reason_codes = list(dict.fromkeys(reason_codes + ["BEHAVIOR_ANOMALY"]))

        return round(anomaly_score, 4), is_anomaly, reason_codes


def _as_float_dict(value: Any) -> Dict[str, float]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, float] = {}
    for k, v in value.items():
        try:
            out[str(k)] = float(v)
        except (TypeError, ValueError):
            continue
    return out


def _sanitize(values: Dict[str, float]) -> Dict[str, float]:
    """Drops NaN/Inf values and retains finite numbers only."""
    return {k: float(v) for k, v in values.items() if math.isfinite(float(v))}


def _check_feature_anomalies(
    obs: Dict[str, float], means: Dict[str, float], stds: Dict[str, float], reason_codes: List[str]
) -> None:
    checks = [
        ("typing_dwell", "TYPING_DWELL_ANOMALY"),
        ("typing_flight", "TYPING_FLIGHT_ANOMALY"),
        ("mouse_velocity", "MOUSE_KINEMATICS_ANOMALY"),
        ("click_interval", "CLICK_CADENCE_ANOMALY"),
        ("scroll_velocity", "SCROLL_VELOCITY_ANOMALY"),
    ]
    for feature, code in checks:
        if feature not in obs or feature not in means:
            continue
        mean = means[feature]
        std = stds.get(feature, 0.0)
        if std <= 0.001:
            std = max(0.5, abs(mean) * 0.2)
        if math.isfinite(std) and std > 0:
            z = abs(obs[feature] - mean) / std
            if z > 2.5:
                reason_codes.append(code)
