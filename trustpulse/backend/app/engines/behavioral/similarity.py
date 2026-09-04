"""
TrustPulse AI — Behavioral Statistical Distance & Similarity Engine.

Implements transparent, reproducible statistical methods:
  * normalized feature extraction from SDK payloads
  * robust z-score distance
  * cosine similarity
  * rolling mean / std helpers

Does not rely on proprietary black boxes or deep-learning pretensions.
"""

import math
from typing import Any, Dict, List, Optional


class SimilarityEngine:
    @staticmethod
    def extract_feature_vector(features: Dict[str, Any]) -> Dict[str, float]:
        """Flattens SDK feature payload into finite numeric key/value pairs."""
        vec: Dict[str, Optional[float]] = {}

        typing = features.get("typing")
        if typing and isinstance(typing, dict):
            vec["typing_dwell"] = _f(typing.get("meanDwellTime"))
            vec["typing_dwell_std"] = _f(typing.get("dwellStdDev"))
            vec["typing_flight"] = _f(typing.get("meanFlightTime"))
            vec["typing_flight_std"] = _f(typing.get("flightStdDev"))
            vec["typing_speed"] = _f(typing.get("typingSpeed"))
            vec["typing_pause"] = _f(typing.get("pauseRate"))

        mouse = features.get("mouse")
        if mouse and isinstance(mouse, dict):
            vec["mouse_velocity"] = _f(mouse.get("meanVelocity"))
            vec["mouse_velocity_std"] = _f(mouse.get("velocityStdDev"))
            vec["mouse_accel"] = _f(mouse.get("meanAcceleration"))
            vec["mouse_dir_rate"] = _f(mouse.get("directionChangeRate"))

        click = features.get("click")
        if click and isinstance(click, dict):
            vec["click_interval"] = _f(click.get("meanInterval"))
            vec["click_interval_std"] = _f(click.get("intervalStdDev"))
            vec["click_freq"] = _f(click.get("clickFrequency"))

        scroll = features.get("scroll")
        if scroll and isinstance(scroll, dict):
            vec["scroll_velocity"] = _f(scroll.get("meanVelocity"))
            vec["scroll_distance"] = _f(scroll.get("totalDistance"))

        touch = features.get("touch")
        if touch and isinstance(touch, dict):
            vec["touch_duration"] = _f(touch.get("meanDuration"))
            vec["touch_velocity"] = _f(touch.get("meanVelocity"))

        return {k: v for k, v in vec.items() if v is not None and math.isfinite(v)}

    @staticmethod
    def normalize_vector(values: Dict[str, float]) -> Dict[str, float]:
        """L2-normalizes a vector without changing a zero vector."""
        norm = math.sqrt(sum(v * v for v in values.values()))
        if norm <= 0:
            return {k: 0.0 for k in values}
        return {k: v / norm for k, v in values.items()}

    @staticmethod
    def compute_z_score_distance(
        observed: Dict[str, float],
        baseline_means: Dict[str, float],
        baseline_stds: Dict[str, float],
    ) -> float:
        """Mean normalized z-score distance across common features (0 = perfect match)."""
        common_keys = set(observed.keys()) & set(baseline_means.keys())
        if not common_keys:
            return 0.0

        total_z = 0.0
        matched = 0
        for key in common_keys:
            obs = observed[key]
            mean = baseline_means[key]
            std = baseline_stds.get(key, 0.0)
            if not math.isfinite(std) or std <= 0.001:
                std = max(1.0, abs(mean) * 0.2)
            z = abs(obs - mean) / std
            total_z += min(z, 5.0)
            matched += 1
        return total_z / matched if matched else 0.0

    @staticmethod
    def compute_robust_z_score_distance(
        observed: Dict[str, float],
        baseline_medians: Dict[str, float],
        baseline_mads: Dict[str, float],
    ) -> float:
        """Robust z-score distance using median/MAD where provided."""
        return SimilarityEngine._z_distance(observed, baseline_medians, baseline_mads)

    @staticmethod
    def _z_distance(
        observed: Dict[str, float],
        centers: Dict[str, float],
        spreads: Dict[str, float],
    ) -> float:
        common_keys = set(observed.keys()) & set(centers.keys())
        if not common_keys:
            return 0.0
        total = 0.0
        for key in common_keys:
            center = centers[key]
            spread = spreads.get(key, 0.0)
            if not math.isfinite(spread) or spread <= 0.001:
                spread = max(1.0, abs(center) * 0.2)
            total += min(abs(observed[key] - center) / spread, 5.0)
        return total / len(common_keys)

    @staticmethod
    def compute_cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        """Cosine similarity over common keys (0.0 to 1.0 clamped)."""
        common_keys = set(vec1.keys()) & set(vec2.keys())
        if not common_keys:
            return 0.5
        dot = sum(vec1[k] * vec2[k] for k in common_keys)
        norm1 = math.sqrt(sum(vec1[k] ** 2 for k in common_keys))
        norm2 = math.sqrt(sum(vec2[k] ** 2 for k in common_keys))
        if norm1 <= 0 or norm2 <= 0:
            return 0.5
        return max(0.0, min(1.0, dot / (norm1 * norm2)))

    @staticmethod
    def compute_rolling_statistics(
        observations: List[Dict[str, float]],
        alpha: float = 0.15,
    ) -> Optional[Dict[str, Any]]:
        """EMA-based rolling mean/std. Missing keys are dropped."""
        if not observations:
            return None
        means: Dict[str, float] = {}
        stds: Dict[str, float] = {}
        count = 0
        for obs in observations:
            count += 1
            for k, v in obs.items():
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
        return {"means": means, "stds": stds, "observation_count": count, "version": 1}


def _f(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) else None
