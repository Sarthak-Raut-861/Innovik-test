"""
TrustPulse AI - Behavioral Statistical Distance & Similarity Engine
"""

import math
from typing import Dict, Any, List, Optional


class SimilarityEngine:
    """
    Computes statistical similarity between observed telemetry features and baseline profiles.
    Does not rely on proprietary black boxes; uses transparent, reproducible statistical metrics.
    """

    @staticmethod
    def extract_feature_vector(features: Dict[str, Any]) -> Dict[str, float]:
        """Flattens feature payload into numerical key-value pairs."""
        vec: Dict[str, float] = {}

        typing = features.get("typing")
        if typing and isinstance(typing, dict):
            if typing.get("meanDwellTime") is not None:
                vec["typing_dwell"] = float(typing["meanDwellTime"])
            if typing.get("dwellStdDev") is not None:
                vec["typing_dwell_std"] = float(typing["dwellStdDev"])
            if typing.get("meanFlightTime") is not None:
                vec["typing_flight"] = float(typing["meanFlightTime"])
            if typing.get("typingSpeed") is not None:
                vec["typing_speed"] = float(typing["typingSpeed"])
            if typing.get("pauseRate") is not None:
                vec["typing_pause"] = float(typing["pauseRate"])

        mouse = features.get("mouse")
        if mouse and isinstance(mouse, dict):
            if mouse.get("meanVelocity") is not None:
                vec["mouse_velocity"] = float(mouse["meanVelocity"])
            if mouse.get("meanAcceleration") is not None:
                vec["mouse_accel"] = float(mouse["meanAcceleration"])
            if mouse.get("directionChangeRate") is not None:
                vec["mouse_dir_rate"] = float(mouse["directionChangeRate"])

        click = features.get("click")
        if click and isinstance(click, dict):
            if click.get("meanInterval") is not None:
                vec["click_interval"] = float(click["meanInterval"])
            if click.get("clickFrequency") is not None:
                vec["click_freq"] = float(click["clickFrequency"])

        scroll = features.get("scroll")
        if scroll and isinstance(scroll, dict):
            if scroll.get("meanVelocity") is not None:
                vec["scroll_velocity"] = float(scroll["meanVelocity"])

        return vec

    @staticmethod
    def compute_z_score_distance(
        observed: Dict[str, float],
        baseline_means: Dict[str, float],
        baseline_stds: Dict[str, float],
    ) -> float:
        """
        Computes mean normalized Mahalanobis/Z-score distance across common features.
        Distance of 0.0 means perfect match. Distance > 2.5 indicates significant deviation.
        """
        common_keys = set(observed.keys()) & set(baseline_means.keys())
        if not common_keys:
            return 0.0  # No comparable features

        total_z = 0.0
        for key in common_keys:
            obs = observed[key]
            mean = baseline_means[key]
            std = baseline_stds.get(key, 0.0)
            if std <= 0.001:
                std = max(1.0, abs(mean) * 0.2)  # Defensive variance estimate

            z = abs(obs - mean) / std
            total_z += min(z, 5.0)  # Clamp outlier influence

        return total_z / len(common_keys)

    @staticmethod
    def compute_cosine_similarity(vec1: Dict[str, float], vec2: Dict[str, float]) -> float:
        """Computes cosine similarity between two feature vectors (0.0 to 1.0)."""
        common_keys = set(vec1.keys()) & set(vec2.keys())
        if not common_keys:
            return 0.5  # Neutral similarity when no common overlap

        dot = sum(vec1[k] * vec2[k] for k in common_keys)
        norm1 = math.sqrt(sum(vec1[k] ** 2 for k in common_keys))
        norm2 = math.sqrt(sum(vec2[k] ** 2 for k in common_keys))

        if norm1 == 0 or norm2 == 0:
            return 0.5

        sim = dot / (norm1 * norm2)
        return max(0.0, min(1.0, sim))
