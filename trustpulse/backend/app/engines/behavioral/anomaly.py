"""
TrustPulse AI - Behavioral Anomaly Detection Engine
"""

from typing import Dict, Any, List, Tuple, Optional
from app.engines.behavioral.similarity import SimilarityEngine


class AnomalyEngine:
    """
    Detects short-term behavioral anomalies by evaluating z-score deviation and cosine similarity.
    """

    @staticmethod
    def evaluate_features(
        observed_features: Dict[str, Any],
        trusted_baseline: Optional[Dict[str, Any]],
    ) -> Tuple[float, bool, List[str]]:
        """
        Evaluates behavioral anomaly.
        Returns:
            (anomaly_score [0.0 - 1.0], is_anomaly [bool], reason_codes [List[str]])
        """
        if not trusted_baseline or "means" not in trusted_baseline:
            return 0.0, False, ["COLD_START_NO_BASELINE"]

        obs_vec = SimilarityEngine.extract_feature_vector(observed_features)
        if not obs_vec:
            return 0.0, False, ["NO_INTERACTION_FEATURES"]

        means = trusted_baseline["means"]
        stds = trusted_baseline.get("stds", {})

        z_dist = SimilarityEngine.compute_z_score_distance(obs_vec, means, stds)
        cos_sim = SimilarityEngine.compute_cosine_similarity(obs_vec, means)

        reason_codes: List[str] = []

        # Feature-specific anomaly checks
        if "typing_dwell" in obs_vec and "typing_dwell" in means:
            std_val = stds.get("typing_dwell", max(1.0, means["typing_dwell"] * 0.2))
            if abs(obs_vec["typing_dwell"] - means["typing_dwell"]) / std_val > 2.5:
                reason_codes.append("TYPING_DWELL_ANOMALY")

        if "mouse_velocity" in obs_vec and "mouse_velocity" in means:
            std_val = stds.get("mouse_velocity", max(1.0, means["mouse_velocity"] * 0.2))
            if abs(obs_vec["mouse_velocity"] - means["mouse_velocity"]) / std_val > 2.5:
                reason_codes.append("MOUSE_KINEMATICS_ANOMALY")

        if "click_interval" in obs_vec and "click_interval" in means:
            std_val = stds.get("click_interval", max(1.0, means["click_interval"] * 0.2))
            if abs(obs_vec["click_interval"] - means["click_interval"]) / std_val > 2.5:
                reason_codes.append("CLICK_CADENCE_ANOMALY")

        # Aggregate anomaly score: combine z-distance and cosine dissimilarity
        # z_dist: 0 -> 0, 2.5 -> ~0.5, 5.0 -> 1.0
        normalized_z = min(1.0, z_dist / 3.0)
        cos_dissim = 1.0 - cos_sim
        anomaly_score = (normalized_z * 0.7) + (cos_dissim * 0.3)
        anomaly_score = max(0.0, min(1.0, anomaly_score))

        is_anomaly = anomaly_score >= 0.5 or len(reason_codes) >= 2
        if is_anomaly and "BEHAVIOR_ANOMALY" not in reason_codes:
            reason_codes.append("BEHAVIOR_ANOMALY")

        return anomaly_score, is_anomaly, reason_codes
