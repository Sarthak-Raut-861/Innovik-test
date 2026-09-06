"""Behavioral anomaly detection — evidence only.

Two detectors are provided:

* :class:`StatisticalAnomalyDetector` — transparent robust z-score (MAD-aware),
  diagonal Mahalanobis-style distance and cosine similarity. Explainable, always
  available, no training required.
* :class:`IsolationForestAnomalyDetector` — optional scikit-learn ensemble fitted
  on historical trusted observations. Returns ``None`` when there is not enough
  history, so it degrades to "no evidence" rather than to a guess.

Neither detector returns a decision. Both return an anomaly score in ``[0, 1]``
plus per-feature explanations that the trust engine turns into evidence records.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

import numpy as np
from trustpulse_ml.baseline.trusted_core import Baseline
from trustpulse_ml.feature_extraction.features import get_spec, transform

# Per-feature explanation codes used by the evidence engine.
FEATURE_EVIDENCE_CODES: Dict[str, str] = {
    "typing_dwell": "TYPING_DWELL_DEVIATION",
    "typing_dwell_std": "TYPING_DWELL_VARIANCE_DEVIATION",
    "typing_flight": "TYPING_FLIGHT_DEVIATION",
    "typing_flight_std": "TYPING_FLIGHT_VARIANCE_DEVIATION",
    "typing_speed": "TYPING_SPEED_DEVIATION",
    "typing_pause_rate": "TYPING_PAUSE_DEVIATION",
    "mouse_velocity": "MOUSE_VELOCITY_DEVIATION",
    "mouse_velocity_std": "MOUSE_VELOCITY_VARIANCE_DEVIATION",
    "mouse_acceleration": "MOUSE_ACCELERATION_DEVIATION",
    "mouse_direction_change_rate": "MOUSE_TRAJECTORY_DEVIATION",
    "mouse_distance": "MOUSE_DISTANCE_DEVIATION",
    "mouse_pause_duration": "MOUSE_PAUSE_DEVIATION",
    "click_interval": "CLICK_CADENCE_DEVIATION",
    "click_interval_std": "CLICK_CADENCE_VARIANCE_DEVIATION",
    "click_frequency": "CLICK_FREQUENCY_DEVIATION",
    "scroll_velocity": "SCROLL_VELOCITY_DEVIATION",
    "scroll_pause_duration": "SCROLL_PAUSE_DEVIATION",
}

Z_ANOMALY_THRESHOLD = 2.5
MIN_STD = 0.05


@dataclass
class AnomalyResult:
    """Evidence bundle produced by a detector."""

    anomaly_score: float  # 0.0 normal .. 1.0 strongly anomalous
    is_anomaly: bool
    reasons: List[str] = field(default_factory=list)
    deviations: List[Dict[str, float]] = field(default_factory=list)
    features_compared: int = 0
    method: str = "statistical"

    def to_dict(self) -> Dict[str, object]:
        return {
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomaly": self.is_anomaly,
            "reasons": list(self.reasons),
            "deviations": [
                {k: (round(v, 4) if isinstance(v, float) else v) for k, v in item.items()}
                for item in self.deviations
            ],
            "features_compared": self.features_compared,
            "method": self.method,
        }


COLD_START_RESULT = AnomalyResult(
    anomaly_score=0.0,
    is_anomaly=False,
    reasons=["COLD_START_NO_BASELINE"],
    method="none",
)


class StatisticalAnomalyDetector:
    """Robust z-score + Mahalanobis-style distance + cosine similarity."""

    def __init__(
        self,
        z_threshold: float = Z_ANOMALY_THRESHOLD,
        z_weight: float = 0.7,
        cosine_weight: float = 0.3,
        max_z: float = 3.0,
    ) -> None:
        self.z_threshold = float(z_threshold)
        self.z_weight = float(z_weight)
        self.cosine_weight = float(cosine_weight)
        self.max_z = float(max_z)

    def evaluate(
        self,
        observation: Dict[str, float],
        baseline: Optional[Baseline],
    ) -> AnomalyResult:
        if baseline is None or baseline.is_empty():
            return AnomalyResult(
                anomaly_score=0.0,
                is_anomaly=False,
                reasons=["COLD_START_NO_BASELINE"],
                method="none",
            )

        observed = transform(observation)
        if not observed:
            return AnomalyResult(
                anomaly_score=0.0,
                is_anomaly=False,
                reasons=["NO_INTERACTION_FEATURES"],
                method="none",
            )

        shared = sorted(set(observed) & set(baseline.means))
        if not shared:
            return AnomalyResult(
                anomaly_score=0.0,
                is_anomaly=False,
                reasons=["NO_SHARED_FEATURES"],
                method="none",
            )

        z_scores: List[float] = []
        deviations: List[Dict[str, float]] = []
        reasons: List[str] = []

        for name in shared:
            mean = baseline.means[name]
            std = max(baseline.stds.get(name, MIN_STD), MIN_STD)
            z = (observed[name] - mean) / std
            z_scores.append(abs(z))
            deviations.append(
                {
                    "feature": name,
                    "observed": observed[name],
                    "baseline_mean": mean,
                    "baseline_std": std,
                    "z": z,
                }
            )
            if abs(z) >= self.z_threshold:
                code = FEATURE_EVIDENCE_CODES.get(name)
                if code and code not in reasons:
                    reasons.append(code)

        mean_abs_z = float(np.mean(np.abs(z_scores)))
        # Diagonal Mahalanobis-style distance normalized by feature count.
        mahalanobis = math.sqrt(float(np.mean(np.square(z_scores))))
        z_component = min(1.0, max(mean_abs_z, mahalanobis) / self.max_z)
        cosine_component = 1.0 - _cosine(
            [observed[n] for n in shared], [baseline.means[n] for n in shared]
        )

        anomaly_score = min(
            1.0, max(0.0, self.z_weight * z_component + self.cosine_weight * cosine_component)
        )
        deviations.sort(key=lambda item: abs(item["z"]), reverse=True)

        is_anomaly = anomaly_score >= 0.5 or len(reasons) >= 2
        if is_anomaly and "BEHAVIOR_DEVIATION" not in reasons:
            reasons.insert(0, "BEHAVIOR_DEVIATION")

        return AnomalyResult(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            reasons=reasons,
            deviations=deviations[:8],
            features_compared=len(shared),
            method="statistical",
        )


class IsolationForestAnomalyDetector:
    """Optional scikit-learn ensemble. Degrades to "no evidence" when unfitted."""

    def __init__(self, min_samples: int = 30, contamination: float = 0.05) -> None:
        self.min_samples = int(min_samples)
        self.contamination = float(contamination)
        self.feature_names_: List[str] = []
        self._model = None

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    def fit(self, history: Sequence[Dict[str, float]]) -> bool:
        """Fit on trusted historical observations. Returns False if under-trained."""
        self._model = None
        if len(history) < self.min_samples:
            return False
        names = sorted({k for row in history for k in row.keys()})
        if not names:
            return False

        matrix: List[List[float]] = []
        for row in history:
            vector = transform(row)
            matrix.append([vector.get(name, 0.0) for name in names])

        try:
            from sklearn.ensemble import IsolationForest
        except Exception:  # pragma: no cover - sklearn is a declared dependency
            return False

        model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=1337,
        )
        model.fit(np.asarray(matrix, dtype=float))
        self.feature_names_ = names
        self._model = model
        return True

    def evaluate(self, observation: Dict[str, float]) -> Optional[AnomalyResult]:
        if not self.is_fitted:
            return None
        vector = transform(observation)
        row = [[vector.get(name, 0.0) for name in self.feature_names_]]
        raw = float(self._model.decision_function(np.asarray(row, dtype=float))[0])
        # decision_function: negative = anomalous. Map roughly [-0.3, 0.3] -> [1, 0].
        score = min(1.0, max(0.0, 0.5 - raw / 0.6))
        return AnomalyResult(
            anomaly_score=score,
            is_anomaly=bool(self._model.predict(np.asarray(row, dtype=float))[0] == -1),
            reasons=["ISOLATION_FOREST_ANOMALY"] if score >= 0.6 else [],
            features_compared=len(self.feature_names_),
            method="isolation_forest",
        )


def fuse_results(
    results: Sequence[Optional[AnomalyResult]],
    weights: Optional[Sequence[float]] = None,
) -> AnomalyResult:
    """Weighted fusion of several detectors. ``None`` results are ignored.

    A model contributes evidence; it never gets veto power. If every detector is
    unavailable the fused result is "no evidence", never "anomalous".
    """
    usable = [r for r in results if r is not None]
    if not usable:
        return AnomalyResult(
            anomaly_score=0.0, is_anomaly=False, reasons=["NO_DETECTOR_EVIDENCE"], method="none"
        )
    if weights is None:
        weights = [1.0] * len(usable)
    total_weight = float(sum(weights)) or 1.0
    score = sum(r.anomaly_score * w for r, w in zip(usable, weights, strict=False)) / total_weight

    reasons: List[str] = []
    deviations: List[Dict[str, float]] = []
    for result in usable:
        for reason in result.reasons:
            if reason not in reasons:
                reasons.append(reason)
        deviations.extend(result.deviations)
    deviations.sort(key=lambda item: abs(item.get("z", 0.0)), reverse=True)

    return AnomalyResult(
        anomaly_score=min(1.0, max(0.0, score)),
        is_anomaly=any(r.is_anomaly for r in usable),
        reasons=reasons,
        deviations=deviations[:8],
        features_compared=max(r.features_compared for r in usable),
        method="+".join(r.method for r in usable),
    )


def describe_deviation(deviation: Dict[str, float]) -> str:
    """Human-readable evidence description for one feature deviation.

    Both sides are converted back to raw units so the message never mixes a raw
    observation with a log-transformed baseline mean.
    """
    name = str(deviation["feature"])
    spec = get_spec(name)
    log_scaled = bool(spec and spec.log_scale)
    observed = float(deviation["observed"])
    baseline_mean = float(deviation["baseline_mean"])
    if log_scaled:
        observed = math.expm1(observed)
        baseline_mean = math.expm1(baseline_mean)
    z = deviation.get("z", 0.0)
    direction = "higher/faster" if z > 0 else "lower/slower"
    return (
        f"{name} is {abs(z):.1f} sigma {direction} than the trusted baseline "
        f"(observed {observed:.1f} vs baseline {baseline_mean:.1f})"
    )


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    va = np.asarray(a, dtype=float)
    vb = np.asarray(b, dtype=float)
    norm_a = float(np.linalg.norm(va))
    norm_b = float(np.linalg.norm(vb))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return float(np.dot(va, vb) / (norm_a * norm_b))


__all__ = [
    "COLD_START_RESULT",
    "FEATURE_EVIDENCE_CODES",
    "AnomalyResult",
    "IsolationForestAnomalyDetector",
    "StatisticalAnomalyDetector",
    "describe_deviation",
    "fuse_results",
]
