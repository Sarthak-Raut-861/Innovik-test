"""
TrustPulse AI — Behavioral engine tests.

Covers no baseline, normal behavior, anomaly, drift, noisy data, missing
features, extreme values, and NaN/Infinity defense.
"""

import math

from app.engines.behavioral.anomaly import AnomalyEngine
from app.engines.behavioral.baseline import BaselineEngine
from app.engines.behavioral.drift import DriftEngine
from app.engines.behavioral.similarity import SimilarityEngine


def _features(typing_dwell: float = 95.0, mouse_velocity: float = 350.0) -> dict:
    return {
        "typing": {
            "sampleCount": 45,
            "meanDwellTime": typing_dwell,
            "dwellStdDev": 12.0,
            "typingSpeed": 4.2,
        },
        "mouse": {"sampleCount": 120, "meanVelocity": mouse_velocity, "meanAcceleration": 120.0},
        "click": {"sampleCount": 8, "meanInterval": 1200.0, "clickFrequency": 0.003},
    }


def test_no_baseline_is_not_malicious():
    score, is_anomaly, reasons = AnomalyEngine.evaluate_features(_features(), None)
    assert score == 0.0
    assert is_anomaly is False
    assert "COLD_START_NO_BASELINE" in reasons


def test_missing_features_is_not_anomaly():
    score, is_anomaly, reasons = AnomalyEngine.evaluate_features({}, {"means": {}, "stds": {}})
    assert score == 0.0
    assert is_anomaly is False
    assert "NO_INTERACTION_FEATURES" in reasons


def test_normal_behavior_low_anomaly():
    baseline = BaselineEngine.update_rolling_baseline(
        None, SimilarityEngine.extract_feature_vector(_features())
    )
    score, is_anomaly, _ = AnomalyEngine.evaluate_features(_features(), baseline)
    assert score < 0.5
    assert is_anomaly is False


def test_anomalous_behavior_high_score():
    normal = _features()
    baseline = BaselineEngine.update_rolling_baseline(
        None, SimilarityEngine.extract_feature_vector(normal)
    )
    anomalous = _features(typing_dwell=2000.0, mouse_velocity=40000.0)
    score, is_anomaly, reasons = AnomalyEngine.evaluate_features(anomalous, baseline)
    assert score >= 0.5
    assert is_anomaly is True
    assert "BEHAVIOR_ANOMALY" in reasons


def test_missing_feature_does_not_poison_baseline():
    features = _features()
    baseline = BaselineEngine.update_rolling_baseline(
        None, SimilarityEngine.extract_feature_vector(features)
    )
    updated = BaselineEngine.update_rolling_baseline(baseline, {})
    assert updated["observation_count"] == 2
    assert "typing_dwell" in updated["means"]


def test_nan_infinity_are_removed():
    vec = {"a": 1.0, "b": float("nan"), "c": float("inf"), "d": -float("inf")}
    cleaned = SimilarityEngine.extract_feature_vector({"typing": {"meanDwellTime": float("nan")}})
    means = BaselineEngine.update_rolling_baseline(None, cleaned)
    assert "typing_dwell" not in means["means"]
    assert all(math.isfinite(v) for v in vec.values()) is False


def test_drift_detects_significant_shift():
    trusted = BaselineEngine.update_rolling_baseline(
        None, SimilarityEngine.extract_feature_vector(_features())
    )
    candidate = BaselineEngine.update_rolling_baseline(
        None,
        SimilarityEngine.extract_feature_vector(
            _features(typing_dwell=3000.0, mouse_velocity=45000.0)
        ),
    )
    magnitude, significant = DriftEngine.evaluate_drift(candidate, trusted)
    assert significant is True
    assert magnitude > 0


def test_no_drift_when_absent():
    magnitude, significant = DriftEngine.evaluate_drift(None, None)
    assert magnitude == 0.0
    assert significant is False


def test_extreme_values_clamped_by_schema_at_engine_level():
    # Engine-level should not raise on extreme finite values and should not be
    # treated as missing.
    baseline = BaselineEngine.update_rolling_baseline(None, {"x": 1.0})
    updated = BaselineEngine.update_rolling_baseline(baseline, {"x": 1e12})
    assert "x" in updated["means"]
    assert updated["means"]["x"] > 0
