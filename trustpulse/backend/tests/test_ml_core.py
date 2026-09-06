"""TRUSTPULSE — ML core: privacy guard, anomaly detection, baseline poisoning.

Covers the project privacy rules and the Trusted Core / Adaptive Shadow model.
"""

from __future__ import annotations

import pytest
from trustpulse_ml.anomaly_detection.detector import (
    IsolationForestAnomalyDetector,
    StatisticalAnomalyDetector,
    describe_deviation,
    fuse_results,
)
from trustpulse_ml.baseline.adaptive_shadow import AdaptiveShadow
from trustpulse_ml.baseline.trusted_core import Baseline, TrustedCore, baseline_distance
from trustpulse_ml.evaluation.metrics import (
    confusion_matrix,
    evaluate_predictions,
    threshold_sweep,
)
from trustpulse_ml.feature_extraction.features import (
    RawDataRejectedError,
    assert_no_raw_data,
    describe,
    extract_feature_vector,
    feature_names,
    initial_std,
    inverse_transform,
    to_array,
    transform,
)

NORMAL_SDK_PAYLOAD = {
    "typing": {
        "meanDwellTime": 112.0,
        "dwellStdDev": 24.0,
        "meanFlightTime": 88.0,
        "flightStdDev": 31.0,
        "typingSpeed": 6.1,
        "pauseRate": 0.12,
    },
    "mouse": {
        "meanVelocity": 820.0,
        "velocityStdDev": 260.0,
        "meanAcceleration": 2100.0,
        "directionChangeRate": 3.4,
        "totalDistance": 18400.0,
        "movementDuration": 4200.0,
        "meanPauseTime": 340.0,
    },
    "click": {
        "clickCount": 18,
        "meanInterval": 940.0,
        "intervalStdDev": 310.0,
        "clickFrequency": 1.1,
    },
    "scroll": {
        "meanVelocity": 1500.0,
        "totalDistance": 9200.0,
        "meanPauseDuration": 620.0,
        "eventRate": 6.2,
    },
}

ATTACKER_SDK_PAYLOAD = {
    "typing": {
        "meanDwellTime": 380.0,
        "dwellStdDev": 12.0,
        "meanFlightTime": 300.0,
        "flightStdDev": 9.0,
        "typingSpeed": 2.1,
        "pauseRate": 0.02,
    },
    "mouse": {
        "meanVelocity": 9000.0,
        "velocityStdDev": 60.0,
        "meanAcceleration": 41000.0,
        "directionChangeRate": 0.4,
        "totalDistance": 92000.0,
        "movementDuration": 900.0,
        "meanPauseTime": 40.0,
    },
    "click": {
        "clickCount": 64,
        "meanInterval": 155.0,
        "intervalStdDev": 12.0,
        "clickFrequency": 6.4,
    },
    "scroll": {
        "meanVelocity": 18000.0,
        "totalDistance": 240000.0,
        "meanPauseDuration": 30.0,
        "eventRate": 42.0,
    },
}


def build_core(payload: dict, observations: int = 8, noise: float = 0.0) -> Baseline:
    learner = TrustedCore()
    baseline = Baseline()
    vector = extract_feature_vector(payload)
    for index in range(observations):
        jittered = {k: v * (1 + (0.01 * index if noise else 0)) for k, v in vector.items()}
        baseline = learner.update(baseline, transform(jittered))
    return baseline


# ---------------------------------------------------------------- privacy guards
@pytest.mark.parametrize(
    "payload",
    [
        {"typing": {"characters": "hunter2"}},
        {"typing": {"keyValue": "a"}},
        {"typing": {"keystrokes": [1, 2, 3]}},
        {"typing": {"password": "secret"}},
        {"typing": {"inputValue": "card number 4111"}},
        {"typing": {"meanDwellTime": 110.0, "text": "typed sentence"}},
        {"nested": {"deep": {"clipboard": "copied"}}},
    ],
)
def test_raw_data_is_rejected(payload):
    with pytest.raises(RawDataRejectedError):
        extract_feature_vector(payload)


def test_short_identifier_strings_are_still_allowed():
    """Device ids / enum labels must not break telemetry ingestion."""
    assert_no_raw_data({"deviceFingerprint": "dev-alice-work-macbook-a1b2c3"})
    assert_no_raw_data({"eventType": "behavioral_batch"})


def test_only_derived_numeric_features_are_accepted():
    vector = extract_feature_vector(NORMAL_SDK_PAYLOAD)
    assert vector["typing_dwell"] == 112.0
    assert vector["mouse_velocity"] == 820.0
    assert set(vector).issubset(set(feature_names()) | {"click_count"})


def test_non_finite_and_out_of_range_values_are_sanitized():
    vector = extract_feature_vector(
        {
            "typing": {"meanDwellTime": float("nan"), "meanFlightTime": 999_999.0},
            "mouse": {"meanVelocity": -50.0},
        }
    )
    assert "typing_dwell" not in vector  # NaN dropped
    assert vector["typing_flight"] == 5000.0  # clamped to the schema maximum
    assert vector["mouse_velocity"] == 0.0  # clamped to the schema minimum


def test_feature_schema_is_documented_without_raw_data():
    metadata = describe(["typing_dwell", "mouse_velocity"])
    assert {item["name"] for item in metadata} == {"typing_dwell", "mouse_velocity"}
    assert metadata[0]["unit"] in {"ms", "px/s"}


def test_log_transform_is_reversible():
    vector = {"typing_dwell": 112.0, "typing_pause_rate": 0.12}
    forward = transform(vector)
    assert forward["typing_dwell"] != 112.0
    assert forward["typing_pause_rate"] == pytest.approx(0.12)
    backward = inverse_transform(forward)
    assert backward["typing_dwell"] == pytest.approx(112.0, abs=1e-6)


def test_to_array_marks_missing_features_as_nan():
    array = to_array({"typing_dwell": 1.0}, ["typing_dwell", "typing_flight"])
    assert array[0] == 1.0
    assert array[1] != array[1]  # NaN


def test_std_prior_is_reasonable_in_transformed_space():
    """A 15% raw variation prior must not become a huge log-space prior.

    Naively taking 15% of the *transformed* value would give std ~= 0.7 for a
    112 ms dwell time, which is wide enough to hide a 4x attacker deviation.
    """
    log_std = initial_std("typing_dwell", transform({"typing_dwell": 112.0})["typing_dwell"])
    assert 0.05 < log_std < 0.3
    # ln(1 + 112 * 0.15) - ln(1 + 112) ~= 0.139
    assert log_std == pytest.approx(0.139, abs=0.01)
    # Linear features keep a plain relative prior.
    assert initial_std("typing_pause_rate", 0.12) == pytest.approx(0.12 * 0.15)


# -------------------------------------------------------------- anomaly detection
def test_matching_behavior_scores_as_normal():
    core = build_core(NORMAL_SDK_PAYLOAD)
    result = StatisticalAnomalyDetector().evaluate(extract_feature_vector(NORMAL_SDK_PAYLOAD), core)
    assert result.anomaly_score < 0.05
    assert result.is_anomaly is False


def test_takeover_behavior_is_flagged_with_evidence():
    core = build_core(NORMAL_SDK_PAYLOAD)
    result = StatisticalAnomalyDetector().evaluate(
        extract_feature_vector(ATTACKER_SDK_PAYLOAD), core
    )
    assert result.anomaly_score > 0.6
    assert result.is_anomaly is True
    assert "BEHAVIOR_DEVIATION" in result.reasons
    assert any("TYPING_DWELL_DEVIATION" == code for code in result.reasons)
    assert any("MOUSE_VELOCITY_DEVIATION" == code for code in result.reasons)


def test_cold_start_is_no_evidence_not_guilt():
    result = StatisticalAnomalyDetector().evaluate(
        extract_feature_vector(ATTACKER_SDK_PAYLOAD), None
    )
    assert result.anomaly_score == 0.0
    assert result.is_anomaly is False
    assert result.reasons == ["COLD_START_NO_BASELINE"]


def test_empty_baseline_is_treated_as_cold_start():
    result = StatisticalAnomalyDetector().evaluate(
        extract_feature_vector(NORMAL_SDK_PAYLOAD), Baseline()
    )
    assert result.method == "none"
    assert result.anomaly_score == 0.0


def test_deviation_description_uses_raw_units():
    core = build_core(NORMAL_SDK_PAYLOAD)
    result = StatisticalAnomalyDetector().evaluate(
        extract_feature_vector(ATTACKER_SDK_PAYLOAD), core
    )
    assert result.deviations, "expected per-feature deviations"
    for deviation in result.deviations[:3]:
        text = describe_deviation(deviation)
        name = deviation["feature"]
        assert name in text
        raw = inverse_transform({name: float(deviation["observed"])})[name]
        # The raw observation must appear, never its log transform.
        assert f"{raw:.1f}" in text, (text, raw)


def test_isolation_forest_degrades_to_no_evidence_when_undertrained():
    detector = IsolationForestAnomalyDetector(min_samples=30)
    assert detector.is_fitted is False
    assert detector.fit([{"typing_dwell": 100.0}] * 5) is False
    assert detector.evaluate({"typing_dwell": 400.0}) is None


def test_isolation_forest_contributes_evidence_when_fitted():
    import random

    rng = random.Random(7)
    history = [
        {
            "typing_dwell": 112.0 * (1 + rng.uniform(-0.08, 0.08)),
            "mouse_velocity": 820.0 * (1 + rng.uniform(-0.08, 0.08)),
            "click_interval": 940.0 * (1 + rng.uniform(-0.08, 0.08)),
        }
        for _ in range(60)
    ]
    detector = IsolationForestAnomalyDetector(min_samples=30)
    assert detector.fit(history) is True
    result = detector.evaluate(
        {"typing_dwell": 380.0, "mouse_velocity": 9000.0, "click_interval": 155.0}
    )
    assert result is not None
    assert result.anomaly_score > 0.5


def test_fusing_detectors_ignores_unavailable_models():
    statistical = StatisticalAnomalyDetector().evaluate(
        extract_feature_vector(ATTACKER_SDK_PAYLOAD), build_core(NORMAL_SDK_PAYLOAD)
    )
    fused = fuse_results([statistical, None])
    assert fused.anomaly_score == pytest.approx(statistical.anomaly_score)
    empty = fuse_results([None, None])
    assert empty.anomaly_score == 0.0
    assert empty.reasons == ["NO_DETECTOR_EVIDENCE"]


# ------------------------------------------------------- baselines and poisoning
def test_trusted_core_moves_slowly():
    learner = TrustedCore(alpha=0.05)
    baseline = build_core(NORMAL_SDK_PAYLOAD, observations=10)
    before = baseline.means["typing_dwell"]
    shifted = transform({"typing_dwell": 400.0})
    after = learner.update(baseline, shifted).means["typing_dwell"]
    assert after < before + 0.2 * abs(shifted["typing_dwell"] - before)


def test_shadow_never_learns_from_a_suspicious_session():
    shadow = AdaptiveShadow()
    baseline = Baseline()
    observation = transform(extract_feature_vector(ATTACKER_SDK_PAYLOAD))
    for state in ("SUSPICIOUS", "CRITICAL", "BLOCKED", "CONTAINED"):
        updated, learned = shadow.update(baseline, observation, state)
        assert learned is False
        assert updated.observation_count == 0
        assert updated.rejected_observations == 1
        assert updated.means == {}


def test_shadow_never_learns_during_an_open_incident():
    shadow = AdaptiveShadow()
    updated, learned = shadow.update(
        Baseline(), transform(extract_feature_vector(NORMAL_SDK_PAYLOAD)), "TRUSTED", True
    )
    assert learned is False
    assert updated.rejected_observations == 1


def test_shadow_learns_from_a_trusted_session():
    shadow = AdaptiveShadow()
    updated, learned = shadow.update(
        Baseline(), transform(extract_feature_vector(NORMAL_SDK_PAYLOAD)), "TRUSTED", False
    )
    assert learned is True
    assert updated.observation_count == 1
    assert "typing_dwell" in updated.means


def _grow_shadow(shadow: AdaptiveShadow, payload: dict, state: str, count: int) -> Baseline:
    baseline = Baseline()
    vector = transform(extract_feature_vector(payload))
    for _ in range(count):
        baseline, _ = shadow.update(baseline, vector, state)
    return baseline


def test_promotion_is_blocked_for_an_untrusted_session():
    shadow = AdaptiveShadow(min_observations=8)
    core = build_core(NORMAL_SDK_PAYLOAD)
    drifted = _grow_shadow(shadow, NORMAL_SDK_PAYLOAD, "TRUSTED", 10)
    decision = shadow.promotion_decision(core, drifted, "CRITICAL", open_incident=True)
    assert decision.promote is False
    assert "SESSION_NOT_TRUSTWORTHY" in decision.reasons
    assert "OPEN_INCIDENT" in decision.reasons


def test_promotion_is_blocked_without_enough_observations():
    shadow = AdaptiveShadow(min_observations=8)
    core = build_core(NORMAL_SDK_PAYLOAD)
    young = _grow_shadow(shadow, NORMAL_SDK_PAYLOAD, "TRUSTED", 3)
    decision = shadow.promotion_decision(core, young, "TRUSTED")
    assert decision.promote is False
    assert "SHADOW_INSUFFICIENT_OBSERVATIONS" in decision.reasons


def test_promotion_is_blocked_when_drift_is_too_large():
    """Baseline poisoning protection: an attacker-shaped shadow cannot be promoted."""
    shadow = AdaptiveShadow(min_observations=8, max_promotion_distance=1.2)
    core = build_core(NORMAL_SDK_PAYLOAD)
    poisoned = _grow_shadow(shadow, ATTACKER_SDK_PAYLOAD, "TRUSTED", 12)
    decision = shadow.promotion_decision(core, poisoned, "TRUSTED")
    assert decision.promote is False
    assert "DRIFT_TOO_LARGE_QUARANTINED" in decision.reasons

    promoted_core, _ = shadow.promote(core, poisoned, "TRUSTED")
    assert promoted_core.means["typing_dwell"] == pytest.approx(core.means["typing_dwell"])


def test_gradual_legitimate_drift_is_promoted():
    shadow = AdaptiveShadow(min_observations=8, max_promotion_distance=1.2)
    core = build_core(NORMAL_SDK_PAYLOAD)
    slightly_slower = dict(NORMAL_SDK_PAYLOAD)
    slightly_slower["typing"] = {**NORMAL_SDK_PAYLOAD["typing"], "meanDwellTime": 118.0}
    drifted = _grow_shadow(shadow, slightly_slower, "TRUSTED", 12)

    decision = shadow.promotion_decision(core, drifted, "TRUSTED")
    assert decision.promote is True, decision.reasons

    promoted, applied = shadow.promote(core, drifted, "TRUSTED", blend_alpha=0.1)
    assert applied.promote is True
    assert promoted.version == core.version + 1
    assert promoted.means["typing_dwell"] > core.means["typing_dwell"]


def test_baseline_distance_is_infinite_when_incomparable():
    left = Baseline(means={"typing_dwell": 1.0}, observation_count=1)
    right = Baseline(means={"mouse_velocity": 1.0}, observation_count=1)
    assert baseline_distance(left, right) == float("inf")
    assert baseline_distance(left, left) == 0.0


def test_rejected_observations_are_counted_not_learned():
    learner = TrustedCore()
    baseline = Baseline(means={"typing_dwell": 1.0}, observation_count=5)
    rejected = learner.record_rejection(baseline)
    assert rejected.rejected_observations == 1
    assert rejected.observation_count == 5
    assert rejected.means == baseline.means


# ------------------------------------------------------------------- evaluation
def test_evaluation_metrics_are_computed_correctly():
    rows = [
        {"label": "benign", "tci": 95},
        {"label": "benign", "tci": 40, "detection_latency_ms": 100},  # false positive
        {"label": "compromised", "tci": 30, "detection_latency_ms": 200},
        {"label": "compromised", "tci": 80},  # false negative
    ]
    report = evaluate_predictions(rows, flag_threshold=50)
    assert (report.true_positives, report.false_positives) == (1, 1)
    assert (report.true_negatives, report.false_negatives) == (1, 1)
    assert report.precision == pytest.approx(0.5)
    assert report.recall == pytest.approx(0.5)
    assert report.false_positive_rate == pytest.approx(0.5)
    assert report.mean_detection_latency_ms == pytest.approx(150)
    assert confusion_matrix(report) == ((1, 1), (1, 1))


def test_threshold_sweep_returns_one_row_per_threshold():
    rows = [{"label": "compromised", "tci": 30}, {"label": "benign", "tci": 90}]
    table = threshold_sweep(rows, [20, 50, 80])
    assert [row["threshold"] for row in table] == [20.0, 50.0, 80.0]
    assert table[0]["recall"] == 0.0
    assert table[2]["recall"] == 1.0
