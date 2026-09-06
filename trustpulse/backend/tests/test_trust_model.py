"""TRUSTPULSE — TCI calculation, configurable weights and trust-state transitions.

Covers the requirements:
  * TCI = F(I, D, B, N, C, H) with configurable prototype weights
  * TCI is a 0-100 index, clamped, and not a probability
  * trust states TRUSTED/DEGRADED/SUSPICIOUS/CRITICAL/BLOCKED with hysteresis
"""

from __future__ import annotations

from typing import List, Optional

import pytest
from trustpulse_ml.trust_fusion.fusion import (
    FactorScore,
    compute_trend,
    fuse_factors,
    validate_weights,
)

from app.core.trust_config import TrustConfigError, get_trust_config, load_trust_config
from app.schemas.trust import STATE_SEVERITY
from app.services.trust_engine.factors import (
    score_behavior,
    score_device,
    score_history,
    score_identity,
    score_network,
    score_session,
)
from app.services.trust_engine.state_machine import TrustStateMachine


# --------------------------------------------------------------------------- TCI
def all_factors(score: float) -> List[FactorScore]:
    config = get_trust_config()
    return [
        FactorScore(name=name, score=score, weight=config.weights[name])
        for name in ("identity", "device", "behavior", "network", "session", "history")
    ]


def test_default_weights_match_documented_prototype_values():
    weights = get_trust_config().weights
    assert weights == {
        "identity": 0.15,
        "device": 0.20,
        "behavior": 0.30,
        "network": 0.15,
        "session": 0.10,
        "history": 0.10,
    }
    assert abs(sum(weights.values()) - 1.0) < 1e-9


def test_tci_is_weighted_sum_of_the_six_factors():
    factors = [
        FactorScore("identity", 90, 0.15),
        FactorScore("device", 95, 0.20),
        FactorScore("behavior", 100, 0.30),
        FactorScore("network", 95, 0.15),
        FactorScore("session", 90, 0.10),
        FactorScore("history", 75, 0.10),
    ]
    result = fuse_factors(factors, evidence_features=12)
    expected = 90 * 0.15 + 95 * 0.20 + 100 * 0.30 + 95 * 0.15 + 90 * 0.10 + 75 * 0.10
    assert result.tci == pytest.approx(expected, abs=0.01)
    assert result.confidence == "HIGH"


def test_weights_are_configurable_at_fusion_time():
    factors = all_factors(50)
    factors[2].weight = 0.0  # behavior ignored
    factors[0].score = 100  # identity perfect
    equal = fuse_factors(factors, evidence_features=12)

    heavy_identity = dict(get_trust_config().weights)
    heavy_identity["identity"] = 0.9
    heavy_identity["behavior"] = 0.0
    weighted = fuse_factors(factors, weights=heavy_identity, evidence_features=12)

    assert weighted.tci > equal.tci


def test_missing_factor_is_excluded_not_zeroed():
    """A blind spot must not be scored as distrust."""
    config = get_trust_config()
    factors = [
        FactorScore(name="identity", score=90, weight=config.weights["identity"]),
        FactorScore(name="network", score=0, weight=config.weights["network"], available=False),
    ]
    result = fuse_factors(factors, evidence_features=2)
    assert result.tci == pytest.approx(90.0, abs=0.01)
    assert "FACTOR_UNAVAILABLE:network" in result.warnings
    assert result.confidence == "LOW"  # confident about the score, not about the evidence


def test_tci_is_clamped_to_the_zero_to_hundred_scale():
    factors = all_factors(500)
    assert fuse_factors(factors, evidence_features=12).tci == 100.0
    factors = all_factors(-500)
    assert fuse_factors(factors, evidence_features=12).tci == 0.0


def test_unknown_factor_name_is_rejected():
    with pytest.raises(ValueError):
        validate_weights({"identity": 1.0, "vibes": 0.5})


def test_confidence_is_separate_from_the_score():
    factors = all_factors(99)
    assert fuse_factors(factors, evidence_features=1).confidence == "LOW"
    assert fuse_factors(factors, evidence_features=12).confidence == "HIGH"


def test_trend_uses_a_slope_not_a_single_sample():
    assert compute_trend([95, 94, 91, 88, 76]) == "FALLING"
    assert compute_trend([80, 82, 81, 83, 82]) == "STABLE"
    assert compute_trend([40, 55, 70, 85]) == "RISING"
    assert compute_trend([90, 89]) == "INSUFFICIENT_DATA"
    # One jittery sample must not flip the trend.
    assert compute_trend([90, 91, 60, 90, 91]) != "FALLING"


# ------------------------------------------------------------------ env overrides
def test_weights_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.setenv("TCI_WEIGHT_BEHAVIOR", "0.5")
    monkeypatch.setenv("TCI_WEIGHT_HISTORY", "0.05")
    config = load_trust_config()
    assert config.weights["behavior"] == 0.5
    assert config.weights["history"] == 0.05


def test_state_bands_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.setenv("TRUST_STATE_TRUSTED_MIN", "90")
    config = load_trust_config()
    assert config.state_for_tci(88) == "DEGRADED"
    assert config.state_for_tci(92) == "TRUSTED"


def test_action_risk_values_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.setenv("ACTION_RISK_CREATE_API_KEY", "42")
    config = load_trust_config()
    assert config.action_risk("CREATE_API_KEY") == 42


def test_zeroed_weights_are_rejected(monkeypatch):
    monkeypatch.setenv(
        "TRUST_MODEL_OVERRIDES",
        '{"tci": {"weights": {"identity": 0, "device": 0, "behavior": 0,'
        ' "network": 0, "session": 0, "history": 0}}}',
    )
    with pytest.raises(TrustConfigError):
        load_trust_config()


def test_misordered_state_bands_are_rejected(monkeypatch):
    monkeypatch.setenv(
        "TRUST_MODEL_OVERRIDES",
        '{"trust_states": {"bands": [{"state": "TRUSTED", "min": 50},'
        ' {"state": "DEGRADED", "min": 70}, {"state": "BLOCKED", "min": 0}]}}',
    )
    with pytest.raises(TrustConfigError):
        load_trust_config()


def test_state_bands_that_do_not_reach_zero_are_rejected(monkeypatch):
    monkeypatch.setenv(
        "TRUST_MODEL_OVERRIDES",
        '{"trust_states": {"bands": [{"state": "TRUSTED", "min": 80},'
        ' {"state": "BLOCKED", "min": 20}]}}',
    )
    with pytest.raises(TrustConfigError):
        load_trust_config()


def test_out_of_range_action_risk_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "TRUST_MODEL_OVERRIDES", '{"action_risk_profiles": {"EXPORT_DATA": {"risk": 140}}}'
    )
    with pytest.raises(TrustConfigError):
        load_trust_config()


# ------------------------------------------------------------------ trust states
def test_state_bands_reproduce_the_documented_example():
    """96 → 94 → 91 → 88 → 76 → 61 → 43 → 28 from the specification."""
    config = get_trust_config()
    expected = [
        "TRUSTED",
        "TRUSTED",
        "TRUSTED",
        "TRUSTED",
        "DEGRADED",
        "SUSPICIOUS",
        "CRITICAL",
        "BLOCKED",
    ]
    for tci, state in zip([96, 94, 91, 88, 76, 61, 43, 28], expected, strict=True):
        assert config.state_for_tci(tci) == state, f"TCI {tci} should map to {state}"


def test_all_required_states_exist_and_are_ordered():
    bands = {str(band["state"]) for band in get_trust_config().state_bands()}
    assert {"TRUSTED", "DEGRADED", "SUSPICIOUS", "CRITICAL", "BLOCKED"} <= bands
    assert STATE_SEVERITY["TRUSTED"] < STATE_SEVERITY["DEGRADED"] < STATE_SEVERITY["SUSPICIOUS"]
    assert STATE_SEVERITY["SUSPICIOUS"] < STATE_SEVERITY["CRITICAL"] < STATE_SEVERITY["BLOCKED"]
    assert STATE_SEVERITY["CONTAINED"] > STATE_SEVERITY["BLOCKED"]


def run_machine(tci_sequence: List[float], **kwargs) -> List[str]:
    """Feeds a TCI series through the state machine, tracking its own history."""
    machine = TrustStateMachine(get_trust_config())
    states: List[str] = []
    bands: List[str] = []
    current: Optional[str] = "TRUSTED"
    previous_tci: Optional[float] = None
    for tci in tci_sequence:
        transition = machine.next_state(
            current_state=current,
            tci=tci,
            previous_tci=previous_tci,
            recent_raw_bands=bands,
            **kwargs,
        )
        bands.append(transition.raw_band)
        current = transition.state
        previous_tci = tci
        states.append(transition.state)
    return states


def test_small_score_changes_do_not_flip_the_state():
    """Hysteresis: 86 → 84 → 86 → 84 must not oscillate TRUSTED/DEGRADED."""
    states = run_machine([92, 90, 86, 84, 86, 84, 86, 84])
    assert states.count("DEGRADED") <= 2
    assert len(set(states)) <= 2, f"state oscillated: {states}"


def test_escalation_needs_confirmation_or_a_decisive_drop():
    machine = TrustStateMachine(get_trust_config())
    held = machine.next_state(
        current_state="TRUSTED", tci=83, recent_raw_bands=["TRUSTED", "TRUSTED"]
    )
    assert held.state == "TRUSTED"
    assert held.reason == "ESCALATION_HELD_PENDING_CONFIRMATION"
    assert held.hysteresis_applied is True

    confirmed = machine.next_state(
        current_state="TRUSTED", tci=83, recent_raw_bands=["TRUSTED", "DEGRADED"]
    )
    assert confirmed.state == "DEGRADED"
    assert confirmed.changed is True

    # A 35-point single-step collapse is decisive evidence on its own.
    sharp = machine.next_state(
        current_state="TRUSTED", tci=60, previous_tci=95, recent_raw_bands=["TRUSTED"]
    )
    assert sharp.state == "SUSPICIOUS"
    assert sharp.reason == "ESCALATED_ON_SHARP_TCI_DROP"

    # Jumping two or more severity levels at once is decisive on its own.
    multi = machine.next_state(
        current_state="TRUSTED", tci=20, previous_tci=22, recent_raw_bands=["TRUSTED"]
    )
    assert multi.state == "BLOCKED"
    assert multi.reason == "ESCALATED_ON_MULTI_LEVEL_DROP"

    # A single-level move that lands 10+ points below the current state's floor
    # (DEGRADED floor is 70, so 58 qualifies) escalates without waiting.
    low = machine.next_state(
        current_state="DEGRADED", tci=58, previous_tci=62, recent_raw_bands=["DEGRADED"]
    )
    assert low.state == "SUSPICIOUS"
    assert low.reason == "ESCALATED_ON_LOW_SCORE"


def test_small_moves_within_a_band_never_escalate():
    machine = TrustStateMachine(get_trust_config())
    transition = machine.next_state(
        current_state="DEGRADED", tci=78, previous_tci=80, recent_raw_bands=["DEGRADED"]
    )
    assert transition.state == "DEGRADED"
    assert transition.reason == "STABLE_WITHIN_BAND"
    assert transition.changed is False


def test_gradual_takeover_walks_the_states_down():
    series = [95, 94, 91, 88, 84, 80, 76, 72, 68, 63, 58, 52, 45, 38, 32, 28]
    states = run_machine(series)
    assert states[0] == "TRUSTED"
    assert states[-1] in {"CRITICAL", "BLOCKED"}
    severity = [STATE_SEVERITY[state] for state in states]
    # Trust may be held by hysteresis, but it must never improve during a
    # monotonic TCI fall.
    assert all(b >= a for a, b in zip(severity, severity[1:], strict=False)), states
    # The walk must pass through the intermediate states in order.
    visited = [state for i, state in enumerate(states) if i == 0 or state != states[i - 1]]
    assert visited == ["TRUSTED", "DEGRADED", "SUSPICIOUS", "CRITICAL"]


def test_sustained_fall_eventually_reaches_blocked():
    states = run_machine([95, 88, 80, 70, 60, 50, 40, 30, 25, 20, 18])
    assert states[-1] == "BLOCKED"
    assert STATE_SEVERITY[states[-1]] == max(STATE_SEVERITY[s] for s in states)


def test_recovery_is_slow_and_requires_sustained_improvement():
    machine = TrustStateMachine(get_trust_config())
    first = machine.next_state(
        current_state="SUSPICIOUS", tci=88, recent_raw_bands=["SUSPICIOUS", "SUSPICIOUS"]
    )
    assert first.state == "SUSPICIOUS"
    assert first.reason == "RECOVERY_HELD_PENDING_CONFIRMATION"

    recovered = machine.next_state(
        current_state="SUSPICIOUS",
        tci=92,
        recent_raw_bands=["TRUSTED", "TRUSTED", "TRUSTED"],
    )
    assert recovered.state == "TRUSTED"
    assert recovered.reason == "RECOVERED_AFTER_SUSTAINED_IMPROVEMENT"


def test_blocked_and_contained_never_recover_automatically():
    machine = TrustStateMachine(get_trust_config())
    for terminal in ("BLOCKED", "CONTAINED"):
        transition = machine.next_state(
            current_state=terminal,
            tci=99,
            recent_raw_bands=["TRUSTED", "TRUSTED", "TRUSTED", "TRUSTED"],
        )
        assert transition.state == terminal
        assert transition.reason == "NO_AUTO_RECOVERY_FROM_TERMINAL_STATE"


def test_open_incident_blocks_recovery():
    machine = TrustStateMachine(get_trust_config())
    transition = machine.next_state(
        current_state="CRITICAL",
        tci=99,
        recent_raw_bands=["TRUSTED", "TRUSTED", "TRUSTED"],
        open_incident=True,
    )
    assert transition.state == "CRITICAL"
    assert transition.reason == "RECOVERY_BLOCKED_BY_OPEN_INCIDENT"


def test_containment_overrides_the_score():
    machine = TrustStateMachine(get_trust_config())
    transition = machine.next_state(
        current_state="TRUSTED", tci=99, recent_raw_bands=[], is_contained=True
    )
    assert transition.state == "CONTAINED"
    assert transition.reason == "SESSION_CONTAINED"


def test_revocation_blocks_the_session():
    machine = TrustStateMachine(get_trust_config())
    transition = machine.next_state(
        current_state="SUSPICIOUS", tci=55, recent_raw_bands=[], is_revoked=True
    )
    assert transition.state == "BLOCKED"
    assert transition.reason == "SESSION_REVOKED"


# ----------------------------------------------------------------- factor scoring
def test_identity_assurance_rewards_mfa():
    config = get_trust_config()
    plain = score_identity(
        auth_method="PASSWORD", mfa_used=False, session_created_at=None, config=config
    )
    hardened = score_identity(
        auth_method="PASSWORD_MFA", mfa_used=True, session_created_at=None, config=config
    )
    assert hardened.score > plain.score
    assert "MFA_VERIFIED" in hardened.reasons


def test_flagged_device_scores_below_a_new_device():
    class _Device:
        is_flagged = True
        is_registered = True
        observation_count = 50
        trust_level = "FLAGGED"

    class _NewDevice:
        is_flagged = False
        is_registered = False
        observation_count = 0
        trust_level = "NEW"

    config = get_trust_config()
    flagged = score_device(device=_Device(), config=config)
    fresh = score_device(device=_NewDevice(), config=config)
    assert flagged.score < fresh.score
    assert "DEVICE_FLAGGED" in flagged.reasons
    assert "NEW_DEVICE" in fresh.reasons


def test_missing_device_context_is_unavailable_not_zero():
    factor = score_device(device=None, config=get_trust_config())
    assert factor.available is False
    assert factor.score == 0.0
    assert "NO_DEVICE_CONTEXT" in factor.reasons


def test_behavior_cold_start_is_neutral_not_guilty():
    config = get_trust_config()
    cold = score_behavior(
        anomaly_score=None,
        anomaly_reasons=None,
        core_observations=0,
        shadow_observations=0,
        features_compared=0,
        config=config,
    )
    assert cold.available is False
    assert cold.score == config.get("behavior", "cold_start_score")
    assert "COLD_START_NO_BEHAVIORAL_EVIDENCE" in cold.reasons


def test_behavior_score_falls_with_anomaly():
    config = get_trust_config()
    normal = score_behavior(
        anomaly_score=0.02,
        anomaly_reasons=[],
        core_observations=30,
        shadow_observations=10,
        features_compared=12,
        config=config,
    )
    attacker = score_behavior(
        anomaly_score=0.85,
        anomaly_reasons=["BEHAVIOR_DEVIATION"],
        core_observations=30,
        shadow_observations=10,
        features_compared=12,
        config=config,
    )
    assert normal.score > 90
    assert attacker.score < 30


def test_network_change_and_vpn_lower_the_score():
    config = get_trust_config()
    baseline = score_network(
        country="US",
        asn="AS15169",
        is_vpn=False,
        is_proxy_or_tor=False,
        baseline_country="US",
        baseline_asn="AS15169",
        config=config,
    )
    moved = score_network(
        country="RU",
        asn="AS48666",
        is_vpn=True,
        is_proxy_or_tor=False,
        baseline_country="US",
        baseline_asn="AS15169",
        config=config,
    )
    assert baseline.score == 95
    assert moved.score < 25
    assert "NETWORK_CHANGE" in moved.reasons
    assert "VPN_DETECTED" in moved.reasons


def test_session_context_penalizes_prior_suspicion_and_step_up_failures():
    config = get_trust_config()
    clean = score_session(
        status="ACTIVE",
        is_contained=False,
        created_at=None,
        last_seen_at=None,
        last_telemetry_at=None,
        suspicious_event_count=0,
        step_up_failures=0,
        config=config,
    )
    dirty = score_session(
        status="ACTIVE",
        is_contained=False,
        created_at=None,
        last_seen_at=None,
        last_telemetry_at=None,
        suspicious_event_count=3,
        step_up_failures=2,
        config=config,
    )
    assert clean.score > dirty.score
    assert "STEP_UP_FAILURES_IN_SESSION" in dirty.reasons


def test_contained_session_scores_zero_context():
    factor = score_session(
        status="CONTAINED",
        is_contained=True,
        created_at=None,
        last_seen_at=None,
        last_telemetry_at=None,
        suspicious_event_count=0,
        step_up_failures=0,
        config=get_trust_config(),
    )
    assert factor.score == 0.0
    assert "SESSION_CONTAINED" in factor.reasons


def test_history_penalizes_past_incidents():
    config = get_trust_config()
    clean = score_history(
        rolling_tci_values=[95, 94, 96],
        past_incident_count=0,
        step_up_failure_count=0,
        config=config,
    )
    troubled = score_history(
        rolling_tci_values=[40, 35],
        past_incident_count=2,
        step_up_failure_count=1,
        config=config,
    )
    assert clean.score > troubled.score
    assert "PAST_INCIDENTS" in troubled.reasons
    assert "HISTORY_RISK" in troubled.reasons
