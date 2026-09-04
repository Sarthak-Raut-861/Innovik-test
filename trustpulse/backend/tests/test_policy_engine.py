"""
TrustPulse AI — Policy Engine Unit Tests.

The policy engine is the only authoritative decision layer.
"""

import pytest

from app.engines.policy.decision_engine import PolicyDecisionEngine
from app.engines.policy.policy_engine import PolicyEngine
from app.engines.policy.policy_types import SecurityDecisionEnum
from app.schemas.action import ActionRiskLevel


@pytest.mark.parametrize(
    "action_risk,confidence,expected,reasons",
    [
        (ActionRiskLevel.LOW, 0, SecurityDecisionEnum.ALLOW, []),
        (ActionRiskLevel.LOW, 40, SecurityDecisionEnum.ALLOW, []),
        (ActionRiskLevel.LOW, 85, SecurityDecisionEnum.ALLOW, []),
        (ActionRiskLevel.MEDIUM, 30, SecurityDecisionEnum.ALLOW, []),
        (ActionRiskLevel.MEDIUM, 70, SecurityDecisionEnum.ALLOW, []),
        (
            ActionRiskLevel.MEDIUM,
            29,
            SecurityDecisionEnum.STEP_UP,
            ["CONFIDENCE_TOO_LOW_FOR_ACTION"],
        ),
        (
            ActionRiskLevel.MEDIUM,
            0,
            SecurityDecisionEnum.STEP_UP,
            ["CONFIDENCE_TOO_LOW_FOR_ACTION"],
        ),
        (ActionRiskLevel.HIGH, 60, SecurityDecisionEnum.ALLOW, []),
        (ActionRiskLevel.HIGH, 45, SecurityDecisionEnum.STEP_UP, ["CONFIDENCE_TOO_LOW_FOR_ACTION"]),
        (ActionRiskLevel.HIGH, 29, SecurityDecisionEnum.BLOCK, ["CONFIDENCE_TOO_LOW_FOR_ACTION"]),
        (ActionRiskLevel.CRITICAL, 80, SecurityDecisionEnum.ALLOW, []),
        (
            ActionRiskLevel.CRITICAL,
            60,
            SecurityDecisionEnum.STEP_UP,
            ["CONFIDENCE_TOO_LOW_FOR_ACTION"],
        ),
        (
            ActionRiskLevel.CRITICAL,
            30,
            SecurityDecisionEnum.BLOCK,
            ["CONFIDENCE_TOO_LOW_FOR_ACTION"],
        ),
        (
            ActionRiskLevel.CRITICAL,
            0,
            SecurityDecisionEnum.BLOCK,
            ["CONFIDENCE_TOO_LOW_FOR_ACTION"],
        ),
    ],
)
def test_policy_decision_matrix(action_risk, confidence, expected, reasons):
    decision, reason_codes = PolicyDecisionEngine.decide(
        session_confidence=confidence,
        action_risk=action_risk,
        reason_codes=[],
    )
    assert decision == expected


def test_open_incident_forces_isolate():
    for risk in ActionRiskLevel:
        for conf in (0, 40, 80, 100):
            decision, reasons = PolicyDecisionEngine.decide(
                session_confidence=conf,
                action_risk=risk,
                reason_codes=[],
                open_incident=True,
            )
            assert decision == SecurityDecisionEnum.ISOLATE
            assert "ACTIVE_SECURITY_INCIDENT" in reasons


def test_isolate_requires_multiple_independent_signals():
    decision, _ = PolicyDecisionEngine.decide(
        session_confidence=0,
        action_risk=ActionRiskLevel.CRITICAL,
        reason_codes=["BEHAVIOR_ANOMALY", "NEW_DEVICE"],
    )
    assert decision == SecurityDecisionEnum.ISOLATE


def test_missing_evidence_is_not_isolate():
    """Missing observations alone must not be treated as malicious."""
    decision, reasons = PolicyDecisionEngine.decide(
        session_confidence=0,
        action_risk=ActionRiskLevel.CRITICAL,
        reason_codes=["COLD_START_NO_BASELINE"],
    )
    assert decision == SecurityDecisionEnum.BLOCK


def test_policy_engine_is_deterministic():
    inputs = {
        "session_confidence": 55,
        "action_risk": ActionRiskLevel.HIGH,
        "reason_codes": ["BEHAVIOR_ANOMALY"],
    }
    d1 = PolicyEngine.decide(**inputs)
    d2 = PolicyEngine.decide(**inputs)
    assert d1 == d2


def test_policy_returns_rule_id():
    _, rule_id, _ = PolicyEngine.decide(
        session_confidence=40,
        action_risk=ActionRiskLevel.MEDIUM,
        reason_codes=[],
    )
    assert rule_id in ("medium-step-up", "medium-allow")
