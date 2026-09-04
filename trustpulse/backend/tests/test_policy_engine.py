"""
TrustPulse AI - Policy Engine Unit Tests
"""

import pytest
from app.engines.policy.decision_engine import PolicyDecisionEngine
from app.engines.policy.policy_types import SecurityDecisionEnum
from app.schemas.action import ActionRiskLevel


@pytest.mark.parametrize("action_risk,confidence,expected_decision", [
    # LOW risk → always ALLOW regardless of confidence
    (ActionRiskLevel.LOW, 0,  SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.LOW, 40, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.LOW, 85, SecurityDecisionEnum.ALLOW),
    # MEDIUM risk: ALLOW if >= 30, STEP_UP otherwise
    (ActionRiskLevel.MEDIUM, 30, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.MEDIUM, 70, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.MEDIUM, 29, SecurityDecisionEnum.STEP_UP),
    (ActionRiskLevel.MEDIUM, 0,  SecurityDecisionEnum.STEP_UP),
    # HIGH risk: ALLOW if >= 60, STEP_UP if >= 30, BLOCK below
    (ActionRiskLevel.HIGH, 60, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.HIGH, 85, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.HIGH, 45, SecurityDecisionEnum.STEP_UP),
    (ActionRiskLevel.HIGH, 30, SecurityDecisionEnum.STEP_UP),
    (ActionRiskLevel.HIGH, 29, SecurityDecisionEnum.BLOCK),
    (ActionRiskLevel.HIGH, 0,  SecurityDecisionEnum.BLOCK),
    # CRITICAL risk: ALLOW >= 80, STEP_UP >= 60, BLOCK >= 30, ISOLATE below
    (ActionRiskLevel.CRITICAL, 80, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.CRITICAL, 90, SecurityDecisionEnum.ALLOW),
    (ActionRiskLevel.CRITICAL, 60, SecurityDecisionEnum.STEP_UP),
    (ActionRiskLevel.CRITICAL, 79, SecurityDecisionEnum.STEP_UP),
    (ActionRiskLevel.CRITICAL, 30, SecurityDecisionEnum.BLOCK),
    (ActionRiskLevel.CRITICAL, 59, SecurityDecisionEnum.BLOCK),
    (ActionRiskLevel.CRITICAL, 29, SecurityDecisionEnum.ISOLATE),
    (ActionRiskLevel.CRITICAL, 0,  SecurityDecisionEnum.ISOLATE),
])
def test_policy_decision_matrix(action_risk, confidence, expected_decision):
    decision, reasons = PolicyDecisionEngine.decide(
        session_confidence=confidence,
        action_risk=action_risk,
        reason_codes=[],
    )
    assert decision == expected_decision, (
        f"Expected {expected_decision} for action_risk={action_risk}, confidence={confidence}"
    )


def test_open_incident_forces_isolate():
    """Active incident always results in ISOLATE regardless of confidence/risk."""
    for risk in ActionRiskLevel:
        for conf in [0, 40, 80, 100]:
            decision, reasons = PolicyDecisionEngine.decide(
                session_confidence=conf,
                action_risk=risk,
                reason_codes=[],
                open_incident=True,
            )
            assert decision == SecurityDecisionEnum.ISOLATE
            assert "ACTIVE_SECURITY_INCIDENT" in reasons


def test_isolate_includes_correct_reason_codes():
    decision, reasons = PolicyDecisionEngine.decide(
        session_confidence=0,
        action_risk=ActionRiskLevel.CRITICAL,
        reason_codes=["BEHAVIOR_ANOMALY"],
    )
    assert decision == SecurityDecisionEnum.ISOLATE
    assert "CONFIDENCE_TOO_LOW_FOR_ACTION" in reasons
    assert "CRITICAL_ACTION_BLOCKED" in reasons
    assert "SESSION_ISOLATED" in reasons
