"""
TrustPulse AI — Action Risk Engine tests.
"""

from app.engines.action.action_risk import ActionRiskEngine
from app.schemas.action import ActionRiskLevel


def test_low_risk_actions():
    assert ActionRiskEngine.evaluate_action_risk("VIEW_PROFILE")[0] == ActionRiskLevel.LOW
    assert ActionRiskEngine.evaluate_action_risk("VIEW_BALANCE")[0] == ActionRiskLevel.LOW


def test_medium_risk_actions():
    assert ActionRiskEngine.evaluate_action_risk("CHANGE_SETTINGS")[0] == ActionRiskLevel.MEDIUM
    assert ActionRiskEngine.evaluate_action_risk("DOWNLOAD_STATEMENT")[0] == ActionRiskLevel.MEDIUM


def test_high_risk_actions():
    assert ActionRiskEngine.evaluate_action_risk("CHANGE_PASSWORD")[0] == ActionRiskLevel.HIGH
    assert ActionRiskEngine.evaluate_action_risk("DISABLE_2FA")[0] == ActionRiskLevel.HIGH


def test_critical_risk_actions():
    assert ActionRiskEngine.evaluate_action_risk("LARGE_TRANSFER")[0] == ActionRiskLevel.CRITICAL
    assert ActionRiskEngine.evaluate_action_risk("DELETE_ACCOUNT")[0] == ActionRiskLevel.CRITICAL


def test_generic_type_inference():
    assert ActionRiskEngine.evaluate_action_risk("VIEW_RECORDS")[0] == ActionRiskLevel.LOW
    assert ActionRiskEngine.evaluate_action_risk("CHANGE_DATA")[0] == ActionRiskLevel.HIGH
    assert ActionRiskEngine.evaluate_action_risk("DELETE_DATA")[0] == ActionRiskLevel.CRITICAL


def test_amount_escalates_risk():
    risk, reason = ActionRiskEngine.evaluate_action_risk(
        "CHANGE_SETTINGS", amount=25000, currency="USD"
    )
    assert risk == ActionRiskLevel.HIGH
    risk2, _ = ActionRiskEngine.evaluate_action_risk(
        "CHANGE_SETTINGS", amount=100000, currency="USD"
    )
    assert risk2 == ActionRiskLevel.CRITICAL


def test_catalog_is_generic():
    catalog = ActionRiskEngine.get_catalog()
    assert "VIEW_PROFILE" in catalog
    assert "LARGE_TRANSFER" in catalog
