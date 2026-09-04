"""
TrustPulse AI - Action Risk Engine
"""

from typing import Optional, Tuple
from app.schemas.action import ActionRiskLevel


class ActionRiskEngine:
    """
    Evaluates the inherent security risk level of an application action.
    Supports generic actions and dynamic thresholds based on transaction amounts.
    """

    # Baseline action risk catalog
    ACTION_MAP = {
        # Low risk actions
        "VIEW_PROFILE": ActionRiskLevel.LOW,
        "VIEW_BALANCE": ActionRiskLevel.LOW,
        "VIEW_DASHBOARD": ActionRiskLevel.LOW,
        "SEARCH": ActionRiskLevel.LOW,
        # Medium risk actions
        "CHANGE_SETTINGS": ActionRiskLevel.MEDIUM,
        "DOWNLOAD_STATEMENT": ActionRiskLevel.MEDIUM,
        "UPDATE_NOTIFICATION_PREFS": ActionRiskLevel.MEDIUM,
        # High risk actions
        "CHANGE_PASSWORD": ActionRiskLevel.HIGH,
        "UPDATE_EMAIL": ActionRiskLevel.HIGH,
        "UPDATE_PHONE": ActionRiskLevel.HIGH,
        "ADD_BENEFICIARY": ActionRiskLevel.HIGH,
        "DISABLE_2FA": ActionRiskLevel.HIGH,
        # Critical actions
        "LARGE_TRANSFER": ActionRiskLevel.CRITICAL,
        "WIRE_TRANSFER": ActionRiskLevel.CRITICAL,
        "DELETE_ACCOUNT": ActionRiskLevel.CRITICAL,
        "EXPORT_ALL_DATA": ActionRiskLevel.CRITICAL,
    }

    @classmethod
    def evaluate_action_risk(
        cls,
        action_type: str,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
    ) -> Tuple[ActionRiskLevel, Optional[str]]:
        """
        Calculates action risk level.
        Escalates risk dynamically based on transaction amount if applicable.
        """
        normalized_type = action_type.strip().upper()
        base_risk = cls.ACTION_MAP.get(normalized_type, ActionRiskLevel.MEDIUM)

        reason: Optional[str] = None

        # Financial amount escalation
        if amount is not None:
            if amount >= 100_000:
                base_risk = ActionRiskLevel.CRITICAL
                reason = f"High transaction amount ({amount} {currency or ''})"
            elif amount >= 25_000 and base_risk in (ActionRiskLevel.LOW, ActionRiskLevel.MEDIUM):
                base_risk = ActionRiskLevel.HIGH
                reason = f"Elevated transaction amount ({amount} {currency or ''})"

        return base_risk, reason
