"""
TrustPulse AI — Action Risk Engine.

Classifies application actions into generic security risk categories:
LOW / MEDIUM / HIGH / CRITICAL.

The core engine is intentional about NOT embedding financial-vertical-only
concepts as hard rules. Verticals can map their own action vocabulary through a
configuration-driven policy. Built-in actions are a generic, auditable default.
"""

from typing import Dict, Optional, Tuple

from app.schemas.action import ActionRiskLevel


class ActionRiskEngine:
    # Baseline built-in generic catalog.
    ACTION_MAP: Dict[str, ActionRiskLevel] = {
        "VIEW_PROFILE": ActionRiskLevel.LOW,
        "VIEW_BALANCE": ActionRiskLevel.LOW,
        "VIEW_DASHBOARD": ActionRiskLevel.LOW,
        "SEARCH": ActionRiskLevel.LOW,
        "LIST": ActionRiskLevel.LOW,
        "CHANGE_SETTINGS": ActionRiskLevel.MEDIUM,
        "DOWNLOAD_STATEMENT": ActionRiskLevel.MEDIUM,
        "UPDATE_NOTIFICATION_PREFS": ActionRiskLevel.MEDIUM,
        "CHANGE_PROFILE": ActionRiskLevel.MEDIUM,
        "CHANGE_PASSWORD": ActionRiskLevel.HIGH,
        "UPDATE_EMAIL": ActionRiskLevel.HIGH,
        "UPDATE_PHONE": ActionRiskLevel.HIGH,
        "ADD_BENEFICIARY": ActionRiskLevel.HIGH,
        "DISABLE_2FA": ActionRiskLevel.HIGH,
        "LARGE_TRANSFER": ActionRiskLevel.CRITICAL,
        "WIRE_TRANSFER": ActionRiskLevel.CRITICAL,
        "DELETE_ACCOUNT": ActionRiskLevel.CRITICAL,
        "EXPORT_ALL_DATA": ActionRiskLevel.CRITICAL,
        "ADMIN_IMPORT": ActionRiskLevel.CRITICAL,
        "ROLE_CHANGE": ActionRiskLevel.HIGH,
    }

    @classmethod
    def get_catalog(cls) -> Dict[str, ActionRiskLevel]:
        return dict(cls.ACTION_MAP)

    @classmethod
    def evaluate_action_risk(
        cls,
        action_type: str,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
    ) -> Tuple[ActionRiskLevel, Optional[str]]:
        """Returns (risk_level, reason_code_or_none)."""
        normalized = (action_type or "").strip().upper()
        if not normalized:
            return ActionRiskLevel.MEDIUM, "UNKNOWN_ACTION_TYPE"

        base_risk = cls.ACTION_MAP.get(normalized)
        reason: Optional[str] = None

        if base_risk is None:
            # Generic classification fallback by category prefix.
            base_risk = cls._infer(normalized)
            reason = "INFERRED_ACTION_TYPE"

        if amount is not None and amount > 0:
            if amount >= 100_000:
                base_risk = ActionRiskLevel.CRITICAL
                reason = "LARGE_AMOUNT_ESCALATION" if not reason else reason
            elif amount >= 25_000 and base_risk in (ActionRiskLevel.LOW, ActionRiskLevel.MEDIUM):
                base_risk = ActionRiskLevel.HIGH
                reason = "AMOUNT_ESCALATION" if not reason else reason

        return base_risk, reason

    @staticmethod
    def _infer(action_type: str) -> ActionRiskLevel:
        if (
            action_type.startswith("VIEW_")
            or action_type.startswith("GET_")
            or action_type.startswith("LIST_")
            or action_type.startswith("SEARCH")
        ):
            return ActionRiskLevel.LOW
        if (
            action_type.startswith("DELETE_")
            or action_type.startswith("WIPE_")
            or action_type.startswith("PURGE_")
        ):
            return ActionRiskLevel.CRITICAL
        if (
            action_type.startswith("TRANSFER_")
            or action_type.startswith("PAYMENT_")
            or action_type.startswith("WITHDRAW_")
        ):
            return ActionRiskLevel.CRITICAL
        if action_type.startswith("EXPORT_") or action_type.startswith("IMPORT_"):
            return ActionRiskLevel.CRITICAL
        if (
            action_type.startswith("CHANGE_")
            or action_type.startswith("UPDATE_")
            or action_type.startswith("ADD_")
        ):
            return ActionRiskLevel.HIGH
        if action_type.startswith("SET_"):
            return ActionRiskLevel.MEDIUM
        return ActionRiskLevel.MEDIUM
