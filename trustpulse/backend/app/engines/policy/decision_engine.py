"""
TrustPulse AI - Policy Decision Engine

Deterministic mapping from (session_confidence, action_risk) to security decision.
All logic is stateless, testable, and auditable.
"""

from typing import List, Tuple
from app.engines.policy.policy_types import SecurityDecisionEnum, PolicyRule
from app.schemas.action import ActionRiskLevel
from app.core.config import settings


class PolicyDecisionEngine:
    """
    Maps (session_confidence, action_risk) → (decision, reason_codes)
    using a priority-ordered, deterministic policy matrix.

    Policy Matrix (ascending specificity / priority):
    ┌────────────────┬────────────────┬───────────────────┐
    │ Action Risk    │ Min Confidence │ Decision          │
    ├────────────────┼────────────────┼───────────────────┤
    │ LOW            │ 0              │ ALLOW             │
    │ MEDIUM         │ GUARDED (30)   │ ALLOW             │
    │ MEDIUM         │ <30            │ STEP_UP           │
    │ HIGH           │ MODERATE (60)  │ ALLOW             │
    │ HIGH           │ GUARDED (30)   │ STEP_UP           │
    │ HIGH           │ <30            │ BLOCK             │
    │ CRITICAL       │ HIGH (80)      │ ALLOW             │
    │ CRITICAL       │ MODERATE (60)  │ STEP_UP           │
    │ CRITICAL       │ GUARDED (30)   │ BLOCK             │
    │ CRITICAL       │ <30            │ ISOLATE           │
    │ ANY            │ active_incident│ ISOLATE           │
    └────────────────┴────────────────┴───────────────────┘
    """

    @staticmethod
    def decide(
        session_confidence: int,
        action_risk: ActionRiskLevel,
        reason_codes: List[str],
        open_incident: bool = False,
    ) -> Tuple[SecurityDecisionEnum, List[str]]:
        """
        Returns (decision, enriched_reason_codes).
        """
        HIGH = settings.HIGH_CONFIDENCE_THRESHOLD       # 80
        MODERATE = settings.MODERATE_CONFIDENCE_THRESHOLD  # 60
        GUARDED = settings.GUARDED_CONFIDENCE_THRESHOLD    # 30

        # Highest priority: active security incident
        if open_incident:
            reason_codes = list(set(reason_codes + ["ACTIVE_SECURITY_INCIDENT"]))
            return SecurityDecisionEnum.ISOLATE, reason_codes

        if action_risk == ActionRiskLevel.LOW:
            return SecurityDecisionEnum.ALLOW, reason_codes

        if action_risk == ActionRiskLevel.MEDIUM:
            if session_confidence >= GUARDED:
                return SecurityDecisionEnum.ALLOW, reason_codes
            reason_codes = list(set(reason_codes + ["CONFIDENCE_TOO_LOW_FOR_ACTION"]))
            return SecurityDecisionEnum.STEP_UP, reason_codes

        if action_risk == ActionRiskLevel.HIGH:
            if session_confidence >= MODERATE:
                return SecurityDecisionEnum.ALLOW, reason_codes
            if session_confidence >= GUARDED:
                reason_codes = list(set(reason_codes + ["CONFIDENCE_TOO_LOW_FOR_ACTION"]))
                return SecurityDecisionEnum.STEP_UP, reason_codes
            reason_codes = list(set(reason_codes + ["CONFIDENCE_TOO_LOW_FOR_ACTION", "HIGH_RISK_ACTION_BLOCKED"]))
            return SecurityDecisionEnum.BLOCK, reason_codes

        if action_risk == ActionRiskLevel.CRITICAL:
            if session_confidence >= HIGH:
                return SecurityDecisionEnum.ALLOW, reason_codes
            if session_confidence >= MODERATE:
                reason_codes = list(set(reason_codes + ["CONFIDENCE_TOO_LOW_FOR_ACTION"]))
                return SecurityDecisionEnum.STEP_UP, reason_codes
            if session_confidence >= GUARDED:
                reason_codes = list(set(reason_codes + ["CONFIDENCE_TOO_LOW_FOR_ACTION", "CRITICAL_ACTION_BLOCKED"]))
                return SecurityDecisionEnum.BLOCK, reason_codes
            reason_codes = list(set(reason_codes + [
                "CONFIDENCE_TOO_LOW_FOR_ACTION",
                "CRITICAL_ACTION_BLOCKED",
                "SESSION_ISOLATED",
            ]))
            return SecurityDecisionEnum.ISOLATE, reason_codes

        # Fallback: should never be reached
        reason_codes = list(set(reason_codes + ["UNKNOWN_RISK_LEVEL"]))
        return SecurityDecisionEnum.BLOCK, reason_codes
