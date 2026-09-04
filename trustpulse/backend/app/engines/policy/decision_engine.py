"""
TrustPulse AI — Backward-compatible Policy Decision Engine wrapper.

Legacy callers used `PolicyDecisionEngine.decide(...)`. New code should use
`PolicyEngine` directly; this adapter keeps older tests and integrations valid.
"""

from typing import List, Tuple

from app.engines.policy.policy_engine import PolicyEngine
from app.engines.policy.policy_types import SecurityDecisionEnum
from app.schemas.action import ActionRiskLevel


class PolicyDecisionEngine:
    @staticmethod
    def decide(
        session_confidence: int,
        action_risk: ActionRiskLevel,
        reason_codes: List[str],
        open_incident: bool = False,
    ) -> Tuple[SecurityDecisionEnum, List[str]]:
        decision, _, reasons = PolicyEngine.decide(
            session_confidence=session_confidence,
            action_risk=action_risk,
            reason_codes=reason_codes,
            open_incident=open_incident,
            policy_version="v1",
        )
        return decision, reasons
