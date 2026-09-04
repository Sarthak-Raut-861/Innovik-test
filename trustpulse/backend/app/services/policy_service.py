"""
TrustPulse AI — Policy Service.

Exposes the deterministic, versioned policy engine. Policy changes are intended
to be audited and protected by RBAC; Phase 2 ships a built-in audited v1 policy.
"""

from typing import List, Tuple

from app.engines.policy.policy_engine import PolicyEngine
from app.engines.policy.policy_types import PolicyDefinition, SecurityDecisionEnum
from app.schemas.action import ActionRiskLevel


class PolicyService:
    def __init__(self, policy_version: str = "v1"):
        self.policy_version = policy_version

    def get_policy(self) -> PolicyDefinition:
        return PolicyEngine.get_policy(self.policy_version)

    def decide(
        self,
        session_confidence: int,
        action_risk: ActionRiskLevel,
        reason_codes: List[str],
        open_incident: bool = False,
    ) -> Tuple[SecurityDecisionEnum, str, List[str]]:
        return PolicyEngine.decide(
            session_confidence=session_confidence,
            action_risk=action_risk,
            reason_codes=reason_codes,
            open_incident=open_incident,
            policy_version=self.policy_version,
        )
