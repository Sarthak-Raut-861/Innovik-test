"""
TrustPulse AI — Policy Types.

Only the policy engine may weigh all evidence and produce the authoritative
security decision. Behavioral models and risk engines produce evidence only.
"""

from enum import Enum
from typing import List

from pydantic import BaseModel, Field

from app.schemas.action import ActionRiskLevel


class SecurityDecisionEnum(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"

    @property
    def is_blocking(self) -> bool:
        return self in (SecurityDecisionEnum.BLOCK, SecurityDecisionEnum.ISOLATE)


class PolicyRule(BaseModel):
    rule_id: str
    description: str
    action_risk: ActionRiskLevel
    min_confidence: int = Field(ge=0, le=100)
    decision: SecurityDecisionEnum
    requires_open_incident: bool = False
    priority: int = Field(default=0, ge=0)


class PolicyDefinition(BaseModel):
    version: str = Field(default="v1")
    description: str = Field(default="TrustPulse default deterministic security policy")
    rules: List[PolicyRule] = Field(default_factory=list)
