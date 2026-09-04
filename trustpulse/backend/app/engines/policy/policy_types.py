"""
TrustPulse AI - Policy Types
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel
from app.schemas.action import ActionRiskLevel


class SecurityDecisionEnum(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    BLOCK = "BLOCK"
    ISOLATE = "ISOLATE"


class PolicyRule(BaseModel):
    rule_id: str
    description: str
    action_risk: ActionRiskLevel
    min_confidence: int
    decision: SecurityDecisionEnum
    requires_incident: bool = False
