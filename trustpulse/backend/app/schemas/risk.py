"""
TrustPulse AI - Risk Evaluation Schemas
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.action import ActionSchema, ActionRiskLevel


class RiskEvaluationRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    action: ActionSchema


class RiskEvaluationResponse(BaseModel):
    decision: str = Field(..., description="ALLOW, STEP_UP, BLOCK, ISOLATE")
    session_confidence: int = Field(..., ge=0, le=100, description="Confidence score 0-100")
    confidence_level: str = Field(..., description="LOW, GUARDED, MODERATE, HIGH")
    action_risk: ActionRiskLevel
    reason_codes: List[str] = Field(default_factory=list)
    policy_version: str = "v1"
    decision_id: Optional[str] = None
    evaluated_at: str
