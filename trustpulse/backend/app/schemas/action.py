"""
TrustPulse AI - Action Schemas
"""

from typing import Optional
from enum import Enum
from pydantic import BaseModel, Field


class ActionRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionSchema(BaseModel):
    type: str = Field(..., min_length=1, max_length=64, description="Action type name, e.g. LARGE_TRANSFER, CHANGE_PASSWORD")
    amount: Optional[float] = Field(None, ge=0, description="Financial or quantitative value associated with action")
    currency: Optional[str] = Field(None, max_length=16, description="ISO currency code, e.g. INR, USD, EUR")
    resource_type: Optional[str] = Field(None, max_length=64, description="Target resource category, e.g. BENEFICIARY, ACCOUNT")
    resource_id: Optional[str] = Field(None, max_length=128, description="Target resource identifier")


class ActionResponse(BaseModel):
    action_id: str
    session_id: str
    action_type: str
    risk_level: ActionRiskLevel
    amount: Optional[float] = None
    currency: Optional[str] = None
    created_at: str

    class Config:
        from_attributes = True
