"""
TrustPulse AI — Incident Schemas.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class IncidentResponse(BaseModel):
    incident_id: str
    session_id: str
    severity: str
    status: str
    trigger_reason: str
    decision_id: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentResolveRequest(BaseModel):
    resolution_notes: Optional[str] = Field(None, max_length=512)
    status: Optional[str] = Field(None, max_length=32, description="RESOLVED or CLOSED")


class IncidentListResponse(BaseModel):
    items: List[IncidentResponse]
    total: int
