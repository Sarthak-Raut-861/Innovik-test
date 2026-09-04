"""
TrustPulse AI - Session Schemas
"""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field


class SessionCreate(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128, description="Host application session ID")
    subject_id: Optional[str] = Field(None, max_length=128, description="Pseudonymous customer/user identifier")
    device_id: Optional[str] = Field(None, max_length=128, description="Device context identifier")
    sdk_instance_id: Optional[str] = Field(None, max_length=64, description="SDK instance UUID")


class SessionResponse(BaseModel):
    session_id: str
    status: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: Optional[datetime] = None
    sdk_instance_id: Optional[str] = None
    session_version: int

    class Config:
        from_attributes = True


class SessionStatusUpdate(BaseModel):
    status: str = Field(..., description="ACTIVE, PAUSED, TERMINATED, ISOLATED")
