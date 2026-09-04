"""
TrustPulse AI - Security Decision Model
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, DateTime, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, generate_uuid, utc_now


class SecurityDecisionModel(Base):
    __tablename__ = "security_decisions"

    decision_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    decision: Mapped[str] = mapped_column(String(32), nullable=False)  # ALLOW, STEP_UP, BLOCK, ISOLATE
    reason_codes: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)

    policy_version: Mapped[str] = mapped_column(String(32), default="v1", nullable=False)
    policy_rule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_security_decisions_tenant_session", "customer_tenant_id", "session_id"),
        Index("ix_security_decisions_decision", "decision"),
    )
