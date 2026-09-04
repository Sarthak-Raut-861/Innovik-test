"""
TrustPulse AI - Action Request Model
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Float, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, generate_uuid, utc_now


class ActionRequestModel(Base):
    __tablename__ = "action_requests"

    action_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)  # VIEW_PROFILE, CHANGE_PASSWORD, LARGE_TRANSFER
    risk_level: Mapped[str] = mapped_column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    amount: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    currency: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_action_requests_tenant_session", "customer_tenant_id", "session_id"),
    )
