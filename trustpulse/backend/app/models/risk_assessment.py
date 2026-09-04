"""
TrustPulse AI - Risk Assessment Model
"""

from datetime import datetime
from sqlalchemy import String, DateTime, Float, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, generate_uuid, utc_now


class RiskAssessmentModel(Base):
    __tablename__ = "risk_assessments"

    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)

    behavior_signal: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    device_signal: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    network_signal: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    session_history_signal: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    session_confidence: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 to 100
    confidence_level: Mapped[str] = mapped_column(String(32), nullable=False)  # LOW, GUARDED, MODERATE, HIGH

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        Index("ix_risk_assessments_tenant_session", "customer_tenant_id", "session_id"),
        Index("ix_risk_assessments_created_at", "created_at"),
    )
