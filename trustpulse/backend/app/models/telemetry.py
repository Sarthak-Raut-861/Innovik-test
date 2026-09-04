"""
TrustPulse AI - Telemetry Event Model
"""

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import JSON, BigInteger, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, generate_uuid, utc_now


class TelemetryEventModel(Base):
    __tablename__ = "telemetry_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sdk_instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[int] = mapped_column(BigInteger, nullable=False)  # UTC Epoch in ms
    schema_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    feature_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    validation_status: Mapped[str] = mapped_column(String(32), default="VALID", nullable=False)
    rejection_reason: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    __table_args__ = (
        Index(
            "ix_telemetry_tenant_session_seq", "customer_tenant_id", "session_id", "sequence_number"
        ),
        Index("ix_telemetry_tenant_event", "customer_tenant_id", "event_id", unique=True),
        Index("ix_telemetry_timestamp", "timestamp"),
    )
