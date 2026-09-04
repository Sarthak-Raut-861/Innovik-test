"""
TrustPulse AI — Behavioral Profile Model.

Holds trusted and candidate statistical baselines. Candidate data never
automatically overwrites the trusted baseline.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, generate_uuid, utc_now


class BehavioralProfileModel(Base):
    __tablename__ = "behavioral_profiles"

    profile_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    device_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    feature_schema_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)

    trusted_baseline: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    trusted_baseline_previous: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    candidate_baseline: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    baseline_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    observation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (
        Index(
            "ix_profiles_tenant_subject_device",
            "customer_tenant_id",
            "subject_id",
            "device_id",
            unique=True,
        ),
    )
