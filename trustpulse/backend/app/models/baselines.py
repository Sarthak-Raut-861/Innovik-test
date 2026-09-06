"""TRUSTPULSE — Trusted Core and Adaptive Shadow baselines.

Two separate tables on purpose:

* ``trusted_baselines`` — the stable reference. Moves slowly, is never trained by
  a suspicious session, and is only ever changed through the promotion gate.
* ``shadow_baselines`` — the fast learner that absorbs legitimate drift. It can
  be quarantined or reset without ever touching the core.

Only derived aggregate statistics (means / standard deviations in transformed
feature space) are stored. Never raw events, never typed characters.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, generate_uuid, utc_now


class _BaselineColumns:
    """Shared column set for both baseline tables (mixed into the models)."""

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=True
    )

    feature_schema_version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    baseline: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    version: Mapped[int] = mapped_column(Integer, default=1)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class TrustedBaselineModel(_BaselineColumns, Base):
    __tablename__ = "trusted_baselines"

    rejected_observations: Mapped[int] = mapped_column(Integer, default=0)
    promotions_from_shadow: Mapped[int] = mapped_column(Integer, default=0)
    last_promotion_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_observation_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "ux_trusted_baselines_tenant_user_device",
            "customer_tenant_id",
            "user_id",
            "device_id",
            unique=True,
        ),
    )


class ShadowBaselineModel(_BaselineColumns, Base):
    __tablename__ = "shadow_baselines"

    rejected_observations: Mapped[int] = mapped_column(Integer, default=0)
    quarantine_count: Mapped[int] = mapped_column(Integer, default=0)
    last_promotion_attempt_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_promotion_reasons: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index(
            "ux_shadow_baselines_tenant_user_device",
            "customer_tenant_id",
            "user_id",
            "device_id",
            unique=True,
        ),
    )
