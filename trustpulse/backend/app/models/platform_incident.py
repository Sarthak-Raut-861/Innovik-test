"""TRUSTPULSE — Platform security incident (raised on trust collapse / containment).

Kept separate from the SDK-facing ``incidents`` table so the two lifecycles never
collide: this one is driven by the TRUSTPULSE trust pipeline and owns the
containment record for a session.
"""

from datetime import datetime
from typing import Any, List, Optional

from sqlalchemy import JSON, DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, generate_uuid, utc_now


class PlatformIncidentModel(Base):
    """Security incident raised when trust collapses or containment triggers.

    Kept in this module so the whole evidence/proof chain lives together; the
    Phase-2 incident service owns its lifecycle.
    """

    __tablename__ = "platform_incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM", nullable=False)
    title: Mapped[str] = mapped_column(String(190), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # OPEN | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE
    status: Mapped[str] = mapped_column(String(24), default="OPEN", nullable=False)

    tci_at_detection: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    trust_state_at_detection: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    evidence_ids: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    containment_actions: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    receipt_ids: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)

    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_platform_incidents_status", "status"),
        Index("ix_platform_incidents_session", "session_id"),
        Index("ix_platform_incidents_severity", "severity"),
    )
