"""TRUSTPULSE — Device Model.

A device is a browser/OS fingerprint observed by the SDK. Devices accumulate
trust through repeated, consistent use; a device can also be flagged during
containment, which immediately degrades every session bound to it.
"""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.session import SessionModel
    from app.models.user import UserModel


class DeviceModel(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Stable, non-reversible fingerprint computed by the SDK from public client hints.
    device_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )

    label: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    platform: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    browser: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    os_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    screen: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # TRUSTED | KNOWN | NEW | FLAGGED
    trust_level: Mapped[str] = mapped_column(String(16), default="NEW", nullable=False)
    is_registered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_flagged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    flag_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    observation_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    user: Mapped[Optional["UserModel"]] = relationship("UserModel", back_populates="devices")
    sessions: Mapped[List["SessionModel"]] = relationship(
        "SessionModel", back_populates="device", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index(
            "ix_devices_tenant_fingerprint",
            "customer_tenant_id",
            "device_fingerprint",
            unique=True,
        ),
        Index("ix_devices_user", "user_id"),
        Index("ix_devices_trust_level", "trust_level"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Device {self.device_fingerprint[:12]} {self.trust_level}>"
