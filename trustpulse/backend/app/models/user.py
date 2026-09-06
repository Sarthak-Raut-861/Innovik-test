"""TRUSTPULSE — User Model.

Privacy rule: **passwords are never stored.** ``credential_hash`` holds a salted
PBKDF2-SHA256 digest of the demo credential and is only used by the TrustDev
simulated application's login. The trust engine never reads it.
"""

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.device import DeviceModel
    from app.models.session import SessionModel


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)

    external_user_id: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "U001"
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    role: Mapped[str] = mapped_column(String(32), default="MEMBER", nullable=False)
    department: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Derived identifiers only — no plaintext contact data.
    email_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Salted PBKDF2 digest for the simulated TrustDev login. Never a password.
    credential_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    credential_salt: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    default_auth_method: Mapped[str] = mapped_column(
        String(32), default="PASSWORD", nullable=False
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    devices: Mapped[List["DeviceModel"]] = relationship(
        "DeviceModel", back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
    sessions: Mapped[List["SessionModel"]] = relationship(
        "SessionModel", back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_users_tenant_external", "customer_tenant_id", "external_user_id", unique=True),
        Index("ix_users_tenant_username", "customer_tenant_id", "username", unique=True),
        Index("ix_users_active", "is_active"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<User {self.external_user_id} {self.username}>"
