"""TRUSTPULSE — Session Model.

A session is the unit of continuous trust. It carries:

* identity context (which user, how they authenticated, whether MFA was used)
* device binding (raw SDK fingerprint + resolved platform device row)
* network/context signals (hashed, never a raw IP address)
* the current TCI, its trend and the hysteresis-filtered trust state

TRUSTPULSE is NOT a session-timeout product: nothing here expires a session for
being idle. A session ends because the application ends it, or because the policy
engine revokes it on evidence of compromise.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, generate_uuid, utc_now

if TYPE_CHECKING:
    from app.models.device import DeviceModel
    from app.models.observations import (
        ActionModel,
        BehaviorFeatureModel,
        SecurityEventModel,
        TrustStateModel,
    )
    from app.models.user import UserModel


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    sdk_instance_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), default="ACTIVE", nullable=False
    )  # ACTIVE, PAUSED, TERMINATED, REVOKED, CONTAINED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    session_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # ------------------------------------------------------- TRUSTPULSE platform
    # Resolved platform identities (subject_id/device_id stay for SDK compatibility).
    user_ref_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE", name="fk_sessions_user_ref_id"),
        nullable=True,
    )
    device_ref_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE", name="fk_sessions_device_ref_id"),
        nullable=True,
    )
    application_id: Mapped[str] = mapped_column(String(64), default="trustdev", nullable=False)

    # Identity assurance context
    auth_method: Mapped[str] = mapped_column(String(32), default="PASSWORD", nullable=False)
    mfa_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    identity_assurance: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Network / context. The IP address is stored only as a SHA-256 digest.
    ip_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    network_country: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    network_asn: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    is_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_proxy_or_tor: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    baseline_network_country: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    baseline_network_asn: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Current trust
    tci: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    previous_tci: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    tci_confidence: Mapped[str] = mapped_column(String(8), default="LOW", nullable=False)
    tci_trend: Mapped[str] = mapped_column(String(20), default="INSUFFICIENT_DATA", nullable=False)
    trust_state: Mapped[str] = mapped_column(String(16), default="TRUSTED", nullable=False)
    trust_state_since: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trust_evaluations: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_trust_evaluation_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Containment / revocation
    is_contained: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    containment_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Step-up bookkeeping (Phase 2 uses this for challenge state)
    pending_step_up: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    step_up_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # ------------------------------------------------------------- relationships
    user: Mapped[Optional["UserModel"]] = relationship(
        "UserModel", back_populates="sessions", foreign_keys=[user_ref_id]
    )
    device: Mapped[Optional["DeviceModel"]] = relationship(
        "DeviceModel", back_populates="sessions", foreign_keys=[device_ref_id]
    )
    behavior_features: Mapped[List["BehaviorFeatureModel"]] = relationship(
        "BehaviorFeatureModel",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="BehaviorFeatureModel.observed_at",
    )
    trust_states: Mapped[List["TrustStateModel"]] = relationship(
        "TrustStateModel",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="TrustStateModel.observed_at",
    )
    security_events: Mapped[List["SecurityEventModel"]] = relationship(
        "SecurityEventModel",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="SecurityEventModel.observed_at",
    )
    actions: Mapped[List["ActionModel"]] = relationship(
        "ActionModel",
        back_populates="session",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="ActionModel.requested_at",
    )

    __table_args__ = (
        Index("ix_sessions_tenant_session", "customer_tenant_id", "session_id", unique=True),
        Index("ix_sessions_status", "status"),
        Index("ix_sessions_subject", "customer_tenant_id", "subject_id"),
        Index("ix_sessions_user_ref", "user_ref_id"),
        Index("ix_sessions_trust_state", "trust_state"),
        Index("ix_sessions_tci", "tci"),
        Index("ix_sessions_created", "created_at"),
    )
