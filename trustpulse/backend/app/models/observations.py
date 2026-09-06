"""TRUSTPULSE — Derived behavioral feature snapshots, trust-state history,
security events (evidence) and action attempts.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, generate_uuid, utc_now


class BehaviorFeatureModel(Base):
    """One derived-feature observation for a session.

    ``features`` holds the transformed canonical vector (means / std devs / rates).
    ``sample_metadata`` holds non-sensitive counters only (sample counts, window
    length). No raw events and no typed characters are ever persisted.
    """

    __tablename__ = "behavior_features"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    feature_schema_version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    features: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict)
    sample_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_reasons: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    deviations: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    features_compared: Mapped[int] = mapped_column(Integer, default=0)
    detector_method: Mapped[str] = mapped_column(String(48), default="statistical")

    # SDK | SIMULATION | BACKFILL — provenance matters for audit.
    source: Mapped[str] = mapped_column(String(16), default="SDK", nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    session = relationship("SessionModel", back_populates="behavior_features")

    __table_args__ = (
        Index("ix_behavior_features_session_time", "session_id", "observed_at"),
        Index("ix_behavior_features_user", "user_id"),
    )


class TrustStateModel(Base):
    """Append-only history of TCI evaluations and trust-state transitions."""

    __tablename__ = "trust_states"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    tci: Mapped[float] = mapped_column(Float, nullable=False)
    previous_tci: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    previous_state: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    state_changed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    raw_band: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    hysteresis_applied: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    confidence: Mapped[str] = mapped_column(String(8), default="LOW", nullable=False)
    trend: Mapped[str] = mapped_column(String(20), default="INSUFFICIENT_DATA", nullable=False)
    factors: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    evidence: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)
    warnings: Mapped[Optional[List[Any]]] = mapped_column(JSON, nullable=True)

    trigger: Mapped[str] = mapped_column(String(32), default="TELEMETRY", nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    session = relationship("SessionModel", back_populates="trust_states")

    __table_args__ = (
        Index("ix_trust_states_session_time", "session_id", "observed_at"),
        Index("ix_trust_states_state", "state"),
    )


class SecurityEventModel(Base):
    """One piece of explainable evidence attached to a session."""

    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True
    )
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # BEHAVIOR_DEVIATION | DEVICE_CHANGE | NETWORK_CHANGE | SESSION_ANOMALY |
    # UNUSUAL_ACTION | BASELINE_DEVIATION | PRIVILEGE_ESCALATION | ...
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)  # 0..1
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="TRUST_ENGINE", nullable=False)
    # `metadata` is reserved on DeclarativeBase, so the attribute is `meta`
    # while the column keeps its documented name.
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    session = relationship("SessionModel", back_populates="security_events")

    __table_args__ = (
        Index("ix_security_events_session_time", "session_id", "observed_at"),
        Index("ix_security_events_type", "event_type"),
        Index("ix_security_events_severity", "severity"),
    )


class ActionRiskProfileModel(Base):
    """Configurable, per-tenant action risk profile (overrides the built-in catalogue)."""

    __tablename__ = "action_risk_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)

    risk: Mapped[int] = mapped_column(Integer, nullable=False)
    sensitivity: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    privilege: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    resource_exposure: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    impact: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    category: Mapped[str] = mapped_column(String(32), default="WRITE", nullable=False)

    source: Mapped[str] = mapped_column(String(16), default="BUILTIN", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        Index("ux_action_risk_profiles_tenant_action", "customer_tenant_id", "action", unique=True),
    )


class ActionModel(Base):
    """A sensitive action attempted against a protected application (TrustDev)."""

    __tablename__ = "actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    customer_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    action_risk: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    risk_breakdown: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    tci_at_decision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    trust_state_at_decision: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # PENDING | ALLOW | STEP_UP | BLOCK | REVOKE | CONTAIN | ERROR
    decision: Mapped[str] = mapped_column(String(16), default="PENDING", nullable=False)
    decision_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    receipt_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    step_up_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    step_up_result: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    context: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    session = relationship("SessionModel", back_populates="actions")

    __table_args__ = (
        Index("ix_actions_session_time", "session_id", "requested_at"),
        Index("ix_actions_decision", "decision"),
        Index("ix_actions_action", "action"),
    )
