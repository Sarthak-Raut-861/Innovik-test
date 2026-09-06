"""TRUSTPULSE platform API schemas (sessions, telemetry, SOC, demo)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.trust import EvidenceRecord, TrustResult


# --------------------------------------------------------------------- session
class DeviceContext(BaseModel):
    """Non-secret device hints. Fingerprint is computed client-side."""

    fingerprint: str = Field(..., min_length=8, max_length=128)
    label: Optional[str] = Field(None, max_length=128)
    platform: Optional[str] = Field(None, max_length=64)
    browser: Optional[str] = Field(None, max_length=64)
    os_name: Optional[str] = Field(None, max_length=64)
    screen: Optional[str] = Field(None, max_length=32)
    timezone: Optional[str] = Field(None, max_length=64)


class NetworkContext(BaseModel):
    """Coarse network context. Raw IP addresses are never persisted."""

    country: Optional[str] = Field(None, max_length=8)
    asn: Optional[str] = Field(None, max_length=32)
    is_vpn: bool = False
    is_proxy_or_tor: bool = False
    client_ip: Optional[str] = Field(
        None, max_length=64, description="Stored only as a SHA-256 digest."
    )


class LoginRequest(BaseModel):
    """Simulated TrustDev login. Creates a TRUSTPULSE session as a side effect."""

    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=128)
    mfa_code: Optional[str] = Field(None, max_length=16)
    device: DeviceContext
    network: Optional[NetworkContext] = None
    application_id: str = Field("trustdev", max_length=64)


class SessionCreateRequest(BaseModel):
    """Server-side session registration for an already-authenticated user."""

    user_id: str = Field(
        ..., min_length=1, max_length=64, description="External user id, e.g. U001"
    )
    device: DeviceContext
    network: Optional[NetworkContext] = None
    auth_method: str = Field("PASSWORD", max_length=32)
    mfa_used: bool = False
    application_id: str = Field("trustdev", max_length=64)
    session_id: Optional[str] = Field(None, max_length=128)


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    status: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    device_id: Optional[str] = None
    device_fingerprint: Optional[str] = None
    application_id: str
    auth_method: str
    mfa_used: bool
    tci: Optional[float] = None
    confidence: str
    trend: str
    trust_state: str
    evaluations: int
    is_contained: bool
    created_at: datetime
    last_seen_at: datetime
    trust: Optional[TrustResult] = None


class LoginResponse(BaseModel):
    session: SessionResponse
    token: str
    trust: TrustResult


# -------------------------------------------------------------------- telemetry
class TelemetryRequest(BaseModel):
    """Derived behavioral telemetry. Raw events and characters are rejected."""

    session_id: str = Field(..., min_length=1, max_length=128)
    features: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Derived aggregates keyed by group: typing/mouse/click/scroll. "
            "Typed characters are rejected server-side."
        ),
    )
    flat_features: Optional[Dict[str, float]] = Field(
        None, description="Alternative: pre-normalized canonical feature values."
    )
    network: Optional[NetworkContext] = None
    sample_metadata: Optional[Dict[str, Any]] = None
    source: str = Field("SDK", max_length=16)
    observed_at: Optional[datetime] = None

    @field_validator("source")
    @classmethod
    def _check_source(cls, value: str) -> str:
        allowed = {"SDK", "SIMULATION", "BACKFILL"}
        if value.upper() not in allowed:
            raise ValueError(f"source must be one of {sorted(allowed)}")
        return value.upper()


class TelemetryResponse(BaseModel):
    accepted: bool
    features_received: int
    anomaly_score: float
    trust: TrustResult
    learned: Dict[str, Any] = Field(default_factory=dict)
    rejected_reason: Optional[str] = None


# -------------------------------------------------------------------- trust API
class TrustEvaluateRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    features: Optional[Dict[str, Any]] = None
    network: Optional[NetworkContext] = None
    trigger: str = Field("MANUAL", max_length=32)


class TrustHistoryResponse(BaseModel):
    session_id: str
    points: List[Dict[str, Any]]
    state_timeline: List[Dict[str, Any]]


# ------------------------------------------------------------------------- SOC
class SocOverview(BaseModel):
    active_sessions: int
    suspicious_sessions: int
    contained_sessions: int
    open_incidents: int
    average_tci: Optional[float]
    blocked_actions: int
    step_up_requests: int
    trust_model_version: str
    disclaimer: str = (
        "TCI is an engineering trust index, not a probability. Values are prototype parameters."
    )


class SocSessionSummary(BaseModel):
    session_id: str
    user: Optional[str] = None
    user_id: Optional[str] = None
    device: Optional[str] = None
    tci: Optional[float] = None
    trust_state: str
    trend: str
    confidence: str
    last_action: Optional[str] = None
    action_risk: Optional[int] = None
    decision: Optional[str] = None
    last_seen_at: datetime
    status: str
    is_contained: bool


class SocSessionDetail(BaseModel):
    session: SocSessionSummary
    trust: Optional[TrustResult] = None
    tci_history: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    baselines: Dict[str, Any] = Field(default_factory=dict)
    incidents: List[Dict[str, Any]] = Field(default_factory=list)


class UserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    external_user_id: str
    username: str
    display_name: Optional[str] = None
    role: str
    mfa_enabled: bool
    is_active: bool


class DeviceSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    device_fingerprint: str
    label: Optional[str] = None
    platform: Optional[str] = None
    browser: Optional[str] = None
    trust_level: str
    is_registered: bool
    is_flagged: bool
    observation_count: int
    last_seen_at: datetime


class HealthResponse(BaseModel):
    status: str
    product: str
    version: str
    trust_model_version: str
    database: str
    redis: str
    time: datetime


class DemoControlRequest(BaseModel):
    """Phase-3 demo hooks; declared here so the contract is stable from Phase 1."""

    session_id: Optional[str] = None
    scenario: str = Field(..., max_length=64)
    parameters: Dict[str, Any] = Field(default_factory=dict)
