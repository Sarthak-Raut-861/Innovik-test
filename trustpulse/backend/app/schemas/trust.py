"""TRUSTPULSE — Trust domain schemas (shared contract with the SDK and the UI)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TrustStateEnum(str, Enum):
    """Trust states are ordered by severity; CONTAINED is terminal."""

    TRUSTED = "TRUSTED"
    DEGRADED = "DEGRADED"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"
    BLOCKED = "BLOCKED"
    CONTAINED = "CONTAINED"


# Severity order used by the hysteresis state machine.
STATE_SEVERITY: Dict[str, int] = {
    TrustStateEnum.TRUSTED.value: 0,
    TrustStateEnum.DEGRADED.value: 1,
    TrustStateEnum.SUSPICIOUS.value: 2,
    TrustStateEnum.CRITICAL.value: 3,
    TrustStateEnum.BLOCKED.value: 4,
    TrustStateEnum.CONTAINED.value: 5,
}


class TrendEnum(str, Enum):
    RISING = "RISING"
    STABLE = "STABLE"
    FALLING = "FALLING"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ConfidenceEnum(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceRecord(BaseModel):
    """One explainable piece of evidence.

    Evidence never decides anything on its own — it explains the decision.
    """

    type: str = Field(..., description="Evidence type, e.g. BEHAVIOR_DEVIATION")
    severity: float = Field(..., ge=0.0, le=1.0)
    description: str
    source: str = "TRUST_ENGINE"
    observed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = self.model_dump()
        if payload.get("observed_at") is not None:
            payload["observed_at"] = self.observed_at.isoformat()
        return payload


class FactorScoreSchema(BaseModel):
    """One of the six TCI factors with its explanation."""

    name: str
    score: float = Field(..., ge=0.0, le=100.0)
    configured_weight: float
    effective_weight: float = 0.0
    available: bool = True
    contribution: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    detail: Dict[str, Any] = Field(default_factory=dict)


class TrustResult(BaseModel):
    """The trust answer for a session at a point in time.

    ``tci`` is a Trust Confidence Index on a 0-100 engineering scale. It is NOT a
    probability of anything and must not be interpreted as one.
    """

    session_id: str
    tci: float = Field(..., ge=0.0, le=100.0)
    confidence: ConfidenceEnum = ConfidenceEnum.LOW
    trend: TrendEnum = TrendEnum.INSUFFICIENT_DATA
    state: TrustStateEnum
    previous_state: Optional[TrustStateEnum] = None
    state_changed: bool = False
    raw_band: Optional[str] = None
    hysteresis_applied: bool = False
    factors: List[FactorScoreSchema] = Field(default_factory=list)
    evidence: List[EvidenceRecord] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    evaluations: int = 0
    evaluated_at: Optional[datetime] = None
    trigger: str = "TELEMETRY"

    def factor_map(self) -> Dict[str, float]:
        return {factor.name: factor.score for factor in self.factors}


class TrustHistoryPoint(BaseModel):
    observed_at: datetime
    tci: float
    state: str
    confidence: str
    trend: str
    trigger: str
    state_changed: bool = False


class SessionTrustResponse(BaseModel):
    """Trust view of one session, as consumed by the SOC dashboard."""

    session_id: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    device_id: Optional[str] = None
    device_label: Optional[str] = None
    application_id: str = "trustdev"
    status: str
    auth_method: str
    tci: Optional[float] = None
    confidence: str = "LOW"
    trend: str = "INSUFFICIENT_DATA"
    trust_state: str
    trust_state_since: Optional[datetime] = None
    evaluations: int = 0
    last_action: Optional[str] = None
    last_action_risk: Optional[int] = None
    last_decision: Optional[str] = None
    created_at: datetime
    last_seen_at: datetime
    is_contained: bool = False
    factors: List[FactorScoreSchema] = Field(default_factory=list)
    evidence: List[EvidenceRecord] = Field(default_factory=list)


class TrustModelInfo(BaseModel):
    """Read-only transparency view of the active trust model configuration."""

    schema_version: str
    source: str
    weights: Dict[str, float]
    state_bands: List[Dict[str, Any]]
    hysteresis: Dict[str, Any]
    action_risk_profiles: Dict[str, Dict[str, Any]]
    evidence_types: List[str]
    disclaimer: str = (
        "TCI is an engineering trust index, not a probability. All weights and "
        "thresholds are configurable prototype parameters."
    )
