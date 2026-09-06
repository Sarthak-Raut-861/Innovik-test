"""TRUSTPULSE — Phase 2 schemas: authorization, receipts, incidents, posture.

The action request and decision shapes here are the shared contract an
integrating application codes against. They are mirrored in
``shared/schemas/trust.ts``; ``tests/test_shared_contract.py`` fails if the two
drift apart.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------- actions
class ActionEvaluateRequest(BaseModel):
    """A sensitive action an application wants to perform.

    Risk describes the ACTION, not the user. Who is asking is handled by the
    session's trust state, which the PEP reads server-side — a caller cannot
    assert its own trust level.
    """

    session_id: str = Field(..., min_length=1, max_length=128)
    action: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description=(
            "Declared action name, e.g. CREATE_API_KEY. Undeclared names are "
            "inferred as MEDIUM risk."
        ),
    )
    resource: Optional[str] = Field(None, max_length=128)
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Risk-relevant context: amount, privileged, production. Everything else is "
            "recorded for audit but does not change the score."
        ),
    )
    features: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional derived telemetry captured since the last sample.",
    )
    re_evaluate_trust: bool = Field(
        True,
        description="Recompute trust before deciding. Disable only for read-only replay.",
    )


class StepUpChallenge(BaseModel):
    challenge_id: str
    required: bool = True
    method: str
    allowed_methods: List[str] = Field(default_factory=list)
    expires_in_seconds: int
    max_attempts: int
    attempts_used: int = 0
    reason: str
    note: Optional[str] = None


class ActionDecisionResponse(BaseModel):
    """The authorization answer.

    The first five fields are the shared decision contract; the rest is
    supplementary audit detail an integration may ignore.
    """

    decision: str
    tci: float
    action_risk: int
    trust_state: str
    receipt_id: Optional[str] = None

    action_id: str
    action: str
    resource: Optional[str] = None
    reason: str
    rule_id: str
    policy_version: str
    risk_band: str
    risk_breakdown: Dict[str, Any] = Field(default_factory=dict)
    step_up: Optional[StepUpChallenge] = None
    containment: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    receipt: Optional[Dict[str, Any]] = None
    trust: Optional[Dict[str, Any]] = None
    policy_audit: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class StepUpResolveRequest(BaseModel):
    """Reports the outcome of a step-up challenge.

    TRUSTPULSE does not perform the authentication — the application or its IdP
    does. This endpoint records the outcome, which is what turns a challenge
    into evidence.
    """

    challenge_id: str = Field(..., min_length=1, max_length=64)
    success: bool
    method: Optional[str] = Field(None, max_length=32)


class StepUpResolveResponse(BaseModel):
    accepted: bool
    challenge_id: str
    status: Optional[str] = None
    error: Optional[str] = None
    attempts: Optional[int] = None
    max_attempts: Optional[int] = None
    exhausted: Optional[bool] = None
    blocked: Optional[bool] = None
    tci: Optional[float] = None
    trust_state: Optional[str] = None
    tci_before: Optional[float] = Field(
        None, description="TCI immediately before re-evaluation, as measured server-side."
    )
    tci_penalty_configured: Optional[float] = Field(
        None,
        description=(
            "The `step_up.failure_tci_penalty` value from the shared config. "
            "This is the configured intent, not the observed change."
        ),
    )
    tci_penalty_applied: Optional[float] = Field(
        None,
        description=(
            "TCI points actually lost, measured before/after re-evaluation. "
            "Smaller than the configured value because the session-context and "
            "history penalties are weighted."
        ),
    )
    mfa_used: Optional[bool] = None
    containment: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None


# ------------------------------------------------------- revocation/containment
class SessionControlRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=256)
    # Containment only: which actions to apply. Defaults to the configured set.
    actions: Optional[List[str]] = None
    flag_device: Optional[bool] = None
    serve_deception: Optional[bool] = None
    open_incident: bool = True


class SessionControlResponse(BaseModel):
    session_id: str
    status: str
    trust_state: str
    tci: Optional[float] = None
    is_contained: bool
    applied: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    token_invalidated: bool = False
    device_flagged: bool = False
    deception: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


# --------------------------------------------------------------------- receipts
class ReceiptResponse(BaseModel):
    receipt_id: str
    session_id: str
    user_id: str
    device_id: str
    action: str
    resource: Optional[str] = None
    nonce: str
    decision: str
    tci: float
    action_risk: int
    trust_state: str
    policy_version: str
    rule_id: Optional[str] = None
    explanation: Optional[str] = None
    evidence_hash: str
    receipt_hash: str
    hash_algorithm: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool
    proof_record_id: Optional[str] = None
    merkle_leaf: Optional[str] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    factors: Dict[str, Any] = Field(default_factory=dict)


class ReceiptVerifyRequest(BaseModel):
    """Optionally re-assert the binding fields when presenting a receipt.

    Any mismatch between what the caller claims and what was issued is a
    verification failure. This is what makes tampering detectable.
    """

    presented: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Claimed binding fields: user_id, device_id, session_id, action, "
            "resource, nonce."
        ),
    )
    check_binding: bool = True
    mark_used: bool = True


class ReceiptVerifyResponse(BaseModel):
    valid: bool
    receipt_id: str
    reasons: List[str]
    hash_matches: bool
    expired: bool = False
    revoked: bool = False
    reused: bool = False
    not_found: bool = False
    binding: Optional[Dict[str, Any]] = None
    verified_at: Optional[datetime] = None


# --------------------------------------------------------------------- incidents
class IncidentResponse(BaseModel):
    id: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    severity: str
    title: str
    description: Optional[str] = None
    status: str
    tci_at_detection: Optional[float] = None
    trust_state_at_detection: Optional[str] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    containment_actions: List[str] = Field(default_factory=list)
    receipt_ids: List[str] = Field(default_factory=list)
    opened_at: datetime
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    is_open: bool


class IncidentUpdateRequest(BaseModel):
    status: str = Field(
        ..., description="OPEN | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE"
    )
    note: Optional[str] = Field(None, max_length=512)
    closed_by: Optional[str] = Field(None, max_length=128)


# ----------------------------------------------------------------------- posture
class PostureResponse(BaseModel):
    score: float
    grade: str
    components: Dict[str, float]
    active_sessions: int
    contained_sessions: int
    suspicious_sessions: int
    average_tci: Optional[float] = None
    open_incidents: int
    critical_incidents: int
    blocked_actions: int
    step_up_requests: int
    step_up_failures: int
    allowed_actions: int
    recent_security_events: int
    generated_at: datetime


class PolicyConfigResponse(BaseModel):
    """The live authorization policy — served so decisions are auditable."""

    policy_version: str
    default_decision: str
    terminal_trust_states: List[str]
    tci_block_floor: float
    tci_block_floor_min_risk: int
    rules: List[Dict[str, Any]]
    step_up: Dict[str, Any]
    receipts: Dict[str, Any]
    containment: Dict[str, Any]
    disclaimer: str


__all__ = [
    "ActionEvaluateRequest",
    "ActionDecisionResponse",
    "StepUpChallenge",
    "StepUpResolveRequest",
    "StepUpResolveResponse",
    "SessionControlRequest",
    "SessionControlResponse",
    "ReceiptResponse",
    "ReceiptVerifyRequest",
    "ReceiptVerifyResponse",
    "IncidentResponse",
    "IncidentUpdateRequest",
    "PostureResponse",
    "PolicyConfigResponse",
]
