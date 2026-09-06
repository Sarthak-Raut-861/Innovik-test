"""TRUSTPULSE platform API — Phase 2: authorization, receipts, incidents, posture.

Mounted at ``/api/v1``. Every sensitive action an integrating application
performs should call ``POST /actions/evaluate`` and honour the answer.

This is the enforcement surface. The Policy Enforcement Point behind it is the
only component in the system that may produce an ALLOW.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.exceptions import SessionNotFoundException, TrustPulseException
from app.core.trust_config import get_trust_config
from app.models.base import get_db_session
from app.models.session import SessionModel
from app.repositories.platform import PlatformRepository
from app.schemas.authorization import (
    ActionDecisionResponse,
    ActionEvaluateRequest,
    IncidentResponse,
    IncidentUpdateRequest,
    PolicyConfigResponse,
    PostureResponse,
    ReceiptResponse,
    ReceiptVerifyRequest,
    ReceiptVerifyResponse,
    SessionControlRequest,
    SessionControlResponse,
    StepUpResolveRequest,
    StepUpResolveResponse,
)
from app.services.enforcement.pep import PolicyEnforcementPoint, read_extra, write_extra
from app.services.incidents.service import (
    CLOSED_STATUSES,
    OPEN_STATUSES,
    IncidentService,
    SecurityPostureService,
)
from app.services.receipts.service import ReceiptService

router = APIRouter(tags=["TRUSTPULSE Authorization"])


async def _require_session(repo: PlatformRepository, session_id: str) -> SessionModel:
    session = await repo.get_session_by_session_id(session_id)
    if session is None:
        raise SessionNotFoundException(session_id)
    return session


# --------------------------------------------------------------------- actions
@router.post(
    "/actions/evaluate",
    response_model=ActionDecisionResponse,
    summary="Authorize a sensitive action (Policy Enforcement Point)",
)
async def evaluate_action(
    request: ActionEvaluateRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """The single authorization entry point.

    Combines the session's current trust with the requested action's risk and
    returns ALLOW, STEP_UP or BLOCK. Trust is re-evaluated first so the decision
    is never made on a stale score.

    The response always carries a ``receipt_id``: the answer to "why?" is
    recorded even when the answer is no.
    """
    repo = PlatformRepository(db, integration.tenant_id)
    session = await _require_session(repo, request.session_id)

    pep = PolicyEnforcementPoint(db, integration.tenant_id)
    result = await pep.enforce(
        session=session,
        action=request.action,
        resource=request.resource,
        context=request.context,
        features=request.features,
        re_evaluate_trust=request.re_evaluate_trust,
    )
    await db.commit()
    return result.to_response()


@router.post(
    "/actions/{action_id}/step-up",
    response_model=StepUpResolveResponse,
    summary="Report the outcome of a step-up challenge",
)
async def resolve_step_up(
    action_id: str,
    request: StepUpResolveRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Records whether a step-up challenge succeeded or failed.

    TRUSTPULSE does not perform the authentication; the application or its IdP
    does. A failure is treated as evidence: it lowers the TCI and, above the
    configured risk threshold, triggers containment.
    """
    repo = PlatformRepository(db, integration.tenant_id)
    pep = PolicyEnforcementPoint(db, integration.tenant_id)

    # The challenge is looked up by id, then bound back to its session — a
    # caller must not be able to resolve one session's challenge against another.
    from sqlalchemy import select

    from app.models.observations import ActionModel

    result = await db.execute(
        select(ActionModel).where(
            ActionModel.customer_tenant_id == integration.tenant_id,
            ActionModel.id == action_id,
        )
    )
    record = result.scalar_one_or_none()
    if record is None:
        return {
            "accepted": False,
            "challenge_id": request.challenge_id,
            "error": "ACTION_NOT_FOUND",
        }

    session = await repo.get_session(record.session_id)
    if session is None:
        raise SessionNotFoundException(record.session_id)

    outcome = await pep.resolve_step_up(
        session=session,
        challenge_id=request.challenge_id,
        success=request.success,
        method=request.method,
    )
    await db.commit()
    return outcome


# ------------------------------------------------------- revocation/containment
@router.post(
    "/sessions/{session_id}/revoke",
    response_model=SessionControlResponse,
    summary="Revoke a session and invalidate its token",
)
async def revoke_session(
    session_id: str,
    request: Optional[SessionControlRequest] = None,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Ends a session immediately.

    Revocation is distinct from containment: it stops the session but does not
    flag the device or serve deception. Use containment for a suspected
    compromise.
    """
    repo = PlatformRepository(db, integration.tenant_id)
    session = await _require_session(repo, session_id)
    payload = request or SessionControlRequest()

    session.status = "REVOKED"
    extra = read_extra(session)
    extra["revoked_at"] = _iso_now()
    extra["revoke_reason"] = payload.reason
    extra["token_hash"] = None
    write_extra(session, extra)
    await db.flush()

    incident_id = None
    if payload.open_incident:
        incidents = IncidentService(db, integration.tenant_id)
        incident = await _open_manual_incident(
            db,
            integration.tenant_id,
            session=session,
            title=f"Session revoked: {payload.reason or 'operator action'}",
            severity="HIGH",
            description=(
                f"Session {session_id} was revoked by an operator or the integrating "
                f"application. Reason: {payload.reason or 'not supplied'}."
            ),
            actions=["REVOKE_SESSION", "INVALIDATE_TOKEN"],
        )
        incident_id = incident.id if incident else None
        _ = incidents  # IncidentService kept for symmetry with the contain path

    await db.commit()
    return {
        "session_id": session.session_id,
        "status": session.status,
        "trust_state": session.trust_state,
        "tci": session.tci,
        "is_contained": bool(session.is_contained),
        "applied": ["REVOKE_SESSION", "INVALIDATE_TOKEN"],
        "incident_id": incident_id,
        "token_invalidated": True,
        "device_flagged": False,
        "deception": None,
        "reason": payload.reason,
    }


@router.post(
    "/sessions/{session_id}/contain",
    response_model=SessionControlResponse,
    summary="Contain a compromised session",
)
async def contain_session(
    session_id: str,
    request: Optional[SessionControlRequest] = None,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Contains a session: revokes it, flags the device, opens an incident.

    Optionally serves labeled deception — the contained session keeps getting
    plausible-but-fake responses so the attacker's activity stays observable
    without exposing real data. The deception is always labeled in the record;
    it is an investigative aid, never a silent lie to the end user's detriment.
    """
    repo = PlatformRepository(db, integration.tenant_id)
    session = await _require_session(repo, session_id)
    payload = request or SessionControlRequest()

    config = get_trust_config().containment()
    applied: List[str] = ["REVOKE_SESSION", "INVALIDATE_TOKEN"]

    session.status = "REVOKED"
    extra = read_extra(session)
    extra["contained_at"] = _iso_now()
    extra["contain_reason"] = payload.reason
    extra["token_hash"] = None
    write_extra(session, extra)

    device_flagged = False
    flag_device = (
        config.get("flag_device", True) if payload.flag_device is None else payload.flag_device
    )
    if flag_device and session.device_ref_id:
        device = await repo.get_device(session.device_ref_id)
        if device is not None:
            device.is_flagged = True
            device.trust_level = "FLAGGED"
            applied.append("FLAG_DEVICE")
            device_flagged = True

    deception_payload = None
    serve = (
        config.get("deception", {}).get("enabled", False)
        if payload.serve_deception is None
        else payload.serve_deception
    )
    if serve:
        deception = config.get("deception", {})
        deception_payload = {
            "active": True,
            "label": deception.get("label", "DECEPTION_SANDBOX"),
            "notice": deception.get("notice", ""),
            "since": _iso_now(),
        }
        extra["deception"] = deception_payload
        write_extra(session, extra)
        applied.append("SERVE_DECEPTION")

    session.is_contained = True
    session.trust_state = "CONTAINED"
    session.trust_state_since = _utc_now()
    await db.flush()

    incident_id = None
    if payload.open_incident:
        incident = await _open_manual_incident(
            db,
            integration.tenant_id,
            session=session,
            title=f"Session contained: {payload.reason or 'suspected compromise'}",
            severity="CRITICAL",
            description=(
                f"Session {session_id} was contained. Reason: {payload.reason or 'not supplied'}. "
                f"Applied: {', '.join(applied)}."
            ),
            actions=applied,
        )
        incident_id = incident.id if incident else None
        applied.append("OPEN_INCIDENT")

    await db.commit()
    return {
        "session_id": session.session_id,
        "status": session.status,
        "trust_state": session.trust_state,
        "tci": session.tci,
        "is_contained": True,
        "applied": applied,
        "incident_id": incident_id,
        "token_invalidated": True,
        "device_flagged": device_flagged,
        "deception": deception_payload,
        "reason": payload.reason,
    }


# --------------------------------------------------------------------- receipts
@router.get(
    "/receipts/{receipt_id}", response_model=ReceiptResponse, summary="Fetch a Trust Receipt"
)
async def get_receipt(
    receipt_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Returns the receipt explaining one authorization decision."""
    service = ReceiptService(db, integration.tenant_id)
    receipt = await service.get(receipt_id)
    if receipt is None:
        raise TrustPulseException(f"Receipt '{receipt_id}' not found", status_code=404)
    return ReceiptService.to_public_dict(receipt)


@router.post(
    "/receipts/{receipt_id}/verify",
    response_model=ReceiptVerifyResponse,
    summary="Verify a Trust Receipt's integrity and binding",
)
async def verify_receipt(
    receipt_id: str,
    request: Optional[ReceiptVerifyRequest] = None,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Recomputes the receipt hash and checks binding, expiry and revocation.

    Returns a structured result rather than raising: an invalid receipt is a
    normal, expected outcome the caller must be able to report.
    """
    payload = request or ReceiptVerifyRequest()
    service = ReceiptService(db, integration.tenant_id)
    verification = await service.verify(
        receipt_id,
        presented=payload.presented,
        check_binding=payload.check_binding,
        mark_used=payload.mark_used,
    )
    await db.commit()
    return verification.to_dict()


# --------------------------------------------------------------------- incidents
@router.get("/incidents", response_model=List[IncidentResponse], summary="List security incidents")
async def list_incidents(
    status: Optional[str] = Query(
        None, description="OPEN | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE"
    ),
    session_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    service = IncidentService(db, integration.tenant_id)
    incidents = await service.list_incidents(
        status=status, session_id=session_id, severity=severity, limit=limit
    )
    return [IncidentService.to_dict(item) for item in incidents]


@router.get(
    "/incidents/{incident_id}", response_model=IncidentResponse, summary="Fetch one incident"
)
async def get_incident(
    incident_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    service = IncidentService(db, integration.tenant_id)
    incident = await service.get(incident_id)
    if incident is None:
        raise TrustPulseException(f"Incident '{incident_id}' not found", status_code=404)
    return IncidentService.to_dict(incident)


@router.patch(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
    summary="Update an incident's status",
)
async def update_incident(
    incident_id: str,
    request: IncidentUpdateRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Moves an incident through its lifecycle.

    Closing an incident unblocks trust recovery and baseline promotion for the
    affected user, which is why it is an explicit operator act.
    """
    service = IncidentService(db, integration.tenant_id)
    try:
        incident = await service.update_status(
            incident_id,
            request.status,
            note=request.note,
            closed_by=request.closed_by,
        )
    except ValueError as exc:
        raise TrustPulseException(str(exc), status_code=422) from exc
    if incident is None:
        raise TrustPulseException(f"Incident '{incident_id}' not found", status_code=404)
    await db.commit()
    return IncidentService.to_dict(incident)


# ----------------------------------------------------------------------- posture
@router.get("/security/posture", response_model=PostureResponse, summary="Tenant security posture")
async def security_posture(
    window_hours: int = Query(24, ge=1, le=720),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Derived tenant-wide posture. Never stored, so it cannot go stale."""
    service = SecurityPostureService(db, integration.tenant_id)
    report = await service.report(window_hours=window_hours)
    return report.to_dict()


@router.get(
    "/config/policy",
    response_model=PolicyConfigResponse,
    summary="Live authorization policy",
)
async def get_policy(
    integration: IntegrationContext = Depends(get_integration_context),
) -> Dict[str, Any]:
    """The rules actually in force, so any decision can be audited against them."""
    config = get_trust_config()
    auth = config.authorization()
    return {
        "policy_version": config.policy_version,
        "default_decision": str(auth.get("default_decision", "ALLOW")),
        "terminal_trust_states": config.terminal_trust_states,
        "tci_block_floor": config.tci_block_floor,
        "tci_block_floor_min_risk": config.tci_block_floor_min_risk,
        "rules": config.policy_rules(),
        "step_up": config.step_up(),
        "receipts": config.receipts_config(),
        "containment": config.containment(),
        "disclaimer": (
            "Authorization is decided by this server-side policy, evaluated by the Policy "
            "Enforcement Point. No AI/ML component authorizes anything. TCI is an engineering "
            "trust index, not a probability."
        ),
    }


@router.get("/actions/policy-rules", summary="Policy rules in evaluation order")
async def policy_rules(
    integration: IntegrationContext = Depends(get_integration_context),
) -> Dict[str, Any]:
    """Rules in evaluation order. First match wins, so order is semantic."""
    config = get_trust_config()
    return {
        "policy_version": config.policy_version,
        "evaluation": "first-match-wins",
        "rules": config.policy_rules(),
        "valid_decisions": ["ALLOW", "STEP_UP", "BLOCK", "REVOKE", "CONTAIN"],
        "incident_statuses": list(OPEN_STATUSES + CLOSED_STATUSES),
    }


# --------------------------------------------------------------------- internals
def _utc_now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat()


async def _open_manual_incident(
    db: AsyncSession,
    tenant_id: str,
    *,
    session: SessionModel,
    title: str,
    severity: str,
    description: str,
    actions: List[str],
):
    """Opens (or reuses) an incident for an operator-initiated control action."""
    from sqlalchemy import select

    from app.models.platform_incident import PlatformIncidentModel

    result = await db.execute(
        select(PlatformIncidentModel)
        .where(
            PlatformIncidentModel.customer_tenant_id == tenant_id,
            PlatformIncidentModel.session_id == session.session_id,
            PlatformIncidentModel.status.in_(OPEN_STATUSES),
        )
        .order_by(PlatformIncidentModel.opened_at.desc())
        .limit(1)
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        notes = list(existing.containment_actions or [])
        notes.extend(actions)
        existing.containment_actions = notes
        existing.updated_at = _utc_now()
        await db.flush()
        return existing

    incident = PlatformIncidentModel(
        customer_tenant_id=tenant_id,
        session_id=session.session_id,
        user_id=session.user_ref_id,
        device_id=session.device_ref_id,
        severity=severity,
        title=title,
        description=description,
        status="OPEN",
        tci_at_detection=session.tci,
        trust_state_at_detection=session.trust_state,
        containment_actions=list(actions),
        opened_at=_utc_now(),
    )
    db.add(incident)
    await db.flush()
    return incident


__all__ = ["router"]
