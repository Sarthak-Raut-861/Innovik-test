"""TRUSTPULSE platform API — sessions, telemetry, trust evaluation, configuration.

Mounted at ``/api/v1``. This is the surface an integrating application (TrustDev)
and the SOC dashboard talk to.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.trust_config import get_trust_config
from app.models.base import get_db_session
from app.schemas.platform import (
    LoginRequest,
    LoginResponse,
    SessionCreateRequest,
    SessionResponse,
    TelemetryRequest,
    TelemetryResponse,
    TrustEvaluateRequest,
)
from app.schemas.trust import TrustModelInfo, TrustResult
from app.services.action_risk.catalogue import RISK_BANDS, ActionRiskCatalogue
from app.services.platform.identity_service import IdentityService
from app.services.platform.trust_service import TrustService

router = APIRouter(tags=["TRUSTPULSE Platform"])


# ------------------------------------------------------------------ authentication
@router.post("/auth/login", response_model=LoginResponse, summary="TrustDev simulated login")
async def login(
    request: LoginRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> LoginResponse:
    """Authenticates a user in the simulated TrustDev app and opens a trusted session.

    Passwords are verified against a salted digest and are never stored or logged.
    TRUSTPULSE records *how* the user authenticated; it does not replace MFA.
    """
    service = IdentityService(db, integration.tenant_id)
    return await service.login(request)


# ---------------------------------------------------------------------- sessions
@router.post("/session", response_model=SessionResponse, summary="Register a session")
async def create_session(
    request: SessionCreateRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> SessionResponse:
    """Opens a TRUSTPULSE session for an already-authenticated user."""
    service = IdentityService(db, integration.tenant_id)
    return await service.create_session(request)


@router.post("/session/{session_id}/end", response_model=SessionResponse, summary="End a session")
async def end_session(
    session_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> SessionResponse:
    """Ends a session. This is an application lifecycle event, not an idle timeout."""
    service = IdentityService(db, integration.tenant_id)
    return await service.end_session(session_id)


# --------------------------------------------------------------------- telemetry
@router.post("/telemetry", response_model=TelemetryResponse, summary="Ingest derived telemetry")
async def ingest_telemetry(
    request: TelemetryRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> TelemetryResponse:
    """Accepts privacy-minimized derived features and recomputes session trust.

    Typed characters and raw events are rejected server-side; only aggregate
    statistics (means, standard deviations, rates) are accepted.
    """
    service = TrustService(db, integration.tenant_id)
    return await service.ingest_telemetry(request)


# ------------------------------------------------------------------------- trust
@router.post("/trust/evaluate", response_model=TrustResult, summary="Evaluate session trust")
async def evaluate_trust(
    request: TrustEvaluateRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> TrustResult:
    """Forces a fresh TCI evaluation for a session."""
    service = TrustService(db, integration.tenant_id)
    return await service.evaluate(request)


@router.get("/trust/{session_id}", response_model=TrustResult, summary="Current session trust")
async def get_trust(
    session_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> TrustResult:
    """Returns the current TCI, state, factor breakdown and evidence."""
    service = TrustService(db, integration.tenant_id)
    return await service.get_trust(session_id)


@router.get("/trust/{session_id}/history", summary="TCI history for a session")
async def trust_history(
    session_id: str,
    limit: int = Query(default=200, ge=1, le=1000),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Time series of TCI samples plus the trust-state transition timeline."""
    service = TrustService(db, integration.tenant_id)
    return await service.get_history(session_id, limit=limit)


# ------------------------------------------------------------------- transparency
@router.get("/config/trust-model", response_model=TrustModelInfo, summary="Active trust model")
async def trust_model_config(
    integration: IntegrationContext = Depends(get_integration_context),
) -> TrustModelInfo:
    """Exposes the live weights, thresholds and hysteresis settings.

    Transparency is part of the product: an analyst must be able to see which
    parameters produced a decision.
    """
    config = get_trust_config()
    return TrustModelInfo(
        schema_version=config.schema_version,
        source=config.source,
        weights=config.weights,
        state_bands=config.state_bands(),
        hysteresis=config.hysteresis(),
        action_risk_profiles=config.action_profiles(),
        evidence_types=config.evidence_types(),
    )


@router.get("/config/actions", summary="Action risk catalogue")
async def action_catalogue(
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Effective action risk catalogue, including tenant overrides."""
    catalogue = await ActionRiskCatalogue(db=db, tenant_id=integration.tenant_id).load_overrides()
    return {
        "actions": catalogue.catalogue(),
        "bands": [{"min_risk": threshold, "band": label} for threshold, label in RISK_BANDS],
        "note": (
            "Risk describes the action, not the user. Authorization combines this "
            "with session trust in the policy engine."
        ),
    }


@router.get("/actions/known", summary="Known action names")
async def known_actions(
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, List[str]]:
    catalogue = await ActionRiskCatalogue(db=db, tenant_id=integration.tenant_id).load_overrides()
    return {"actions": catalogue.known_actions()}
