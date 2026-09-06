"""TRUSTPULSE platform API — SOC dashboard read models, users and devices."""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.config import settings
from app.core.redis import redis_manager
from app.core.trust_config import get_trust_config
from app.models.base import get_db_session
from app.repositories.platform import PlatformRepository, utcnow
from app.schemas.platform import (
    DeviceSummary,
    HealthResponse,
    SocOverview,
    SocSessionDetail,
    SocSessionSummary,
    UserSummary,
)
from app.services.platform.trust_service import TrustService

router = APIRouter(tags=["TRUSTPULSE SOC"])


@router.get("/soc/overview", response_model=SocOverview, summary="SOC headline metrics")
async def soc_overview(
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> SocOverview:
    """Active / suspicious sessions, incidents, average TCI, blocked actions."""
    service = TrustService(db, integration.tenant_id)
    return await service.soc_overview()


@router.get("/soc/sessions", response_model=List[SocSessionSummary], summary="SOC session table")
async def soc_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> List[SocSessionSummary]:
    service = TrustService(db, integration.tenant_id)
    return await service.soc_sessions(limit=limit)


@router.get(
    "/soc/sessions/{session_id}", response_model=SocSessionDetail, summary="SOC session detail"
)
async def soc_session_detail(
    session_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> SocSessionDetail:
    """Full analyst view: TCI history, factors, evidence, actions, baselines."""
    service = TrustService(db, integration.tenant_id)
    return await service.soc_session_detail(session_id)


@router.get("/users", response_model=List[UserSummary], summary="Users")
async def list_users(
    limit: int = Query(default=100, ge=1, le=500),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> List[UserSummary]:
    repo = PlatformRepository(db, integration.tenant_id)
    return [UserSummary.model_validate(user) for user in await repo.list_users(limit=limit)]


@router.get("/devices", response_model=List[DeviceSummary], summary="Devices")
async def list_devices(
    limit: int = Query(default=100, ge=1, le=500),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
) -> List[DeviceSummary]:
    repo = PlatformRepository(db, integration.tenant_id)
    return [DeviceSummary.model_validate(device) for device in await repo.list_devices(limit=limit)]


@router.get("/platform/health", response_model=HealthResponse, summary="Platform health")
async def platform_health(db: AsyncSession = Depends(get_db_session)) -> HealthResponse:
    """Liveness/readiness for the TRUSTPULSE platform API."""
    database = "ok"
    try:
        await PlatformRepository(db, "health-check").soc_overview()
    except Exception:  # pragma: no cover - defensive
        database = "degraded"
    redis = "fallback" if redis_manager.is_fallback else "ok"
    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        product=settings.PROJECT_NAME,
        version=settings.VERSION,
        trust_model_version=get_trust_config().schema_version,
        database=database,
        redis=redis,
        time=utcnow(),
    )
