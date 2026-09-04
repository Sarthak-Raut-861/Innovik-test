"""
TrustPulse AI — Health, Readiness & Metrics Routes.

These endpoints expose only operational state. No telemetry, sessions, or
customer data is exposed here.
"""

import time

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.metrics import metrics
from app.core.redis import redis_manager
from app.models.base import get_db_session

router = APIRouter(prefix="/health", tags=["Health"])

_START_TIME = time.time()


class HealthResponse(BaseModel):
    status: str = Field(..., description="ok or degraded")
    version: str
    environment: str
    uptime_seconds: float
    redis_mode: str
    redis_replay_durable: bool
    redis_queue_available: bool
    database_ok: bool


class ReadyResponse(BaseModel):
    status: str
    dependencies: dict


class MetricsResponse(BaseModel):
    counters: dict
    uptime_seconds: float


@router.get("", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db_session)):
    """Health & liveness check. Returns degraded rather than failing when Redis is absent."""
    database_ok = await _check_database(db)
    status = "ok" if database_ok else "degraded"
    return HealthResponse(
        status=status,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        uptime_seconds=round(time.time() - _START_TIME, 2),
        redis_mode="external" if not redis_manager.is_fallback else "fallback",
        redis_replay_durable=redis_manager.replay_durable,
        redis_queue_available=redis_manager.queue_available,
        database_ok=database_ok,
    )


@router.get("/ready", response_model=ReadyResponse)
async def readiness_check(db: AsyncSession = Depends(get_db_session)):
    """
    Readiness probe for orchestrators.

    Requires PostgreSQL to be reachable. Redis is optional because the backend
    degrades safely, but ready reports its availability so operators can react.
    """
    database_ok = await _check_database(db)
    status = "ready" if database_ok else "not_ready"
    return ReadyResponse(
        status=status,
        dependencies={
            "database": database_ok,
            "redis_external": not redis_manager.is_fallback,
        },
    )


@router.get("/metrics", response_model=MetricsResponse)
async def metrics_endpoint(request: Request):
    """Exposes non-sensitive operational counters."""
    if not settings.METRICS_ENABLED:
        from fastapi import HTTPException

        raise HTTPException(status_code=404)
    snapshot = metrics.snapshot()
    counters = snapshot.get("counters", {})
    uptime = snapshot.get("uptime_seconds", 0.0)
    if not isinstance(counters, dict):
        counters = {}
    if not isinstance(uptime, (int, float)):
        uptime = 0.0
    return MetricsResponse(
        counters=counters,
        uptime_seconds=float(uptime),
    )


async def _check_database(db: AsyncSession) -> bool:
    try:
        await db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
