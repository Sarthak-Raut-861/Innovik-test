"""
TrustPulse AI - Health & Liveness Routes
"""

import time
from fastapi import APIRouter
from pydantic import BaseModel
from app.core.config import settings
from app.core.redis import redis_manager

router = APIRouter(prefix="/health", tags=["Health"])


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    redis_mode: str
    uptime_seconds: float


_START_TIME = time.time()


@router.get("", response_model=HealthResponse)
async def health_check():
    """Health & liveness check endpoint."""
    redis_client = await redis_manager.get_client()
    redis_mode = "fallback" if redis_manager.is_fallback else "external"

    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        redis_mode=redis_mode,
        uptime_seconds=round(time.time() - _START_TIME, 2),
    )


@router.get("/ready")
async def readiness_check():
    """Readiness probe for orchestrators (k8s, etc.)."""
    return {"status": "ready"}
