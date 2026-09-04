"""
TrustPulse AI - Telemetry Ingestion API Routes
"""

from fastapi import APIRouter, Depends, Header, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import get_db_session
from app.services.telemetry_service import TelemetryService
from app.schemas.telemetry import TelemetryBatchSchema, TelemetryIngestionResponse
from app.core.exceptions import (
    TrustPulseException,
    SessionNotFoundException,
    RateLimitExceededException,
)
from app.core.config import settings

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


def get_tenant_id(x_trustpulse_tenant_id: str = Header(..., alias="X-TrustPulse-Tenant-Id")) -> str:
    return x_trustpulse_tenant_id


@router.post("/batch", response_model=TelemetryIngestionResponse, status_code=202)
async def ingest_telemetry_batch(
    request: Request,
    body: TelemetryBatchSchema,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Ingest a telemetry batch from the TrustPulse SDK.

    Performs per-packet replay detection, clock-skew validation,
    sequence monotonicity enforcement, integrity verification,
    and DB persistence.
    """
    # Payload size guard
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")

    try:
        svc = TelemetryService(db, tenant_id)
        result = await svc.ingest_batch(body)
        await db.commit()
        return result
    except RateLimitExceededException as e:
        raise HTTPException(status_code=429, detail=e.message)
    except SessionNotFoundException as e:
        await db.rollback()
        raise HTTPException(status_code=404, detail=e.message)
    except TrustPulseException as e:
        await db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
