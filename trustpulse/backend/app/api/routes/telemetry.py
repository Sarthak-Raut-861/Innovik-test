"""
TrustPulse AI — Telemetry Ingestion Routes.

The @trustpulse/sdk posts a TelemetryBatch to POST /v1/telemetry. The route also
accepts /v1/telemetry/batch for backward compatibility.

Authentication: X-TrustPulse-Public-Key (non-secret SDK identification),
binding the session and tenant server-side.
"""

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.config import settings
from app.core.exceptions import (
    RateLimitExceededException,
    SecurityServiceUnavailableException,
    TrustPulseException,
)
from app.models.base import get_db_session
from app.schemas.telemetry import TelemetryBatchSchema, TelemetryIngestionResponse
from app.services.telemetry_service import TelemetryService

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


async def _ingest(
    body: TelemetryBatchSchema,
    integration: IntegrationContext,
    db: AsyncSession,
    sdk_session_header: str | None,
) -> TelemetryIngestionResponse:
    try:
        svc = TelemetryService(db, integration.tenant_id, integration)
        result = await svc.ingest_batch(body, sdk_session_header=sdk_session_header)
        await db.commit()
        return result
    except RateLimitExceededException as e:
        await db.rollback()
        raise HTTPException(status_code=429, detail=e.message) from None
    except SecurityServiceUnavailableException as e:
        await db.rollback()
        raise HTTPException(status_code=503, detail=e.message) from None
    except TrustPulseException as e:
        await db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message) from None
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Telemetry ingestion failed") from None


@router.post("", response_model=TelemetryIngestionResponse, status_code=202)
async def ingest_telemetry(
    body: TelemetryBatchSchema,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
    x_trustpulse_session_id: str | None = Header(default=None, alias="X-TrustPulse-Session-Id"),
):
    """
    Ingest a telemetry batch from the TrustPulse SDK.

    Validation performed server-side:
      * tenant/binding
      * session existence and state
      * schema version
      * event ID uniqueness (replay protection)
      * sequence monotonicity
      * clock skew / freshness
      * feature ranges and NaN/Infinity
      * payload size / batch size limits
      * integrity checksum advisory check

    The SDK's client-side checksum is advisory only; a compromised browser can
    forge it. No client-provided risk score is ever accepted.
    """
    if len(body.packets) > settings.MAX_BATCH_PACKETS:
        raise HTTPException(status_code=422, detail="Batch contains too many packets") from None
    return await _ingest(body, integration, db, x_trustpulse_session_id)


@router.post("/batch", response_model=TelemetryIngestionResponse, status_code=202)
async def ingest_telemetry_batch_alias(
    body: TelemetryBatchSchema,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
    x_trustpulse_session_id: str | None = Header(default=None, alias="X-TrustPulse-Session-Id"),
):
    """Backward-compatible alias for POST /v1/telemetry/batch."""
    if len(body.packets) > settings.MAX_BATCH_PACKETS:
        raise HTTPException(status_code=422, detail="Batch contains too many packets") from None
    return await _ingest(body, integration, db, x_trustpulse_session_id)
