"""
TrustPulse AI — Incident API Routes.

Incidents reference security decisions and session evidence; they do not store
duplicate telemetry payloads.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.exceptions import TrustPulseException
from app.models.base import get_db_session
from app.schemas.incident import IncidentListResponse, IncidentResolveRequest, IncidentResponse
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    session_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """List incident records for the authenticated tenant."""
    svc = IncidentService(db, integration.tenant_id, integration)
    items = await svc.list_incidents(session_id=session_id, limit=limit)
    return IncidentListResponse(
        items=[IncidentResponse.model_validate(i) for i in items], total=len(items)
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve one incident record."""
    svc = IncidentService(db, integration.tenant_id, integration)
    incident = await svc.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found") from None
    return IncidentResponse.model_validate(incident)


@router.post("/{incident_id}/resolve", response_model=IncidentResponse)
async def resolve_incident(
    incident_id: str,
    body: IncidentResolveRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Resolve an open incident and emit an audit event."""
    try:
        svc = IncidentService(db, integration.tenant_id, integration)
        incident = await svc.resolve_incident(incident_id, resolution_notes=body.resolution_notes)
        await db.commit()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found") from None
        return IncidentResponse.model_validate(incident)
    except TrustPulseException as e:
        await db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message) from None
