"""
TrustPulse AI — Session API Routes.

Authentication: customer server-side API key (Bearer or X-TrustPulse-API-Key),
or X-TrustPulse-Public-Key for read-only SDK-facing operations in dev modes.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.exceptions import (
    SessionNotFoundException,
    TrustPulseException,
)
from app.models.base import get_db_session
from app.schemas.session import SessionCreate, SessionResponse, SessionStatusUpdate
from app.services.session_service import SessionService

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.post("", response_model=SessionResponse, status_code=201)
async def register_session(
    body: SessionCreate,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Register a new TrustPulse session for an authenticated application session."""
    svc = SessionService(db, integration.tenant_id, integration)
    result = await svc.register_session(body)
    await db.commit()
    return result


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve the current state of a TrustPulse session."""
    try:
        svc = SessionService(db, integration.tenant_id, integration)
        return await svc.get_session(session_id)
    except SessionNotFoundException as e:
        from fastapi import HTTPException

        raise HTTPException(status_code=e.status_code, detail=e.message) from None


@router.patch("/{session_id}/status", response_model=SessionResponse)
async def update_session_status(
    session_id: str,
    body: SessionStatusUpdate,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Update a session's status (ACTIVE, PAUSED, TERMINATED, ISOLATED)."""
    svc = SessionService(db, integration.tenant_id, integration)
    try:
        result = await svc.update_session_status(session_id, body)
        await db.commit()
        return result
    except TrustPulseException as e:
        await db.rollback()
        from fastapi import HTTPException

        raise HTTPException(status_code=e.status_code, detail=e.message) from None
