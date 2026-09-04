"""
TrustPulse AI - Session API Routes
"""

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import get_db_session
from app.services.session_service import SessionService
from app.schemas.session import SessionCreate, SessionResponse, SessionStatusUpdate
from app.core.exceptions import SessionNotFoundException, TrustPulseException
from app.core.config import settings

router = APIRouter(prefix="/sessions", tags=["Sessions"])


def get_tenant_id(x_trustpulse_tenant_id: str = Header(..., alias="X-TrustPulse-Tenant-Id")) -> str:
    return x_trustpulse_tenant_id


@router.post("", response_model=SessionResponse, status_code=201)
async def register_session(
    body: SessionCreate,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db_session),
):
    """Register a new TrustPulse session for an authenticated application session."""
    try:
        svc = SessionService(db, tenant_id)
        result = await svc.register_session(body)
        await db.commit()
        return result
    except TrustPulseException as e:
        await db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve the current state of a TrustPulse session."""
    try:
        svc = SessionService(db, tenant_id)
        return await svc.get_session(session_id)
    except SessionNotFoundException as e:
        raise HTTPException(status_code=404, detail=e.message)
    except TrustPulseException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.patch("/{session_id}/status", response_model=SessionResponse)
async def update_session_status(
    session_id: str,
    body: SessionStatusUpdate,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db_session),
):
    """Update a session's status (ACTIVE, PAUSED, TERMINATED, ISOLATED)."""
    try:
        svc = SessionService(db, tenant_id)
        result = await svc.update_session_status(session_id, body)
        await db.commit()
        return result
    except SessionNotFoundException as e:
        raise HTTPException(status_code=404, detail=e.message)
    except TrustPulseException as e:
        await db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
