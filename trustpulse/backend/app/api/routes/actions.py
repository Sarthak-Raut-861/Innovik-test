"""
TrustPulse AI — Action API Routes.

Actions are financial-vertical-agnostic security primitives. The core engine
categorizes generic action types; a customer's policy layer can map its own
application actions to these risk categories.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.models.base import get_db_session
from app.schemas.action import ActionResponse
from app.services.action_risk_service import ActionRiskService

router = APIRouter(prefix="/actions", tags=["Actions"])


@router.get("", response_model=List[ActionResponse])
async def list_actions(
    session_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """List action request records for the authenticated tenant."""
    svc = ActionRiskService(db, integration.tenant_id, integration)
    items = await svc.list_actions(session_id=session_id, limit=limit)
    return [ActionResponse.model_validate(item) for item in items]


@router.get("/catalog", response_model=dict)
async def action_catalog():
    """Expose the generic built-in action risk catalog (used for policy mapping)."""
    service = ActionRiskService(None, "", None)
    return {"actions": {k: v.value for k, v in service.get_catalog().items()}}


@router.get("/{action_id}", response_model=ActionResponse)
async def get_action(
    action_id: str,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieve one action request record."""
    svc = ActionRiskService(db, integration.tenant_id, integration)
    action = await svc.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return ActionResponse.model_validate(action)
