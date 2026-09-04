"""
TrustPulse AI — Risk Evaluation API Routes.

Synchronous, deterministic evaluation of an action for a live session.

Authentication: server-side customer API key (or dev fallback).
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext, get_integration_context
from app.core.exceptions import (
    RateLimitExceededException,
    SecurityServiceUnavailableException,
    SessionNotFoundException,
    TrustPulseException,
)
from app.models.base import get_db_session
from app.schemas.risk import RiskEvaluationRequest, RiskEvaluationResponse
from app.services.risk_service import RiskService

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.post("/evaluate", response_model=RiskEvaluationResponse, status_code=200)
async def evaluate_action_risk(
    body: RiskEvaluationRequest,
    integration: IntegrationContext = Depends(get_integration_context),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Evaluate the risk of a sensitive action against the session's current posture.

    Pipeline:
      session lookup → behavioral anomaly evidence → signal fusion →
      session confidence → action risk → policy engine → deterministic decision.

    Decisions: ALLOW, STEP_UP, BLOCK, ISOLATE.
    """
    try:
        svc = RiskService(db, integration.tenant_id, integration)
        result = await svc.evaluate(body)
        await db.commit()
        return result
    except SessionNotFoundException as e:
        raise HTTPException(status_code=404, detail=e.message) from None
    except RateLimitExceededException as e:
        raise HTTPException(status_code=429, detail=e.message) from None
    except SecurityServiceUnavailableException as e:
        await db.rollback()
        raise HTTPException(status_code=503, detail=e.message) from None
    except TrustPulseException as e:
        await db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message) from None
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e)) from None
