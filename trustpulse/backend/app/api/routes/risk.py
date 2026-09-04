"""
TrustPulse AI - Risk Evaluation API Routes
"""

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import get_db_session
from app.services.risk_service import RiskService
from app.schemas.risk import RiskEvaluationRequest, RiskEvaluationResponse
from app.core.exceptions import SessionNotFoundException, TrustPulseException

router = APIRouter(prefix="/risk", tags=["Risk"])


def get_tenant_id(x_trustpulse_tenant_id: str = Header(..., alias="X-TrustPulse-Tenant-Id")) -> str:
    return x_trustpulse_tenant_id


@router.post("/evaluate", response_model=RiskEvaluationResponse, status_code=200)
async def evaluate_action_risk(
    body: RiskEvaluationRequest,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Evaluate the risk of a high-sensitivity action against the current session security posture.

    Returns a deterministic security decision:
    - **ALLOW**: Session confidence is sufficient for this action risk level.
    - **STEP_UP**: Trigger additional authentication (MFA/biometric challenge).
    - **BLOCK**: Action is blocked; session may continue.
    - **ISOLATE**: Session is terminated and quarantined; re-authentication required.
    """
    try:
        svc = RiskService(db, tenant_id)
        result = await svc.evaluate(body)
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
