"""
TrustPulse AI - Risk and Security Decision Repository
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.risk_assessment import RiskAssessmentModel
from app.models.action_request import ActionRequestModel
from app.models.security_decision import SecurityDecisionModel
from app.models.base import utc_now


class RiskRepository:
    def __init__(self, session: AsyncSession, tenant_id: str):
        self.session = session
        self.tenant_id = tenant_id

    async def record_assessment(
        self,
        session_id: str,
        behavior_signal: float,
        device_signal: float,
        network_signal: float,
        session_history_signal: float,
        session_confidence: int,
        confidence_level: str,
    ) -> RiskAssessmentModel:
        model = RiskAssessmentModel(
            customer_tenant_id=self.tenant_id,
            session_id=session_id,
            behavior_signal=behavior_signal,
            device_signal=device_signal,
            network_signal=network_signal,
            session_history_signal=session_history_signal,
            session_confidence=session_confidence,
            confidence_level=confidence_level,
            created_at=utc_now(),
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def get_latest_assessment(self, session_id: str) -> Optional[RiskAssessmentModel]:
        stmt = (
            select(RiskAssessmentModel)
            .where(
                RiskAssessmentModel.customer_tenant_id == self.tenant_id,
                RiskAssessmentModel.session_id == session_id,
            )
            .order_by(RiskAssessmentModel.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def record_action_request(
        self,
        session_id: str,
        action_type: str,
        risk_level: str,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> ActionRequestModel:
        model = ActionRequestModel(
            customer_tenant_id=self.tenant_id,
            session_id=session_id,
            action_type=action_type,
            risk_level=risk_level,
            amount=amount,
            currency=currency,
            resource_type=resource_type,
            resource_id=resource_id,
            created_at=utc_now(),
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def record_decision(
        self,
        session_id: str,
        decision: str,
        reason_codes: List[str],
        action_id: Optional[str] = None,
        policy_version: str = "v1",
        policy_rule_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> SecurityDecisionModel:
        model = SecurityDecisionModel(
            customer_tenant_id=self.tenant_id,
            session_id=session_id,
            action_id=action_id,
            decision=decision,
            reason_codes=reason_codes,
            policy_version=policy_version,
            policy_rule_id=policy_rule_id,
            created_at=utc_now(),
            expires_at=expires_at,
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def get_latest_decision(self, session_id: str) -> Optional[SecurityDecisionModel]:
        stmt = (
            select(SecurityDecisionModel)
            .where(
                SecurityDecisionModel.customer_tenant_id == self.tenant_id,
                SecurityDecisionModel.session_id == session_id,
            )
            .order_by(SecurityDecisionModel.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()
