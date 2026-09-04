"""
TrustPulse AI - Incident Repository
"""

from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.incident import IncidentModel
from app.repositories.base import BaseRepository
from app.models.base import utc_now


class IncidentRepository(BaseRepository[IncidentModel]):
    def __init__(self, session: AsyncSession, tenant_id: str):
        super().__init__(IncidentModel, session, tenant_id)

    async def get_by_incident_id(self, incident_id: str) -> Optional[IncidentModel]:
        stmt = select(IncidentModel).where(
            IncidentModel.incident_id == incident_id,
            IncidentModel.customer_tenant_id == self.tenant_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create_incident(
        self,
        session_id: str,
        severity: str,
        trigger_reason: str,
        decision_id: Optional[str] = None,
    ) -> IncidentModel:
        model = IncidentModel(
            customer_tenant_id=self.tenant_id,
            session_id=session_id,
            severity=severity,
            status="OPEN",
            trigger_reason=trigger_reason,
            decision_id=decision_id,
            created_at=utc_now(),
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def list_incidents(self, session_id: Optional[str] = None, limit: int = 50) -> List[IncidentModel]:
        stmt = select(IncidentModel).where(IncidentModel.customer_tenant_id == self.tenant_id)
        if session_id:
            stmt = stmt.where(IncidentModel.session_id == session_id)
        stmt = stmt.order_by(IncidentModel.created_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def resolve_incident(self, incident_id: str) -> Optional[IncidentModel]:
        incident = await self.get_by_incident_id(incident_id)
        if incident:
            incident.status = "RESOLVED"
            incident.resolved_at = utc_now()
            await self.session.flush()
        return incident

    async def get_open_incidents(self, session_id: str) -> List[IncidentModel]:
        """Returns all unresolved incidents for a session."""
        stmt = (
            select(IncidentModel)
            .where(
                IncidentModel.customer_tenant_id == self.tenant_id,
                IncidentModel.session_id == session_id,
                IncidentModel.status == "OPEN",
            )
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

