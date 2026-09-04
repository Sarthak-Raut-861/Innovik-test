"""
TrustPulse AI - Immutable Audit Log Repository
"""

from typing import Optional, List, Dict, Any
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_log import AuditLogModel
from app.models.base import utc_now


class AuditRepository:
    def __init__(self, session: AsyncSession, tenant_id: str):
        self.session = session
        self.tenant_id = tenant_id

    async def log_event(
        self,
        event_type: str,
        actor_type: str = "SYSTEM",
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        metadata_payload: Optional[Dict[str, Any]] = None,
    ) -> AuditLogModel:
        model = AuditLogModel(
            customer_tenant_id=self.tenant_id,
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata_payload=metadata_payload or {},
            timestamp=utc_now(),
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def list_audit_logs(self, limit: int = 100) -> List[AuditLogModel]:
        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.customer_tenant_id == self.tenant_id)
            .order_by(AuditLogModel.timestamp.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
