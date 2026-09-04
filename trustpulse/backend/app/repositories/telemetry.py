"""
TrustPulse AI — Telemetry Repository.
"""

from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import utc_now
from app.models.telemetry import TelemetryEventModel
from app.repositories.base import BaseRepository


class TelemetryRepository(BaseRepository[TelemetryEventModel]):
    def __init__(self, session: AsyncSession, tenant_id: str):
        super().__init__(TelemetryEventModel, session, tenant_id)

    async def get_by_event_id(self, event_id: str) -> Optional[TelemetryEventModel]:
        stmt = select(TelemetryEventModel).where(
            TelemetryEventModel.event_id == event_id,
            TelemetryEventModel.customer_tenant_id == self.tenant_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def record_event(
        self,
        event_id: str,
        session_id: str,
        sdk_instance_id: str,
        sequence_number: int,
        timestamp: int,
        schema_version: str,
        feature_payload: Dict[str, Any],
        validation_status: str = "VALID",
        rejection_reason: Optional[str] = None,
    ) -> TelemetryEventModel:
        model = TelemetryEventModel(
            event_id=event_id,
            customer_tenant_id=self.tenant_id,
            session_id=session_id,
            sdk_instance_id=sdk_instance_id,
            sequence_number=sequence_number,
            timestamp=timestamp,
            schema_version=schema_version,
            feature_payload=feature_payload,
            received_at=utc_now(),
            validation_status=validation_status,
            rejection_reason=rejection_reason,
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def get_session_events(
        self, session_id: str, limit: int = 100
    ) -> List[TelemetryEventModel]:
        stmt = (
            select(TelemetryEventModel)
            .where(
                TelemetryEventModel.session_id == session_id,
                TelemetryEventModel.customer_tenant_id == self.tenant_id,
            )
            .order_by(TelemetryEventModel.sequence_number.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_session_events(self, session_id: str) -> int:
        stmt = select(func.count(TelemetryEventModel.id)).where(
            TelemetryEventModel.session_id == session_id,
            TelemetryEventModel.customer_tenant_id == self.tenant_id,
        )
        result = await self.session.execute(stmt)
        return int(result.scalar() or 0)
