"""
TrustPulse AI - Session Repository
"""

from typing import Optional
from datetime import datetime, timezone
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.session import SessionModel
from app.repositories.base import BaseRepository
from app.models.base import utc_now


class SessionRepository(BaseRepository[SessionModel]):
    def __init__(self, session: AsyncSession, tenant_id: str):
        super().__init__(SessionModel, session, tenant_id)

    async def get_by_session_id(self, session_id: str) -> Optional[SessionModel]:
        stmt = select(SessionModel).where(
            SessionModel.session_id == session_id,
            SessionModel.customer_tenant_id == self.tenant_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create_session(
        self,
        session_id: str,
        subject_id: Optional[str] = None,
        device_id: Optional[str] = None,
        sdk_instance_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> SessionModel:
        model = SessionModel(
            session_id=session_id,
            customer_tenant_id=self.tenant_id,
            subject_id=subject_id,
            device_id=device_id,
            sdk_instance_id=sdk_instance_id,
            status="ACTIVE",
            created_at=utc_now(),
            last_seen_at=utc_now(),
            expires_at=expires_at,
        )
        self.session.add(model)
        await self.session.flush()
        return model

    async def update_last_seen(self, session_id: str) -> None:
        stmt = (
            update(SessionModel)
            .where(
                SessionModel.session_id == session_id,
                SessionModel.customer_tenant_id == self.tenant_id,
            )
            .values(last_seen_at=utc_now())
        )
        await self.session.execute(stmt)

    async def update_status(self, session_id: str, status: str) -> Optional[SessionModel]:
        sess = await self.get_by_session_id(session_id)
        if sess:
            sess.status = status
            sess.last_seen_at = utc_now()
            await self.session.flush()
        return sess
