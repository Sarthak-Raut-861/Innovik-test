"""
TrustPulse AI — Integration Credential Repository.
"""

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.integration_client import IntegrationClientModel
from app.repositories.base import BaseRepository


class IntegrationRepository(BaseRepository[IntegrationClientModel]):
    def __init__(self, session: AsyncSession, tenant_id: Optional[str] = None):
        super().__init__(IntegrationClientModel, session, tenant_id or "")

    async def get_by_public_key(self, public_key: str) -> Optional[IntegrationClientModel]:
        stmt = select(IntegrationClientModel).where(IntegrationClientModel.public_key == public_key)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_api_key_hash(self, api_key_hash: str) -> Optional[IntegrationClientModel]:
        stmt = select(IntegrationClientModel).where(
            IntegrationClientModel.api_key_hash == api_key_hash
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def list_by_tenant(self, limit: int = 100) -> list[IntegrationClientModel]:
        stmt = (
            select(IntegrationClientModel)
            .where(IntegrationClientModel.customer_tenant_id == self.tenant_id)
            .order_by(IntegrationClientModel.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_credential(
        self,
        tenant_id: str,
        public_key: str,
        api_key_hash: str,
        api_key_hint: Optional[str] = None,
        name: str = "Default",
    ) -> IntegrationClientModel:
        model = IntegrationClientModel(
            customer_tenant_id=tenant_id,
            public_key=public_key,
            api_key_hash=api_key_hash,
            api_key_hint=api_key_hint,
            name=name,
            status="ACTIVE",
        )
        self.session.add(model)
        await self.session.flush()
        return model
