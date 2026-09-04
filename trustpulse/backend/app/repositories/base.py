"""
TrustPulse AI - Base Repository with Strict Multi-Tenant Scoping
"""

from typing import TypeVar, Generic, Type, Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], session: AsyncSession, tenant_id: str):
        self.model = model
        self.session = session
        self.tenant_id = tenant_id

    async def get_by_id(self, id_val: str) -> Optional[ModelType]:
        stmt = select(self.model).where(
            self.model.id == id_val,
            self.model.customer_tenant_id == self.tenant_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def add(self, entity: ModelType) -> ModelType:
        if hasattr(entity, "customer_tenant_id") and not getattr(entity, "customer_tenant_id"):
            setattr(entity, "customer_tenant_id", self.tenant_id)
        self.session.add(entity)
        await self.session.flush()
        return entity
