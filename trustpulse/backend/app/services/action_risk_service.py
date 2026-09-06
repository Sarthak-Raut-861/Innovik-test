"""
TrustPulse AI — Action Risk Service.

Public-facing operations for action requests and the generic action catalog.
"""

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import IntegrationContext
from app.engines.action.action_risk import ActionRiskEngine
from app.repositories.risks import RiskRepository


class ActionRiskService:
    def __init__(
        self,
        db: Optional[AsyncSession],
        tenant_id: str,
        integration: Optional[IntegrationContext] = None,
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.repo = RiskRepository(db, tenant_id) if db else None

    def get_catalog(self) -> Dict[str, Any]:
        return ActionRiskEngine.get_catalog()

    async def list_actions(self, session_id: Optional[str] = None, limit: int = 100):
        assert self.repo is not None
        return await self.repo.list_actions(session_id=session_id, limit=limit)

    async def get_action(self, action_id: str):
        assert self.repo is not None
        return await self.repo.get_action_by_id(action_id)
