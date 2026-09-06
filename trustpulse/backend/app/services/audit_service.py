"""
TrustPulse AI — Audit Service.

Every important security decision/event generates an immutable-style audit
record. Secrets are never logged.
"""

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import IntegrationContext
from app.core.security import SecurityUtils
from app.repositories.audit import AuditRepository


class AuditService:
    def __init__(
        self, db: AsyncSession, tenant_id: str, integration: Optional[IntegrationContext] = None
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.repo = AuditRepository(db, tenant_id)

    async def log(
        self,
        event_type: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor_type: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> None:
        safe_metadata = SecurityUtils.redact_secrets(metadata or {})
        actor_type = actor_type or (self.integration.actor_type if self.integration else "SYSTEM")
        actor_id = actor_id or (self.integration.actor_id if self.integration else None)

        await self.repo.log_event(
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata_payload=safe_metadata,
        )

    async def list(self, limit: int = 100):
        return await self.repo.list_audit_logs(limit=limit)
