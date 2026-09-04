"""
TrustPulse AI — Incident Service.

Creates and manages security incidents. An incident references a decision and a
session; it does not duplicate telemetry payloads.
"""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext
from app.models.incident import IncidentModel
from app.repositories.incidents import IncidentRepository
from app.services.audit_service import AuditService


class IncidentService:
    def __init__(
        self, db: AsyncSession, tenant_id: str, integration: Optional[IntegrationContext] = None
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.repo = IncidentRepository(db, tenant_id)
        self.audit = AuditService(db, tenant_id, integration)

    async def create_incident(
        self,
        session_id: str,
        severity: str,
        trigger_reason: str,
        decision_id: Optional[str] = None,
    ) -> IncidentModel:
        incident = await self.repo.create_incident(
            session_id=session_id,
            severity=severity,
            trigger_reason=trigger_reason,
            decision_id=decision_id,
        )
        await self.audit.log(
            event_type="INCIDENT_CREATED",
            resource_type="INCIDENT",
            resource_id=incident.incident_id,
            metadata={"session_id": session_id, "severity": severity, "reason": trigger_reason},
        )
        return incident

    async def list_incidents(
        self, session_id: Optional[str] = None, limit: int = 100
    ) -> List[IncidentModel]:
        return await self.repo.list_incidents(session_id=session_id, limit=limit)

    async def get_incident(self, incident_id: str) -> Optional[IncidentModel]:
        return await self.repo.get_by_incident_id(incident_id)

    async def resolve_incident(
        self, incident_id: str, resolution_notes: Optional[str] = None, status: str = "RESOLVED"
    ) -> Optional[IncidentModel]:
        incident = await self.repo.resolve_incident(incident_id)
        if not incident:
            return None
        incident.status = status.upper() if status.upper() in {"RESOLVED", "CLOSED"} else "RESOLVED"
        incident.resolved_at = datetime.now(timezone.utc)
        await self.db.flush()
        await self.audit.log(
            event_type="INCIDENT_RESOLVED",
            resource_type="INCIDENT",
            resource_id=incident.incident_id,
            metadata={"session_id": incident.session_id, "notes": resolution_notes},
        )
        return incident
