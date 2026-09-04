"""
TrustPulse AI — Session Service.

Handles session registration, lookup, status transitions, and tenant isolation.
TrustPulse is not the application authentication provider; it binds to the
authenticated application session identifier supplied by the customer.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext
from app.core.config import settings
from app.core.exceptions import (
    SessionNotFoundException,
    SessionTerminalStateException,
    TrustPulseException,
)
from app.core.logging import logger
from app.repositories.incidents import IncidentRepository
from app.repositories.sessions import SessionRepository
from app.schemas.session import SessionCreate, SessionResponse, SessionStatusUpdate
from app.services.audit_service import AuditService


class SessionService:
    def __init__(
        self, db: AsyncSession, tenant_id: str, integration: Optional[IntegrationContext] = None
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.session_repo = SessionRepository(db, tenant_id)
        self.incident_repo = IncidentRepository(db, tenant_id)
        self.audit = AuditService(db, tenant_id, integration)

    async def register_session(self, data: SessionCreate) -> SessionResponse:
        """Register a TrustPulse session. Active sessions are idempotently returned."""
        existing = await self.session_repo.get_by_session_id(data.session_id)
        if existing:
            if existing.status == "ACTIVE":
                if (
                    data.sdk_instance_id
                    and existing.sdk_instance_id
                    and data.sdk_instance_id != existing.sdk_instance_id
                ):
                    raise TrustPulseException(
                        message="Session already bound to a different SDK instance",
                        status_code=409,
                    )
                await self.session_repo.update_last_seen(data.session_id)
                action = "SESSION_REUSED" if existing.sdk_instance_id else "SESSION_CREATED"
                await self.audit.log(
                    event_type=action,
                    resource_type="SESSION",
                    resource_id=data.session_id,
                    metadata={"subject_id": data.subject_id, "device_id": data.device_id},
                )
                return self._to_response(existing)

            if existing.status in ("TERMINATED", "ISOLATED"):
                raise SessionTerminalStateException(data.session_id, existing.status)

            # Paused session can be reactivated.
            existing.status = "ACTIVE"
            existing.session_version += 1
            existing.last_seen_at = datetime.now(timezone.utc)
            await self.db.flush()
            await self.audit.log(
                event_type="SESSION_CREATED",
                resource_type="SESSION",
                resource_id=data.session_id,
                metadata={"reactivated": True, "subject_id": data.subject_id},
            )
            return self._to_response(existing)

        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=settings.REDIS_SESSION_TTL_SECONDS
        )
        sess = await self.session_repo.create_session(
            session_id=data.session_id,
            subject_id=data.subject_id,
            device_id=data.device_id,
            sdk_instance_id=data.sdk_instance_id,
            expires_at=expires_at,
        )
        await self.audit.log(
            event_type="SESSION_CREATED",
            resource_type="SESSION",
            resource_id=data.session_id,
            metadata={"subject_id": data.subject_id, "device_id": data.device_id},
        )
        logger.info(f"Registered session {data.session_id} for tenant {self.tenant_id}")
        return self._to_response(sess)

    async def get_session(self, session_id: str) -> SessionResponse:
        sess = await self.session_repo.get_by_session_id(session_id)
        if not sess:
            raise SessionNotFoundException(session_id)
        return self._to_response(sess)

    async def update_session_status(
        self, session_id: str, update: SessionStatusUpdate
    ) -> SessionResponse:
        valid_statuses = {"ACTIVE", "PAUSED", "TERMINATED", "ISOLATED"}
        if update.status not in valid_statuses:
            raise TrustPulseException(
                message=f"Invalid status '{update.status}'. Valid: {sorted(valid_statuses)}",
                status_code=422,
            )
        sess = await self.session_repo.update_status(session_id, update.status)
        if not sess:
            raise SessionNotFoundException(session_id)
        await self.audit.log(
            event_type=f"SESSION_STATUS_{update.status}",
            resource_type="SESSION",
            resource_id=session_id,
            metadata={"status": update.status},
        )
        logger.info(f"Session {session_id} status -> {update.status}")
        return self._to_response(sess)

    def _to_response(self, sess) -> SessionResponse:
        return SessionResponse(
            session_id=sess.session_id,
            status=sess.status,
            created_at=sess.created_at,
            last_seen_at=sess.last_seen_at,
            expires_at=sess.expires_at,
            sdk_instance_id=sess.sdk_instance_id,
            session_version=sess.session_version,
        )
