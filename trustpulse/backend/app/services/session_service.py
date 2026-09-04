"""
TrustPulse AI - Session Service

Handles session lifecycle: registration, lookup, status transitions.
"""

from typing import Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.sessions import SessionRepository
from app.repositories.incidents import IncidentRepository
from app.schemas.session import SessionCreate, SessionResponse, SessionStatusUpdate
from app.core.config import settings
from app.core.logging import logger
from app.core.exceptions import SessionNotFoundException, TrustPulseException


class SessionService:
    def __init__(self, db: AsyncSession, tenant_id: str):
        self.session_repo = SessionRepository(db, tenant_id)
        self.incident_repo = IncidentRepository(db, tenant_id)
        self.tenant_id = tenant_id

    async def register_session(self, data: SessionCreate) -> SessionResponse:
        """
        Registers a new TrustPulse session for the given host application session ID.
        If a session already exists and is ACTIVE, returns the existing session.
        """
        existing = await self.session_repo.get_by_session_id(data.session_id)
        if existing and existing.status == "ACTIVE":
            logger.debug(f"Session {data.session_id} already active; returning existing.")
            await self.session_repo.update_last_seen(data.session_id)
            return SessionResponse(
                session_id=existing.session_id,
                status=existing.status,
                created_at=existing.created_at,
                last_seen_at=existing.last_seen_at,
                expires_at=existing.expires_at,
                sdk_instance_id=existing.sdk_instance_id,
                session_version=existing.session_version,
            )

        if existing and existing.status in ("TERMINATED", "ISOLATED"):
            raise TrustPulseException(
                message=f"Session {data.session_id} is in terminal state '{existing.status}'",
                status_code=409,
            )

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
        logger.info(f"Registered new TrustPulse session: {data.session_id} for tenant {self.tenant_id}")
        return SessionResponse(
            session_id=sess.session_id,
            status=sess.status,
            created_at=sess.created_at,
            last_seen_at=sess.last_seen_at,
            expires_at=sess.expires_at,
            sdk_instance_id=sess.sdk_instance_id,
            session_version=sess.session_version,
        )

    async def get_session(self, session_id: str) -> SessionResponse:
        sess = await self.session_repo.get_by_session_id(session_id)
        if not sess:
            raise SessionNotFoundException(session_id)
        return SessionResponse(
            session_id=sess.session_id,
            status=sess.status,
            created_at=sess.created_at,
            last_seen_at=sess.last_seen_at,
            expires_at=sess.expires_at,
            sdk_instance_id=sess.sdk_instance_id,
            session_version=sess.session_version,
        )

    async def update_session_status(self, session_id: str, update: SessionStatusUpdate) -> SessionResponse:
        valid_statuses = {"ACTIVE", "PAUSED", "TERMINATED", "ISOLATED"}
        if update.status not in valid_statuses:
            raise TrustPulseException(
                message=f"Invalid status '{update.status}'. Valid: {valid_statuses}",
                status_code=422,
            )

        sess = await self.session_repo.update_status(session_id, update.status)
        if not sess:
            raise SessionNotFoundException(session_id)

        logger.info(f"Session {session_id} status → {update.status}")
        return SessionResponse(
            session_id=sess.session_id,
            status=sess.status,
            created_at=sess.created_at,
            last_seen_at=sess.last_seen_at,
            expires_at=sess.expires_at,
            sdk_instance_id=sess.sdk_instance_id,
            session_version=sess.session_version,
        )

    async def has_open_incident(self, session_id: str) -> bool:
        """Check if the session has an unresolved security incident."""
        incidents = await self.incident_repo.get_open_incidents(session_id)
        return len(incidents) > 0
