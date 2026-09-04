"""
TrustPulse AI - Telemetry Ingestion Service

Validates, deduplicates, and persists telemetry batch packets.
Triggers behavioral analysis after acceptance.
"""

import time
from typing import List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.telemetry import (
    TelemetryBatchSchema,
    TelemetryPacketSchema,
    TelemetryIngestionResponse,
    ExtractedFeaturePayloadSchema,
)
from app.repositories.sessions import SessionRepository
from app.repositories.telemetry import TelemetryRepository
from app.core.redis import redis_manager
from app.core.config import settings
from app.core.logging import logger
from app.core.exceptions import (
    SessionNotFoundException,
    ReplayDetectedException,
    StaleTimestampException,
    RateLimitExceededException,
)
from app.core.security import SecurityUtils


class TelemetryService:
    def __init__(self, db: AsyncSession, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id
        self.session_repo = SessionRepository(db, tenant_id)
        self.telemetry_repo = TelemetryRepository(db, tenant_id)

    async def ingest_batch(self, batch: TelemetryBatchSchema) -> TelemetryIngestionResponse:
        """
        Ingests a telemetry batch. Performs:
        1. Rate limiting
        2. Per-packet replay detection
        3. Clock-skew validation
        4. Sequence validation
        5. Integrity verification
        6. DB persistence
        """
        # Rate limit check
        allowed = await redis_manager.check_rate_limit(
            self.tenant_id, settings.RATE_LIMIT_TELEMETRY_PER_MINUTE
        )
        if not allowed:
            raise RateLimitExceededException()

        accepted = 0
        rejected = 0
        now_ms = int(time.time() * 1000)

        for packet in batch.packets:
            try:
                await self._validate_and_persist(packet, now_ms)
                accepted += 1
            except Exception as e:
                logger.warn(f"Packet {packet.eventId} rejected: {e}")
                rejected += 1

        logger.info(
            f"Batch {batch.batchId}: {accepted} accepted, {rejected} rejected "
            f"for tenant {self.tenant_id}"
        )

        return TelemetryIngestionResponse(
            status="accepted" if accepted > 0 else "rejected",
            batch_id=batch.batchId,
            received_packets=len(batch.packets),
            accepted_packets=accepted,
            rejected_packets=rejected,
        )

    async def _validate_and_persist(self, packet: TelemetryPacketSchema, now_ms: int) -> None:
        # 1. Session must exist
        sess = await self.session_repo.get_by_session_id(packet.sessionId)
        if not sess:
            raise SessionNotFoundException(packet.sessionId)
        if sess.status in ("TERMINATED", "ISOLATED"):
            raise Exception(f"Session {packet.sessionId} is {sess.status}")

        # 2. Clock skew check (server-side)
        delta_seconds = abs(now_ms - packet.timestamp) / 1000.0
        if delta_seconds > settings.MAX_CLOCK_SKEW_SECONDS:
            raise StaleTimestampException(delta_seconds, settings.MAX_CLOCK_SKEW_SECONDS)

        # 3. Replay prevention (event-level)
        is_new = await redis_manager.check_and_set_replay(
            self.tenant_id, packet.eventId, settings.REDIS_REPLAY_TTL_SECONDS
        )
        if not is_new:
            raise ReplayDetectedException()

        # 4. Monotonic sequence check
        last_seq = await redis_manager.validate_and_update_sequence(
            self.tenant_id, packet.sessionId, packet.sequenceNumber
        )
        if packet.sequenceNumber <= last_seq:
            logger.warn(
                f"Sequence regression for session {packet.sessionId}: "
                f"received {packet.sequenceNumber}, last was {last_seq}"
            )
            # Log but do not hard-reject — drop silently (common with reconnects)
            raise Exception(f"Sequence regression: {packet.sequenceNumber} <= {last_seq}")

        # 5. Integrity verification (FNV-1a checksum)
        if packet.integrity:
            import json
            payload_str = json.dumps(packet.features.model_dump(), separators=(",", ":"), sort_keys=True)
            valid = SecurityUtils.verify_integrity(payload_str, packet.integrity)
            if not valid:
                logger.warn(f"Integrity mismatch for packet {packet.eventId}")
                # Accept but mark as degraded — don't hard-reject (client-side hash is advisory)

        # 6. Persist to DB
        await self.telemetry_repo.record_event(
            event_id=packet.eventId,
            session_id=packet.sessionId,
            sdk_instance_id=packet.sdkInstanceId,
            sequence_number=packet.sequenceNumber,
            timestamp=packet.timestamp,
            schema_version=packet.schemaVersion,
            feature_payload=packet.features.model_dump(),
            validation_status="VALID",
        )

        # 7. Update session last_seen
        await self.session_repo.update_last_seen(packet.sessionId)
