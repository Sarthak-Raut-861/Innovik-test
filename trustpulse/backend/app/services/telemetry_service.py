"""
TrustPulse AI — Telemetry Ingestion Service.

Server-side validation pipeline:
  session binding -> rate limit -> schema/timestamp -> replay ->
  sequence -> integrity advisory -> persist important events -> background
  behavioral profile processing.

Client-provided risk scores are never accepted. A client checksum is advisory only.
"""

import json
import time
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.context import IntegrationContext
from app.core.exceptions import (
    RateLimitExceededException,
    ReplayDetectedException,
    SessionNotFoundException,
    SessionTerminalStateException,
    StaleTimestampException,
    TelemetryValidationException,
)
from app.core.logging import logger
from app.core.metrics import metrics
from app.core.redis import redis_manager
from app.core.security import SecurityUtils
from app.repositories.sessions import SessionRepository
from app.repositories.telemetry import TelemetryRepository
from app.schemas.telemetry import (
    TelemetryBatchSchema,
    TelemetryIngestionResponse,
    TelemetryPacketResult,
    TelemetryPacketSchema,
)
from app.services.audit_service import AuditService
from app.services.behavioral_service import BehavioralService


class TelemetryService:
    def __init__(
        self, db: AsyncSession, tenant_id: str, integration: Optional[IntegrationContext] = None
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.session_repo = SessionRepository(db, tenant_id)
        self.telemetry_repo = TelemetryRepository(db, tenant_id)
        self.audit = AuditService(db, tenant_id, integration)
        self.behavioral = BehavioralService(db, tenant_id, integration)

    async def ingest_batch(
        self, batch: TelemetryBatchSchema, sdk_session_header: Optional[str] = None
    ) -> TelemetryIngestionResponse:
        """Validates and persists a batch. Returns per-packet outcomes."""
        metrics.incr("telemetry_batches_received")
        allowed = await redis_manager.check_rate_limit(
            self.tenant_id,
            settings.RATE_LIMIT_TELEMETRY_PER_MINUTE,
            scope="tenant",
        )
        if not allowed:
            metrics.incr("telemetry_rate_limited")
            raise RateLimitExceededException(scope="tenant")

        accepted = 0
        rejected = 0
        results: List[TelemetryPacketResult] = []
        now_ms = int(time.time() * 1000)

        # Batch metadata freshness.
        if abs(now_ms - batch.sentAt) > settings.MAX_CLOCK_SKEW_SECONDS * 1000 * 10:
            logger.warning(
                f"Batch {batch.batchId} has stale sentAt value",
                extra={"extra_data": {"batch_id": batch.batchId, "tenant": self.tenant_id}},
            )

        for packet in batch.packets:
            outcome = await self._validate_and_persist(packet, now_ms, sdk_session_header)
            results.append(outcome)
            if outcome.status == "ACCEPTED":
                accepted += 1
            else:
                rejected += 1
                metrics.incr("telemetry_rejected")

        total = len(results)
        metrics.incr("telemetry_packets_received", accepted + rejected)
        logger.info(
            f"Batch {batch.batchId}: {accepted} accepted, {rejected} "
            f"rejected (tenant {self.tenant_id})"
        )
        return TelemetryIngestionResponse(
            status="accepted" if accepted > 0 else "rejected",
            batch_id=batch.batchId,
            received_packets=total,
            accepted_packets=accepted,
            rejected_packets=rejected,
            results=results,
        )

    async def _validate_and_persist(
        self,
        packet: TelemetryPacketSchema,
        now_ms: int,
        sdk_session_header: Optional[str],
    ) -> TelemetryPacketResult:
        try:
            sess = await self.session_repo.get_by_session_id(packet.sessionId)
            if not sess:
                raise SessionNotFoundException(packet.sessionId)
            if sess.status in ("TERMINATED", "ISOLATED"):
                raise SessionTerminalStateException(packet.sessionId, sess.status)

            if sdk_session_header and sdk_session_header != packet.sessionId:
                raise TelemetryValidationException("Header session does not match body session")

            if sess.sdk_instance_id and sess.sdk_instance_id != packet.sdkInstanceId:
                raise TelemetryValidationException("SDK instance does not match session binding")

            allowed_session_rate = await redis_manager.check_rate_limit(
                self.tenant_id,
                settings.RATE_LIMIT_TELEMETRY_PER_SESSION_PER_MINUTE,
                scope="session",
                scope_id=packet.sessionId,
            )
            if not allowed_session_rate:
                raise RateLimitExceededException(scope="session")

            if packet.schemaVersion != settings.TELEMETRY_SCHEMA_VERSION:
                raise TelemetryValidationException(
                    f"Unsupported schema version '{packet.schemaVersion}'",
                    [f"expected {settings.TELEMETRY_SCHEMA_VERSION}"],
                )

            if (
                packet.timestamp < 0
                or abs(now_ms - packet.timestamp) / 1000.0 > settings.MAX_CLOCK_SKEW_SECONDS
            ):
                raise StaleTimestampException(
                    abs(now_ms - packet.timestamp) / 1000.0, settings.MAX_CLOCK_SKEW_SECONDS
                )

            features_bytes = len(json.dumps(packet.features.model_dump()).encode("utf-8"))
            if features_bytes > settings.MAX_PACKET_FEATURES_BYTES:
                raise TelemetryValidationException("Feature payload too large")

            is_new = await redis_manager.check_and_set_replay(
                self.tenant_id, packet.eventId, settings.REDIS_REPLAY_TTL_SECONDS
            )
            if not is_new:
                metrics.incr("telemetry_duplicate_events")
                await self.audit.log(
                    event_type="TELEMETRY_REJECTED",
                    resource_type="TELEMETRY_EVENT",
                    resource_id=packet.eventId,
                    metadata={"reason": "DUPLICATE_EVENT_ID", "session_id": packet.sessionId},
                )
                return TelemetryPacketResult(
                    event_id=packet.eventId, status="REJECTED", reason="DUPLICATE_EVENT_ID"
                )

            last_seq, accepted = await redis_manager.validate_and_update_sequence(
                self.tenant_id, packet.sessionId, packet.sdkInstanceId, packet.sequenceNumber
            )
            if not accepted:
                metrics.incr("telemetry_sequence_rejections")
                await self.audit.log(
                    event_type="TELEMETRY_REJECTED",
                    resource_type="TELEMETRY_EVENT",
                    resource_id=packet.eventId,
                    metadata={"reason": "SEQUENCE_REGRESSION", "session_id": packet.sessionId},
                )
                return TelemetryPacketResult(
                    event_id=packet.eventId, status="REJECTED", reason="SEQUENCE_REGRESSION"
                )

            # Advisory integrity check. If payload checksum does not match, retain the
            # event but mark it degraded. A forged checksum is not authoritative.
            integrity_ok = True
            payload_str = SecurityUtils.canonical_json(packet.features.model_dump())
            if packet.integrity and not SecurityUtils.verify_integrity(
                payload_str, packet.integrity
            ):
                integrity_ok = False
                metrics.incr("telemetry_integrity_mismatches")

            if not sess.sdk_instance_id:
                await self.session_repo.bind_sdk_instance(packet.sessionId, packet.sdkInstanceId)

            await self.telemetry_repo.record_event(
                event_id=packet.eventId,
                session_id=packet.sessionId,
                sdk_instance_id=packet.sdkInstanceId,
                sequence_number=packet.sequenceNumber,
                timestamp=packet.timestamp,
                schema_version=packet.schemaVersion,
                feature_payload=packet.features.model_dump(),
                validation_status="DEGRADED" if not integrity_ok else "VALID",
                rejection_reason=None,
            )
            await self.session_repo.update_last_seen(packet.sessionId)

            # Background behavioral processing (separate from synchronous risk eval).
            await self._enqueue_or_process(sess, packet, integrity_ok)

            if not integrity_ok:
                await self.audit.log(
                    event_type="TELEMETRY_INTEGRITY_MISMATCH",
                    resource_type="TELEMETRY_EVENT",
                    resource_id=packet.eventId,
                    metadata={"session_id": packet.sessionId},
                )

            metrics.incr("telemetry_accepted")
            return TelemetryPacketResult(event_id=packet.eventId, status="ACCEPTED")
        except ReplayDetectedException as e:
            raise e
        except RateLimitExceededException as e:
            raise e
        except Exception as e:
            # Persist important rejected security events when they don't collide with
            # an existing event ID.
            await self._record_rejected(packet, e)
            metrics.incr("telemetry_rejected")
            return TelemetryPacketResult(
                event_id=packet.eventId,
                status="REJECTED",
                reason=e.message if hasattr(e, "message") else str(e),
            )

    async def _record_rejected(self, packet: TelemetryPacketSchema, exc: Exception) -> None:
        reason = exc.message if hasattr(exc, "message") else str(exc)
        await self.audit.log(
            event_type="TELEMETRY_REJECTED",
            resource_type="TELEMETRY_EVENT",
            resource_id=packet.eventId,
            metadata={"session_id": packet.sessionId, "reason": reason[:255]},
        )
        # Persist validly-shaped but rejected events for auditability. Replayed event
        # IDs will already exist and are intentionally skipped.
        exists = await self.telemetry_repo.get_by_event_id(packet.eventId)
        if not exists:
            try:
                await self.telemetry_repo.record_event(
                    event_id=packet.eventId,
                    session_id=packet.sessionId,
                    sdk_instance_id=packet.sdkInstanceId,
                    sequence_number=packet.sequenceNumber,
                    timestamp=packet.timestamp,
                    schema_version=packet.schemaVersion,
                    feature_payload=packet.features.model_dump(),
                    validation_status="REJECTED",
                    rejection_reason=reason[:256],
                )
            except Exception:
                # Consistency between Redis and DB; replayed duplicate is acceptable.
                pass

    async def _enqueue_or_process(self, sess, packet, integrity_ok: bool) -> None:
        try:
            if settings.TELEMETRY_ASYNC_PROCESSING:
                depth = await redis_manager.queue_depth(self.tenant_id, "telemetry")
                if depth >= settings.TELEMETRY_QUEUE_MAX_SIZE:
                    logger.warning(
                        "Telemetry queue overload; skipping background behavioral processing"
                    )
                    metrics.incr("telemetry_queue_overload")
                    return
                payload = {
                    "tenant_id": self.tenant_id,
                    "session_id": sess.session_id,
                    "subject_id": sess.subject_id,
                    "device_id": sess.device_id,
                    "feature_payload": packet.features.model_dump(),
                    "event_id": packet.eventId,
                }
                await redis_manager.queue_push(self.tenant_id, "telemetry", payload)
            else:
                await self.behavioral.update_baseline_from_event(
                    session=sess,
                    feature_payload=packet.features.model_dump(),
                    session_confidence=settings.COLD_START_CONFIDENCE,
                    has_active_incident=False,
                    suspicious_action=False,
                    policy_allows_learning=integrity_ok,
                )
        except Exception as e:
            # Baseline update failure must not fail telemetry ingestion.
            logger.warning(f"Behavioral processing deferred due to: {e}")
            metrics.incr("telemetry_background_errors")
