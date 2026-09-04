"""
TrustPulse AI — Background Telemetry Worker.

Consumes validated telemetry jobs and updates behavioral baselines. This keeps
heavy background processing away from synchronous action risk evaluation.

If Redis is unavailable, the worker degrades to an in-memory process-local queue
and the reduced durability guarantee is reported by /health.
"""

import asyncio
from typing import Any, Dict, Optional

from app.core.config import settings
from app.core.logging import logger
from app.core.metrics import metrics
from app.core.redis import redis_manager
from app.models.base import async_session_factory
from app.repositories.sessions import SessionRepository
from app.services.behavioral_service import BehavioralService


class TelemetryWorker:
    def __init__(self, tenant_id: str = "system"):
        self.tenant_id = tenant_id
        self.queue_name = "telemetry"
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self.active = False

    async def start(self) -> None:
        if self.active:
            return
        self.active = True
        self._stop.clear()
        self._task = asyncio.create_task(self._run_loop(), name="trustpulse-telemetry-worker")
        logger.info("Telemetry worker started")

    async def stop(self) -> None:
        self.active = False
        self._stop.set()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Telemetry worker stopped")

    async def _run_loop(self) -> None:
        while self.active:
            try:
                payload = await redis_manager.queue_pop(self.tenant_id, self.queue_name)
                if payload is None:
                    await asyncio.sleep(settings.REDIS_QUEUE_REPEAT_MS / 1000.0)
                    continue
                await self._process(payload)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(f"Telemetry worker error: {exc}")
                metrics.incr("telemetry_worker_errors")

    async def _process(self, payload: Dict[str, Any]) -> None:
        async with async_session_factory() as db:
            try:
                session_repo = SessionRepository(db, payload.get("tenant_id", self.tenant_id))
                sess = await session_repo.get_by_session_id(payload.get("session_id", ""))
                if not sess:
                    return
                behavioral = BehavioralService(db, payload.get("tenant_id", self.tenant_id))
                await behavioral.update_baseline_from_event(
                    session=sess,
                    feature_payload=payload.get("feature_payload", {}),
                    session_confidence=settings.COLD_START_CONFIDENCE,
                    has_active_incident=False,
                    suspicious_action=False,
                    policy_allows_learning=True,
                )
                await db.commit()
                metrics.incr("telemetry_worker_processed")
            except Exception as exc:
                await db.rollback()
                logger.warning(f"Telemetry worker processing failed: {exc}")
                metrics.incr("telemetry_worker_errors")
