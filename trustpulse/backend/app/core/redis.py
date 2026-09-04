"""
TrustPulse AI — Redis State Manager.

Redis is used for TEMPORARY/high-speed state only:
  * duplicate/replay prevention
  * monotonic sequence tracking
  * tenant/session rate limits
  * short-lived decision/hysteresis state
  * telemetry background queue

PostgreSQL remains the authoritative source of truth. If Redis is unavailable,
an in-memory fallback keeps the process functional for local testing while the
system exposes reduced durability guarantees in `/health`.
"""

import asyncio
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple

import redis.asyncio as aioredis

from app.core.config import settings
from app.core.logging import logger


class InMemoryRedisFallback:
    """
    In-memory fallback used when Redis is unreachable.

    It implements the subset of Redis operations used by the TrustPulse backend.
    State is process-local and is NOT durable across restarts. Rate-limit and
    replay guarantees are therefore temporarily degraded and reported by /health.
    """

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}
        self._queues: Dict[str, Deque[Any]] = {}
        self._lock = asyncio.Lock()

    def _purge_expired(self) -> None:
        now = time.time()
        expired = [k for k, exp in self._expiry.items() if exp <= now]
        for k in expired:
            self._data.pop(k, None)
            self._expiry.pop(k, None)
            self._queues.pop(k, None)

    async def get(self, key: str) -> Optional[str]:
        async with self._lock:
            self._purge_expired()
            val = self._data.get(key)
            return str(val) if val is not None else None

    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        async with self._lock:
            self._purge_expired()
            self._data[key] = value
            if ex:
                self._expiry[key] = time.time() + ex
            else:
                self._expiry.pop(key, None)
        return True

    async def setnx(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        async with self._lock:
            self._purge_expired()
            if key in self._data:
                return False
            self._data[key] = value
            if ex:
                self._expiry[key] = time.time() + ex
        return True

    async def incr(self, key: str) -> int:
        async with self._lock:
            self._purge_expired()
            curr = int(self._data.get(key, 0))
            curr += 1
            self._data[key] = curr
            return curr

    async def expire(self, key: str, seconds: int) -> bool:
        async with self._lock:
            if key in self._data or key in self._queues:
                self._expiry[key] = time.time() + seconds
                return True
        return False

    async def delete(self, *keys: str) -> int:
        async with self._lock:
            count = 0
            for k in keys:
                if k in self._data:
                    del self._data[k]
                    self._expiry.pop(k, None)
                    count += 1
                if k in self._queues:
                    del self._queues[k]
                    self._expiry.pop(k, None)
                    count += 1
        return count

    async def ping(self) -> bool:
        return True

    async def rpush(self, key: str, value: Any, ex: Optional[int] = None) -> int:
        async with self._lock:
            self._purge_expired()
            q = self._queues.setdefault(key, deque())
            q.append(value)
            if ex:
                self._expiry[key] = time.time() + ex
            return len(q)

    async def lpop(self, key: str) -> Optional[Any]:
        async with self._lock:
            self._purge_expired()
            q = self._queues.get(key)
            if not q:
                return None
            return q.popleft()

    async def llen(self, key: str) -> int:
        async with self._lock:
            self._purge_expired()
            return len(self._queues.get(key, deque()))

    async def close(self) -> None:
        pass


class RedisClientManager:
    _instance: Optional["RedisClientManager"] = None

    def __init__(self) -> None:
        self.redis: Any = None
        self.is_fallback: bool = False
        self.initialized: bool = False
        self.replay_durable: bool = False
        self.queue_available: bool = False
        self.last_error: str = ""

    async def initialize(self) -> None:
        if self.initialized:
            return
        try:
            client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=settings.REDIS_SOCKET_TIMEOUT_SECONDS,
                socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS,
            )
            pong = await client.ping()
            if isinstance(pong, bool) and not pong:
                raise RuntimeError("Redis ping returned false")
            self.redis = client
            self.is_fallback = False
            self.replay_durable = True
            self.queue_available = True
            self.last_error = ""
            logger.info("Connected to external Redis instance.")
        except Exception as exc:  # pragma: no cover - depends on environment
            self.redis = InMemoryRedisFallback()
            self.is_fallback = True
            self.replay_durable = False
            self.queue_available = False
            self.last_error = str(exc)
            logger.warning(
                f"External Redis unavailable ({exc}). Using resilient in-memory state manager.",
                extra={"extra_data": {"component": "redis", "fallback": True}},
            )
        self.initialized = True

    async def get_client(self) -> Any:
        if not self.initialized:
            await self.initialize()
        return self.redis

    async def close(self) -> None:
        if self.redis and hasattr(self.redis, "close"):
            try:
                await self.redis.close()
            except Exception:
                pass
        self.initialized = False

    @staticmethod
    def _replay_key(tenant_id: str, event_id: str) -> str:
        return f"tp:{tenant_id}:replay:{event_id}"

    @staticmethod
    def _sequence_key(tenant_id: str, session_id: str, sdk_instance_id: str) -> str:
        return f"tp:{tenant_id}:seq:{session_id}:{sdk_instance_id}"

    @staticmethod
    def _rate_key(tenant_id: str, scope: str, bucket: int) -> str:
        return f"tp:{tenant_id}:rate:{scope}:{bucket}"

    @staticmethod
    def _decision_key(tenant_id: str, session_id: str) -> str:
        return f"tp:{tenant_id}:decision:{session_id}"

    async def check_and_set_replay(
        self, tenant_id: str, event_id: str, ttl_seconds: int = 86400
    ) -> bool:
        """
        Returns True if event_id is NEW, False if already seen.
        Uses SET NX in Redis, or a local dict in fallback mode.
        """
        client = await self.get_client()
        key = self._replay_key(tenant_id, event_id)
        result = await client.setnx(key, "1", ex=ttl_seconds)
        return bool(result)

    async def validate_and_update_sequence(
        self,
        tenant_id: str,
        session_id: str,
        sdk_instance_id: str,
        seq: int,
    ) -> Tuple[int, bool]:
        """
        Validates strict monotonic progression.

        Returns (last_seq, accepted). If seq <= last_seq, the event is a
        duplicate/replayed/malicious sequence and is not accepted.
        """
        client = await self.get_client()
        key = self._sequence_key(tenant_id, session_id, sdk_instance_id)
        last_str = await client.get(key)
        last_seq = int(last_str) if last_str is not None else 0

        if seq > last_seq:
            await client.set(key, str(seq), ex=settings.REDIS_SESSION_TTL_SECONDS)
            return last_seq, True
        return last_seq, False

    async def check_rate_limit(
        self,
        tenant_id: str,
        limit_per_minute: int,
        scope: str = "tenant",
        scope_id: str = "",
    ) -> bool:
        """
        Fixed-window Redis-backed counter.

        scope='tenant' doesn't need scope_id; scope='session' uses scope_id.
        """
        client = await self.get_client()
        bucket = int(time.time() // 60)
        identifier = f"{scope}:{scope_id}" if scope == "session" else scope
        key = self._rate_key(tenant_id, identifier, bucket)
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, 120)
        return count <= limit_per_minute

    async def get_session_state(self, tenant_id: str, session_id: str) -> Optional[str]:
        client = await self.get_client()
        key = f"tp:{tenant_id}:session:{session_id}"
        return await client.get(key)

    async def cache_session_state(
        self, tenant_id: str, session_id: str, value: str, ttl_seconds: Optional[int] = None
    ) -> None:
        client = await self.get_client()
        key = f"tp:{tenant_id}:session:{session_id}"
        await client.set(key, value, ex=ttl_seconds or settings.REDIS_SESSION_TTL_SECONDS)

    async def get_decision_state(self, tenant_id: str, session_id: str) -> Optional[Dict[str, Any]]:
        client = await self.get_client()
        raw = await client.get(self._decision_key(tenant_id, session_id))
        if raw is None:
            return None
        try:
            import json

            return json.loads(raw)
        except Exception:
            return None

    async def set_decision_state(
        self, tenant_id: str, session_id: str, decision: str, confidence: int
    ) -> None:
        import json

        client = await self.get_client()
        await client.set(
            self._decision_key(tenant_id, session_id),
            json.dumps({"decision": decision, "confidence": confidence, "at": time.time()}),
            ex=settings.REDIS_DECISION_STATE_TTL_SECONDS,
        )

    async def clear_decision_state(self, tenant_id: str, session_id: str) -> None:
        client = await self.get_client()
        await client.delete(self._decision_key(tenant_id, session_id))

    # ------------------------------------------------------------------ Queue
    def _queue_key(self, tenant_id: str, queue: str) -> str:
        return f"tp:{tenant_id}:queue:{queue}"

    async def queue_push(self, tenant_id: str, queue: str, payload: Any) -> int:
        import json

        client = await self.get_client()
        key = self._queue_key(tenant_id, queue)
        encoded = json.dumps(payload, default=str)
        size = await client.rpush(key, encoded, ex=settings.REDIS_QUEUE_TTL_SECONDS)
        return int(size)

    async def queue_pop(self, tenant_id: str, queue: str) -> Optional[Any]:
        import json

        client = await self.get_client()
        key = self._queue_key(tenant_id, queue)
        raw = await client.lpop(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return raw

    async def queue_depth(self, tenant_id: str, queue: str) -> int:
        client = await self.get_client()
        key = self._queue_key(tenant_id, queue)
        return int(await client.llen(key))

    @property
    def availability(self) -> Dict[str, bool]:
        return {
            "external": not self.is_fallback,
            "replay_durable": self.replay_durable,
            "queue_available": self.queue_available,
        }


redis_manager = RedisClientManager()
