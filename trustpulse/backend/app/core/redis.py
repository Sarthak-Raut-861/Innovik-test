"""
TrustPulse AI - Redis State & Replay Cache Manager
"""

import time
from typing import Optional, Dict, Any
import redis.asyncio as aioredis
from app.core.config import settings
from app.core.logging import logger


class InMemoryRedisFallback:
    """
    In-memory async dictionary cache fallback when external Redis daemon is unreachable.
    Provides fast O(1) replay checking, monotonic sequence tracking, and rate limiting.
    """

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}

    def _purge_expired(self):
        now = time.time()
        expired = [k for k, exp in self._expiry.items() if exp <= now]
        for k in expired:
            self._data.pop(k, None)
            self._expiry.pop(k, None)

    async def get(self, key: str) -> Optional[str]:
        self._purge_expired()
        val = self._data.get(key)
        return str(val) if val is not None else None

    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        self._purge_expired()
        self._data[key] = value
        if ex:
            self._expiry[key] = time.time() + ex
        else:
            self._expiry.pop(key, None)
        return True

    async def setnx(self, key: str, value: Any) -> bool:
        self._purge_expired()
        if key in self._data:
            return False
        self._data[key] = value
        return True

    async def incr(self, key: str) -> int:
        self._purge_expired()
        curr = int(self._data.get(key, 0))
        curr += 1
        self._data[key] = curr
        return curr

    async def delete(self, *keys: str) -> int:
        count = 0
        for k in keys:
            if k in self._data:
                del self._data[k]
                self._expiry.pop(k, None)
                count += 1
        return count

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        pass


class RedisClientManager:
    _instance: Optional["RedisClientManager"] = None

    def __init__(self):
        self.redis: Any = None
        self.is_fallback: bool = False

    async def initialize(self) -> None:
        try:
            client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
            )
            await client.ping()
            self.redis = client
            self.is_fallback = False
            logger.info("Connected to external Redis instance.")
        except Exception as e:
            logger.warn(f"External Redis unavailable ({e}). Using resilient in-memory state manager.")
            self.redis = InMemoryRedisFallback()
            self.is_fallback = True

    async def get_client(self) -> Any:
        if self.redis is None:
            await self.initialize()
        return self.redis

    async def check_and_set_replay(self, tenant_id: str, event_id: str, ttl_seconds: int = 86400) -> bool:
        """
        Returns True if event_id is NEW (not seen before).
        Returns False if event_id has ALREADY been recorded (replay detected).
        """
        client = await self.get_client()
        key = f"tp:tenant:{tenant_id}:replay:{event_id}"
        if self.is_fallback:
            if key in client._data:
                return False
            await client.set(key, "1", ex=ttl_seconds)
            return True
        else:
            success = await client.set(key, "1", ex=ttl_seconds, nx=True)
            return bool(success)

    async def validate_and_update_sequence(self, tenant_id: str, session_id: str, seq: int) -> int:
        """
        Validates monotonic sequence number.
        Returns last seen sequence. If seq <= last seen, indicates sequence regression.
        """
        client = await self.get_client()
        key = f"tp:tenant:{tenant_id}:seq:{session_id}"
        last_str = await client.get(key)
        last_seq = int(last_str) if last_str is not None else 0

        if seq > last_seq:
            await client.set(key, str(seq), ex=settings.REDIS_SESSION_TTL_SECONDS)

        return last_seq

    async def check_rate_limit(self, tenant_id: str, limit_per_minute: int = 120) -> bool:
        """
        Checks rate limit using minute-bucket counter.
        Returns True if allowed, False if exceeded.
        """
        client = await self.get_client()
        current_minute = int(time.time() // 60)
        key = f"tp:tenant:{tenant_id}:ratelimit:{current_minute}"
        count = await client.incr(key)
        if count == 1 and not self.is_fallback:
            await client.expire(key, 120)
        return count <= limit_per_minute

    async def close(self) -> None:
        if self.redis and hasattr(self.redis, "close"):
            await self.redis.close()


redis_manager = RedisClientManager()
