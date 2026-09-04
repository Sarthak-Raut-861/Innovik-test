"""
Shared test fixtures for the TrustPulse backend.

Uses an in-memory async SQLite database and an in-memory Redis fallback so the
full test suite runs without external services. Auth development fallback is
enabled by default for functional tests; security tests override it.
"""

import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.redis import InMemoryRedisFallback, redis_manager
from app.main import app
from app.models.base import Base, get_db_session
from app.repositories.integrations import IntegrationRepository

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DB_URL, echo=False, future=True, poolclass=StaticPool)
TestSessionFactory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

TENANT_ID = "test-tenant-001"
TENANT_B = "test-tenant-002"
HEADERS = {
    "X-TrustPulse-Tenant-Id": TENANT_ID,
    "Content-Type": "application/json",
}
PUBLIC_KEY = "test-public-key-123"
TEST_API_KEY = "trustpulse-test-api-key-0001"


@pytest_asyncio.fixture(autouse=True, scope="function")
async def setup_database():
    """Create tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(autouse=True, scope="function")
async def reset_redis_state():
    """Reset the in-memory Redis fallback between tests."""
    redis_manager.redis = InMemoryRedisFallback()
    redis_manager.initialized = True
    redis_manager.is_fallback = True
    redis_manager.replay_durable = False
    redis_manager.queue_available = False
    yield


@pytest_asyncio.fixture
async def client():
    """AsyncClient against the FastAPI app with injected in-memory DB."""

    async def override_get_db():
        async with TestSessionFactory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        c.app_dependency_overrides = {}
        yield c
    app.dependency_overrides.clear()


async def seed_integration(
    tenant_id: str = TENANT_ID,
    api_key: str = TEST_API_KEY,
    public_key: str = PUBLIC_KEY,
) -> dict:
    """Seeds an integration credential into the test DB."""
    from app.core.security import SecurityUtils

    async with TestSessionFactory() as db:
        repo = IntegrationRepository(db, tenant_id)
        existing_by_public = await repo.get_by_public_key(public_key)
        existing_by_hash = await repo.get_by_api_key_hash(SecurityUtils.hash_api_key(api_key))
        if existing_by_public or existing_by_hash:
            await db.commit()
            return {}
        await repo.create_credential(
            tenant_id=tenant_id,
            public_key=public_key,
            api_key_hash=SecurityUtils.hash_api_key(api_key),
            api_key_hint=api_key[-4:],
            name="test-integration",
        )
        await db.commit()
    return {}


def make_session_payload(
    session_id: str = "sess-001",
    subject_id: str = "user-001",
    device_id: str = "device-001",
    sdk_instance_id: str = "inst-001",
) -> dict:
    return {
        "session_id": session_id,
        "subject_id": subject_id,
        "device_id": device_id,
        "sdk_instance_id": sdk_instance_id,
    }


def make_telemetry_packet(
    session_id: str,
    seq: int,
    sdk_instance_id: str = "inst-001",
    event_id: str = None,
    typing_anomalous: bool = False,
) -> dict:
    event_id = event_id or f"evt-{session_id}-{seq}"
    now_ms = int(time.time() * 1000)
    return {
        "sessionId": session_id,
        "sdkInstanceId": sdk_instance_id,
        "eventId": event_id,
        "sequenceNumber": seq,
        "timestamp": now_ms,
        "schemaVersion": settings.TELEMETRY_SCHEMA_VERSION,
        "sdkVersion": settings.SDK_VERSION,
        "eventType": "behavioral_batch",
        "features": {
            "feature_schema_version": "1.0.0",
            "typing": {
                "sampleCount": 45,
                "meanDwellTime": 300.0 if typing_anomalous else 95.0,
                "dwellStdDev": 12.1,
                "meanFlightTime": 110.0,
                "flightStdDev": 15.5,
                "typingSpeed": 4.2,
                "pauseRate": 0.08,
            },
            "mouse": {
                "sampleCount": 120,
                "meanVelocity": 350.0,
                "velocityStdDev": 45.0,
                "meanAcceleration": 120.0,
                "directionChangeRate": 0.3,
                "movementDuration": 2500.0,
                "totalDistance": 875.0,
            },
            "click": {
                "clickCount": 8,
                "doubleClickCount": 1,
                "meanInterval": 1200.0,
                "intervalStdDev": 250.0,
                "clickFrequency": 0.003,
            },
            "scroll": {
                "scrollEventCount": 5,
                "totalDistance": 1200.0,
                "meanVelocity": 450.0,
                "meanPauseDuration": 800.0,
            },
        },
    }


def make_telemetry_batch(
    session_id: str,
    seq: int = 1,
    sdk_instance_id: str = "inst-001",
    event_id: str = None,
    typing_anomalous: bool = False,
) -> dict:
    packet = make_telemetry_packet(
        session_id=session_id,
        seq=seq,
        sdk_instance_id=sdk_instance_id,
        event_id=event_id,
        typing_anomalous=typing_anomalous,
    )
    return {
        "batchId": f"batch-{session_id}-{seq}",
        "sentAt": int(time.time() * 1000),
        "packets": [packet],
    }


@pytest.fixture
def monkeypatch_settings(monkeypatch):
    """Convenience fixture for tests that need to change settings for one test."""
    return monkeypatch
