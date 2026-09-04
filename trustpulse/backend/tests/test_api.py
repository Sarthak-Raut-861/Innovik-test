"""
TrustPulse AI - Backend Integration Tests

Uses pytest-asyncio with an in-memory SQLite database.
No external services required (Redis falls back to in-memory).
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.main import app
from app.models.base import Base, get_db_session
from app.core.config import settings

# --- Test Database Fixture ---
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DB_URL, echo=False, future=True)
TestSessionFactory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

TENANT_ID = "test-tenant-001"
HEADERS = {
    "X-TrustPulse-Tenant-Id": TENANT_ID,
    "Content-Type": "application/json",
}


@pytest_asyncio.fixture(autouse=True, scope="function")
async def setup_database():
    """Create tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    """AsyncClient against test app with injected in-memory DB."""

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
        yield c

    app.dependency_overrides.clear()


# ==============================================================================
# Health Check Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    resp = await client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == settings.VERSION
    assert "redis_mode" in data


@pytest.mark.asyncio
async def test_readiness_check(client: AsyncClient):
    resp = await client.get("/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


# ==============================================================================
# Session Management Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_register_session(client: AsyncClient):
    resp = await client.post(
        "/v1/sessions",
        json={"session_id": "sess-001", "subject_id": "user-001"},
        headers=HEADERS,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["session_id"] == "sess-001"
    assert data["status"] == "ACTIVE"
    assert "created_at" in data


@pytest.mark.asyncio
async def test_register_duplicate_session_returns_existing(client: AsyncClient):
    """Re-registering an active session should return the existing one, not create a duplicate."""
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-dup", "subject_id": "user-001"},
        headers=HEADERS,
    )
    resp2 = await client.post(
        "/v1/sessions",
        json={"session_id": "sess-dup", "subject_id": "user-001"},
        headers=HEADERS,
    )
    assert resp2.status_code == 201
    assert resp2.json()["session_id"] == "sess-dup"


@pytest.mark.asyncio
async def test_get_session(client: AsyncClient):
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-get"},
        headers=HEADERS,
    )
    resp = await client.get("/v1/sessions/sess-get", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["session_id"] == "sess-get"


@pytest.mark.asyncio
async def test_get_nonexistent_session_returns_404(client: AsyncClient):
    resp = await client.get("/v1/sessions/nonexistent", headers=HEADERS)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_session_status(client: AsyncClient):
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-status"},
        headers=HEADERS,
    )
    resp = await client.patch(
        "/v1/sessions/sess-status/status",
        json={"status": "PAUSED"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "PAUSED"


@pytest.mark.asyncio
async def test_update_session_invalid_status(client: AsyncClient):
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-bad"},
        headers=HEADERS,
    )
    resp = await client.patch(
        "/v1/sessions/sess-bad/status",
        json={"status": "UNKNOWN_STATUS"},
        headers=HEADERS,
    )
    assert resp.status_code in (400, 422)


# ==============================================================================
# Telemetry Ingestion Tests
# ==============================================================================

def make_telemetry_batch(session_id: str, seq: int = 1) -> dict:
    return {
        "batchId": f"batch-{seq}",
        "sentAt": 1725000000000,
        "packets": [
            {
                "sessionId": session_id,
                "sdkInstanceId": "inst-001",
                "eventId": f"evt-{session_id}-{seq}",
                "sequenceNumber": seq,
                "timestamp": 1725000000000,
                "schemaVersion": "1.0.0",
                "sdkVersion": "1.0.0",
                "eventType": "behavioral_batch",
                "features": {
                    "typing": {
                        "sampleCount": 45,
                        "meanDwellTime": 95.3,
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
        ],
    }


@pytest.mark.asyncio
async def test_telemetry_ingestion_success(client: AsyncClient):
    # First register the session
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-telemetry"},
        headers=HEADERS,
    )
    resp = await client.post(
        "/v1/telemetry/batch",
        json=make_telemetry_batch("sess-telemetry", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted_packets"] == 1
    assert data["rejected_packets"] == 0


@pytest.mark.asyncio
async def test_telemetry_replay_detection(client: AsyncClient):
    """Same event_id sent twice should be detected as a replay."""
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-replay"},
        headers=HEADERS,
    )
    batch = make_telemetry_batch("sess-replay", seq=1)
    # First submission
    await client.post("/v1/telemetry/batch", json=batch, headers=HEADERS)
    # Identical second submission — should be rejected as replay
    resp2 = await client.post("/v1/telemetry/batch", json=batch, headers=HEADERS)
    assert resp2.status_code == 202
    assert resp2.json()["rejected_packets"] == 1


@pytest.mark.asyncio
async def test_telemetry_unknown_session(client: AsyncClient):
    """Telemetry for an unregistered session should be rejected."""
    resp = await client.post(
        "/v1/telemetry/batch",
        json=make_telemetry_batch("ghost-session", seq=1),
        headers=HEADERS,
    )
    # Either 404 (first packet raises SessionNotFound and propagates)
    # or 202 with 1 rejected packet (caught internally)
    assert resp.status_code in (202, 404)
    if resp.status_code == 202:
        assert resp.json()["rejected_packets"] >= 1


# ==============================================================================
# Risk Evaluation Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_risk_evaluate_low_risk_action_cold_start(client: AsyncClient):
    """Cold-start session + LOW risk action → ALLOW."""
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-risk-1"},
        headers=HEADERS,
    )
    resp = await client.post(
        "/v1/risk/evaluate",
        json={
            "session_id": "sess-risk-1",
            "action": {"type": "VIEW_BALANCE"},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW"
    assert data["action_risk"] == "LOW"


@pytest.mark.asyncio
async def test_risk_evaluate_critical_action_cold_start(client: AsyncClient):
    """Cold-start session + CRITICAL action → BLOCK or STEP_UP (confidence=40, below HIGH=80)."""
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-risk-2"},
        headers=HEADERS,
    )
    resp = await client.post(
        "/v1/risk/evaluate",
        json={
            "session_id": "sess-risk-2",
            "action": {"type": "LARGE_TRANSFER", "amount": 150000, "currency": "INR"},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    # Cold start → confidence=40 (GUARDED), CRITICAL action → BLOCK
    assert data["decision"] in ("BLOCK", "STEP_UP", "ISOLATE")
    assert data["action_risk"] == "CRITICAL"


@pytest.mark.asyncio
async def test_risk_evaluate_nonexistent_session(client: AsyncClient):
    """Risk evaluation for unknown session → 404."""
    resp = await client.post(
        "/v1/risk/evaluate",
        json={
            "session_id": "ghost-session",
            "action": {"type": "VIEW_BALANCE"},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_risk_high_amount_escalates_risk(client: AsyncClient):
    """A CHANGE_SETTINGS action with amount ≥ 100,000 escalates to CRITICAL."""
    await client.post(
        "/v1/sessions",
        json={"session_id": "sess-risk-3"},
        headers=HEADERS,
    )
    resp = await client.post(
        "/v1/risk/evaluate",
        json={
            "session_id": "sess-risk-3",
            "action": {"type": "CHANGE_SETTINGS", "amount": 200000, "currency": "USD"},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["action_risk"] == "CRITICAL"
