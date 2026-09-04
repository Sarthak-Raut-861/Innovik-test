"""
TrustPulse AI — Failure mode tests.

Verifies that unavailable dependencies do not silently turn a security decision
into ALLOW.
"""

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.core.redis import redis_manager
from tests.conftest import HEADERS, make_session_payload, make_telemetry_batch


@pytest.mark.asyncio
async def test_redis_fallback_keeps_risk_available(client: AsyncClient):
    """When Redis is not reachable, the app uses fallback and still works."""
    assert redis_manager.is_fallback is True
    await client.post("/v1/sessions", json=make_session_payload("sess-redis"), headers=HEADERS)
    resp = await client.post(
        "/v1/risk/evaluate",
        json={"session_id": "sess-redis", "action": {"type": "VIEW_BALANCE"}},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_database_unavailable_returns_503(client: AsyncClient, monkeypatch):
    import app.services.risk_service as risk_service_mod

    await client.post("/v1/sessions", json=make_session_payload("sess-dbdown"), headers=HEADERS)

    async def boom(*args, **kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(risk_service_mod.SessionRepository, "get_by_session_id", boom)
    resp = await client.post(
        "/v1/risk/evaluate",
        json={"session_id": "sess-dbdown", "action": {"type": "CHANGE_PASSWORD"}},
        headers=HEADERS,
    )
    assert resp.status_code == 503
    body = resp.json()
    message = body.get("error") or body.get("detail") or ""
    assert "fail-safe" in message.lower() or "unavailable" in message.lower()


@pytest.mark.asyncio
async def test_behavioral_engine_failure_does_not_trust_user(client: AsyncClient, monkeypatch):
    import app.services.behavioral_service as behavioral_mod

    def fail(*args, **kwargs):
        raise RuntimeError("behavioral engine exploded")

    monkeypatch.setattr(behavioral_mod.AnomalyEngine, "evaluate_features", fail)
    await client.post("/v1/sessions", json=make_session_payload("sess-behav-fail"), headers=HEADERS)
    resp = await client.post(
        "/v1/risk/evaluate",
        json={
            "session_id": "sess-behav-fail",
            "action": {"type": "LARGE_TRANSFER", "amount": 1000000},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    # Critical action with unknown behavior must not be ALLOW.
    assert data["decision"] in ("BLOCK", "STEP_UP", "ISOLATE")
    assert "BEHAVIOR_ENGINE_UNAVAILABLE" in data["reason_codes"]


@pytest.mark.asyncio
async def test_queue_failure_does_not_fail_ingestion(client: AsyncClient, monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("queue down")

    monkeypatch.setattr(settings, "TELEMETRY_ASYNC_PROCESSING", True)
    monkeypatch.setattr(redis_manager, "queue_push", boom)
    await client.post("/v1/sessions", json=make_session_payload("sess-queue"), headers=HEADERS)
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-queue", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 1


@pytest.mark.asyncio
async def test_telemetry_async_processing_enqueues(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "TELEMETRY_ASYNC_PROCESSING", True)
    await client.post("/v1/sessions", json=make_session_payload("sess-async"), headers=HEADERS)
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-async", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 1

    depth = await redis_manager.queue_depth("test-tenant-001", "telemetry")
    assert depth >= 1
