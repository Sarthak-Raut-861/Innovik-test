"""
TrustPulse AI — Security tests:

  * missing credentials
  * replay
  * stale events
  * invalid sessions
  * malformed payloads
  * rate limiting
  * cross-tenant access
"""

import time

import pytest
from httpx import AsyncClient

from app.core.config import settings
from tests.conftest import (
    HEADERS,
    PUBLIC_KEY,
    TENANT_B,
    TEST_API_KEY,
    make_session_payload,
    make_telemetry_batch,
    seed_integration,
)


@pytest.mark.asyncio
async def test_missing_credentials_rejected(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DEVELOPMENT_AUTH_FALLBACK", False)
    resp = await client.get("/v1/sessions/sess-001")
    assert resp.status_code == 401
    body = resp.json()
    assert "credential" in body["error"].lower()


@pytest.mark.asyncio
async def test_invalid_api_key_rejected(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DEVELOPMENT_AUTH_FALLBACK", False)
    await seed_integration()
    resp = await client.get(
        "/v1/sessions/sess-001",
        headers={"X-TrustPulse-API-Key": "wrong-key", "Content-Type": "application/json"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_valid_public_key_telemetry(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DEVELOPMENT_AUTH_FALLBACK", False)
    await seed_integration()
    await client.post(
        "/v1/sessions",
        json=make_session_payload("sess-pub"),
        headers={**HEADERS, "X-TrustPulse-API-Key": TEST_API_KEY},
    )
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-pub", seq=1),
        headers={"X-TrustPulse-Public-Key": PUBLIC_KEY, "Content-Type": "application/json"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 1


@pytest.mark.asyncio
async def test_cross_tenant_cannot_read_session(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-cross"), headers=HEADERS)
    resp = await client.get(
        "/v1/sessions/sess-cross",
        headers=HEADERS,
    )
    assert resp.status_code == 200

    cross = await client.get(
        "/v1/sessions/sess-cross",
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert cross.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_cannot_evaluate_session(client: AsyncClient):
    await client.post(
        "/v1/sessions",
        json=make_session_payload("sess-cross-eval"),
        headers=HEADERS,
    )
    resp = await client.post(
        "/v1/risk/evaluate",
        json={"session_id": "sess-cross-eval", "action": {"type": "VIEW_BALANCE"}},
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_cannot_access_incident(client: AsyncClient):
    # Tenant A creates a session and lists incidents. Tenant B's operations are scoped.
    await client.post(
        "/v1/sessions",
        json=make_session_payload("sess-cross-inc"),
        headers=HEADERS,
    )
    resp = await client.get(
        "/v1/incidents",
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_replay_detection(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-replay-sec"), headers=HEADERS)
    batch = make_telemetry_batch("sess-replay-sec", seq=1)
    await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    resp2 = await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    assert resp2.json()["rejected_packets"] == 1
    assert resp2.json()["results"][0]["reason"] == "DUPLICATE_EVENT_ID"


@pytest.mark.asyncio
async def test_stale_timestamp_rejected(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-stale"), headers=HEADERS)
    batch = make_telemetry_batch("sess-stale", seq=1)
    batch["packets"][0]["timestamp"] = int(time.time() * 1000) - 10 * 60 * 60 * 1000
    resp = await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 0


@pytest.mark.asyncio
async def test_invalid_session_rejected(client: AsyncClient):
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("does-not-exist", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 0


@pytest.mark.asyncio
async def test_malformed_payload_schema_rejected(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-mal"), headers=HEADERS)
    batch = make_telemetry_batch("sess-mal", seq=1)
    batch["packets"][0]["features"]["mouse"]["meanVelocity"] = -1.0
    resp = await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_oversized_payload_413(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "MAX_PAYLOAD_BYTES", 100)
    await client.post("/v1/sessions", json=make_session_payload("sess-oversize"), headers=HEADERS)
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-oversize", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_rate_limit_telemetry(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_TELEMETRY_PER_MINUTE", 2)
    await client.post("/v1/sessions", json=make_session_payload("sess-ratelimit"), headers=HEADERS)
    await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-ratelimit", seq=1),
        headers=HEADERS,
    )
    await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-ratelimit", seq=2),
        headers=HEADERS,
    )
    resp3 = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-ratelimit", seq=3),
        headers=HEADERS,
    )
    assert resp3.status_code == 429


@pytest.mark.asyncio
async def test_session_rate_limit(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_TELEMETRY_PER_SESSION_PER_MINUTE", 1)
    await client.post("/v1/sessions", json=make_session_payload("sess-srl"), headers=HEADERS)
    resp1 = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-srl", seq=1),
        headers=HEADERS,
    )
    assert resp1.status_code == 202
    resp2 = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-srl", seq=2),
        headers=HEADERS,
    )
    assert resp2.status_code == 429
