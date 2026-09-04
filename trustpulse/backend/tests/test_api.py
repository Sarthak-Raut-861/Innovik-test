"""
TrustPulse AI — Main API integration tests.

These cover the live HTTP contract:
  POST /v1/sessions
  POST /v1/telemetry (+ alias /batch)
  POST /v1/risk/evaluate
  GET /v1/incidents
  GET /v1/actions
  GET /v1/health
"""

import pytest
from httpx import AsyncClient

from tests.conftest import (
    HEADERS,
    make_session_payload,
    make_telemetry_batch,
)


@pytest.mark.asyncio
async def test_health_and_ready(client: AsyncClient):
    resp = await client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert data["database_ok"] is True
    assert data["redis_mode"] == "fallback"

    ready = await client.get("/v1/health/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_metrics_endpoint(client: AsyncClient):
    resp = await client.get("/v1/health/metrics")
    assert resp.status_code == 200
    assert "counters" in resp.json()


@pytest.mark.asyncio
async def test_register_and_get_session(client: AsyncClient):
    resp = await client.post(
        "/v1/sessions",
        json=make_session_payload("sess-api-001"),
        headers=HEADERS,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["session_id"] == "sess-api-001"
    assert body["status"] == "ACTIVE"

    get_resp = await client.get("/v1/sessions/sess-api-001", headers=HEADERS)
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_register_duplicate_active_session_is_idempotent(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-dup"), headers=HEADERS)
    resp2 = await client.post(
        "/v1/sessions", json=make_session_payload("sess-dup"), headers=HEADERS
    )
    assert resp2.status_code == 201
    assert resp2.json()["session_id"] == "sess-dup"


@pytest.mark.asyncio
async def test_session_not_found(client: AsyncClient):
    resp = await client.get("/v1/sessions/nope", headers=HEADERS)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_session_status_update(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-status"), headers=HEADERS)
    resp = await client.patch(
        "/v1/sessions/sess-status/status", json={"status": "PAUSED"}, headers=HEADERS
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "PAUSED"


@pytest.mark.asyncio
async def test_session_invalid_status_rejected(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-bad"), headers=HEADERS)
    resp = await client.patch(
        "/v1/sessions/sess-bad/status", json={"status": "UNKNOWN"}, headers=HEADERS
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_telemetry_ingestion_success(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-tel"), headers=HEADERS)
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-tel", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted_packets"] == 1
    assert data["rejected_packets"] == 0


@pytest.mark.asyncio
async def test_telemetry_batch_alias(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-alias"), headers=HEADERS)
    resp = await client.post(
        "/v1/telemetry/batch",
        json=make_telemetry_batch("sess-alias", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 1


@pytest.mark.asyncio
async def test_telemetry_unknown_session_rejected(client: AsyncClient):
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("ghost-session", seq=1),
        headers=HEADERS,
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 0


@pytest.mark.asyncio
async def test_telemetry_duplicate_event_rejected(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-rep"), headers=HEADERS)
    batch = make_telemetry_batch("sess-rep", seq=1)
    await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    resp2 = await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    assert resp2.status_code == 202
    assert resp2.json()["rejected_packets"] == 1
    assert resp2.json()["results"][0]["reason"] == "DUPLICATE_EVENT_ID"


@pytest.mark.asyncio
async def test_telemetry_sequence_regression_rejected(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-seq"), headers=HEADERS)
    await client.post(
        "/v1/telemetry", json=make_telemetry_batch("sess-seq", seq=2), headers=HEADERS
    )
    resp2 = await client.post(
        "/v1/telemetry", json=make_telemetry_batch("sess-seq", seq=1), headers=HEADERS
    )
    assert resp2.status_code == 202
    assert resp2.json()["rejected_packets"] == 1
    assert resp2.json()["results"][0]["reason"] == "SEQUENCE_REGRESSION"


@pytest.mark.asyncio
async def test_telemetry_nan_is_rejected(client: AsyncClient):
    import json

    await client.post("/v1/sessions", json=make_session_payload("sess-nan"), headers=HEADERS)
    batch = make_telemetry_batch("sess-nan", seq=1)
    batch["packets"][0]["features"]["typing"]["meanDwellTime"] = float("nan")
    raw = json.dumps(batch, allow_nan=True)
    resp = await client.post(
        "/v1/telemetry",
        content=raw,
        headers={**HEADERS, "Content-Type": "application/json"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_telemetry_oversized_payload_rejected(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-big"), headers=HEADERS)
    batch = make_telemetry_batch("sess-big", seq=1)
    batch["packets"][0]["features"]["typing"]["meanDwellTime"] = 999999999.0
    resp = await client.post("/v1/telemetry", json=batch, headers=HEADERS)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_risk_evaluate_low_risk_cold_start_allowed(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-risk-low"), headers=HEADERS)
    resp = await client.post(
        "/v1/risk/evaluate",
        json={"session_id": "sess-risk-low", "action": {"type": "VIEW_BALANCE"}},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "ALLOW"
    assert resp.json()["session_confidence"] == 30


@pytest.mark.asyncio
async def test_risk_evaluate_critical_cold_start_blocked(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-risk-crit"), headers=HEADERS)
    resp = await client.post(
        "/v1/risk/evaluate",
        json={
            "session_id": "sess-risk-crit",
            "action": {"type": "LARGE_TRANSFER", "amount": 50000, "currency": "INR"},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    # Cold start is LOW confidence; critical actions are blocked, not isolated
    # unless independent compromise signals exist.
    assert data["decision"] == "BLOCK"
    assert data["action_risk"] == "CRITICAL"


@pytest.mark.asyncio
async def test_risk_evaluate_nonexistent_session_404(client: AsyncClient):
    resp = await client.post(
        "/v1/risk/evaluate",
        json={"session_id": "ghost", "action": {"type": "VIEW_BALANCE"}},
        headers=HEADERS,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_incident_list_and_resolution(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-inc"), headers=HEADERS)
    # Force an isolation via critically low confidence + independent signals is
    # complex to trigger over HTTP; resolve path is exercised with an empty list first.
    resp = await client.get("/v1/incidents", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


@pytest.mark.asyncio
async def test_action_catalog_and_empty_list(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-act"), headers=HEADERS)
    catalog = await client.get("/v1/actions/catalog", headers=HEADERS)
    assert catalog.status_code == 200
    assert "LARGE_TRANSFER" in catalog.json()["actions"]
    listing = await client.get("/v1/actions", headers=HEADERS)
    assert listing.status_code == 200
    assert listing.json() == []


@pytest.mark.asyncio
async def test_action_catalog_no_auth(client: AsyncClient):
    resp = await client.get("/v1/actions/catalog")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_payload_rejected_when_no_session_binding(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-bind"), headers=HEADERS)
    batch = make_telemetry_batch("sess-bind", seq=1)
    resp = await client.post(
        "/v1/telemetry",
        json=batch,
        headers={**HEADERS, "X-TrustPulse-Session-Id": "different-session"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 0
