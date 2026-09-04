"""
TrustPulse AI — Explicit multi-tenant isolation tests.

Tenant A must not read, modify, or evaluate Tenant B's sessions.
"""

import pytest
from httpx import AsyncClient

from tests.conftest import (
    HEADERS,
    TENANT_B,
    make_session_payload,
    make_telemetry_batch,
)


@pytest.mark.asyncio
async def test_tenant_a_cannot_read_tenant_b_session(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-mt-read"), headers=HEADERS)
    resp = await client.get(
        "/v1/sessions/sess-mt-read",
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_tenant_a_cannot_modify_tenant_b_session(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-mt-mod"), headers=HEADERS)
    resp = await client.patch(
        "/v1/sessions/sess-mt-mod/status",
        json={"status": "TERMINATED"},
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_tenant_a_cannot_evaluate_tenant_b_session(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-mt-eval"), headers=HEADERS)
    resp = await client.post(
        "/v1/risk/evaluate",
        json={"session_id": "sess-mt-eval", "action": {"type": "VIEW_BALANCE"}},
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_tenant_a_cannot_send_telemetry_for_tenant_b_event(client: AsyncClient):
    await client.post("/v1/sessions", json=make_session_payload("sess-mt-tel"), headers=HEADERS)
    resp = await client.post(
        "/v1/telemetry",
        json=make_telemetry_batch("sess-mt-tel", seq=1),
        headers={"X-TrustPulse-Tenant-Id": TENANT_B, "Content-Type": "application/json"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted_packets"] == 0
