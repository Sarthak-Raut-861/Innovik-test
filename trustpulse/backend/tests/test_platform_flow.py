"""TRUSTPULSE — End-to-end platform API flow (Phase 1).

login → session → telemetry → TCI → trust state → SOC dashboard,
plus the privacy guard and the authentication boundary.
"""

from __future__ import annotations

import json

import pytest
import pytest_asyncio

from app.services.platform.seed_service import SeedService
from tests.conftest import TENANT_ID, TEST_API_KEY, TestSessionFactory, seed_integration

API = "/api/v1"
PASSWORD = "TrustDemo!234"
AUTH = {"X-TrustPulse-API-Key": TEST_API_KEY, "Content-Type": "application/json"}

ALICE_DEVICE = {
    "fingerprint": "dev-alice-work-macbook-a1b2c3",
    "label": "alice-work-macbook",
    "platform": "macOS",
    "browser": "Chrome",
}
NORMAL_FEATURES = {
    "typing": {
        "meanDwellTime": 114.0,
        "dwellStdDev": 25.0,
        "meanFlightTime": 90.0,
        "flightStdDev": 30.0,
        "typingSpeed": 6.0,
        "pauseRate": 0.13,
    },
    "mouse": {
        "meanVelocity": 830.0,
        "velocityStdDev": 255.0,
        "meanAcceleration": 2150.0,
        "directionChangeRate": 3.3,
        "totalDistance": 18000.0,
        "movementDuration": 4100.0,
        "meanPauseTime": 335.0,
    },
    "click": {
        "clickCount": 17,
        "meanInterval": 930.0,
        "intervalStdDev": 300.0,
        "clickFrequency": 1.1,
    },
    "scroll": {
        "meanVelocity": 1520.0,
        "totalDistance": 9100.0,
        "meanPauseDuration": 610.0,
        "eventRate": 6.1,
    },
}
ATTACKER_FEATURES = {
    "typing": {
        "meanDwellTime": 380.0,
        "dwellStdDev": 12.0,
        "meanFlightTime": 300.0,
        "flightStdDev": 9.0,
        "typingSpeed": 2.1,
        "pauseRate": 0.02,
    },
    "mouse": {
        "meanVelocity": 9000.0,
        "velocityStdDev": 60.0,
        "meanAcceleration": 41000.0,
        "directionChangeRate": 0.4,
        "totalDistance": 92000.0,
        "movementDuration": 900.0,
        "meanPauseTime": 40.0,
    },
    "click": {
        "clickCount": 64,
        "meanInterval": 155.0,
        "intervalStdDev": 12.0,
        "clickFrequency": 6.4,
    },
    "scroll": {
        "meanVelocity": 18000.0,
        "totalDistance": 240000.0,
        "meanPauseDuration": 30.0,
        "eventRate": 42.0,
    },
}


@pytest_asyncio.fixture
async def seeded(client):
    """Seeds the integration credential and the TrustDev demo tenant."""
    await seed_integration(tenant_id=TENANT_ID, api_key=TEST_API_KEY)
    async with TestSessionFactory() as db:
        service = SeedService(db, TENANT_ID)
        summary = await service.run(baseline_observations=20)
        await db.commit()
    return summary


async def login(client, *, username="alice.chen", mfa="123456", device=None, network=None):
    payload = {
        "username": username,
        "password": PASSWORD,
        "mfa_code": mfa,
        "device": device or ALICE_DEVICE,
        "network": network or {"country": "US", "asn": "AS15169"},
    }
    return await client.post(f"{API}/auth/login", headers=AUTH, json=payload)


async def send_telemetry(client, session_id, features, source="SDK", flat=None):
    return await client.post(
        f"{API}/telemetry",
        headers=AUTH,
        json={
            "session_id": session_id,
            "features": features,
            "flat_features": flat,
            "source": source,
        },
    )


# ----------------------------------------------------------------- happy path
@pytest.mark.asyncio
async def test_login_opens_a_trusted_session(client, seeded):
    response = await login(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token"]
    session = body["session"]
    assert session["status"] == "ACTIVE"
    assert session["username"] == "alice.chen"
    assert session["auth_method"] == "PASSWORD_MFA"
    assert session["mfa_used"] is True
    assert body["trust"]["session_id"] == session["session_id"]
    assert body["trust"]["tci"] >= 80, body["trust"]["tci"]
    assert body["trust"]["state"] == "TRUSTED"
    # High trust on LOW confidence at login: no behavioral observation yet. The
    # score and the strength of the evidence behind it are reported separately.
    assert body["trust"]["confidence"] == "LOW"
    assert "FACTOR_UNAVAILABLE:network" in body["trust"]["warnings"]


@pytest.mark.asyncio
async def test_normal_behavior_keeps_trust_high(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]

    for _ in range(3):
        response = await send_telemetry(client, session_id, NORMAL_FEATURES)
        assert response.status_code == 200, response.text

    body = response.json()
    assert body["accepted"] is True
    assert body["features_received"] >= 10
    assert body["anomaly_score"] < 0.2
    assert body["trust"]["tci"] >= 85, body["trust"]["tci"]
    assert body["trust"]["state"] == "TRUSTED"
    assert body["trust"]["confidence"] in {"MEDIUM", "HIGH"}
    assert {factor["name"] for factor in body["trust"]["factors"]} == {
        "identity",
        "device",
        "behavior",
        "network",
        "session",
        "history",
    }


@pytest.mark.asyncio
async def test_takeover_behavior_drops_trust_and_produces_evidence(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    for _ in range(3):
        await send_telemetry(client, session_id, NORMAL_FEATURES)
    healthy = (await send_telemetry(client, session_id, NORMAL_FEATURES)).json()

    attacker = (await send_telemetry(client, session_id, ATTACKER_FEATURES)).json()
    assert attacker["anomaly_score"] > 0.5
    assert attacker["trust"]["tci"] < healthy["trust"]["tci"]
    evidence_types = {item["type"] for item in attacker["trust"]["evidence"]}
    assert evidence_types & {"BEHAVIOR_DEVIATION", "BASELINE_DEVIATION"}, evidence_types


SEVERITY = {"TRUSTED": 0, "DEGRADED": 1, "SUSPICIOUS": 2, "CRITICAL": 3, "BLOCKED": 4}


@pytest.mark.asyncio
async def test_a_sharp_trust_collapse_escalates_immediately(client, seeded):
    """A single observation that collapses the TCI must not be held by hysteresis."""
    session_id = (await login(client)).json()["session"]["session_id"]
    for _ in range(3):
        await send_telemetry(client, session_id, NORMAL_FEATURES)
    healthy = (await send_telemetry(client, session_id, NORMAL_FEATURES)).json()["trust"]
    assert healthy["state"] == "TRUSTED"

    first_attack = (await send_telemetry(client, session_id, ATTACKER_FEATURES)).json()["trust"]
    assert first_attack["state_changed"] is True
    assert SEVERITY[first_attack["state"]] > SEVERITY["TRUSTED"]
    assert healthy["tci"] - first_attack["tci"] > 15  # beyond the decisive-drop threshold


@pytest.mark.asyncio
async def test_repeated_anomalies_keep_eroding_trust(client, seeded):
    """Evidence accumulation: a sustained deviation must not plateau immediately."""
    session_id = (await login(client)).json()["session"]["session_id"]
    for _ in range(3):
        await send_telemetry(client, session_id, NORMAL_FEATURES)

    tci_series = []
    for _ in range(5):
        body = (await send_telemetry(client, session_id, ATTACKER_FEATURES)).json()
        tci_series.append(body["trust"]["tci"])

    assert tci_series[0] > tci_series[-1], tci_series
    # The first three samples must fall monotonically, not flatten at once.
    assert tci_series[0] > tci_series[1] > tci_series[2], tci_series


@pytest.mark.asyncio
async def test_sustained_attacker_behavior_escalates_the_trust_state(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    for _ in range(3):
        await send_telemetry(client, session_id, NORMAL_FEATURES)

    states = []
    for _ in range(6):
        body = (await send_telemetry(client, session_id, ATTACKER_FEATURES)).json()
        states.append(body["trust"]["state"])

    assert states[-1] != "TRUSTED", states
    assert all(
        SEVERITY[b] >= SEVERITY[a] for a, b in zip(states, states[1:], strict=False)
    ), f"trust improved during an attack: {states}"
    assert SEVERITY[states[-1]] >= SEVERITY["SUSPICIOUS"], states


@pytest.mark.asyncio
async def test_takeover_from_a_new_device_on_a_new_network_is_flagged_at_login(client, seeded):
    """Device + network + identity change alone is enough to distrust a session."""
    response = await client.post(
        f"{API}/session",
        headers=AUTH,
        json={
            "user_id": "U001",
            "device": {
                "fingerprint": "dev-unknown-vps-headless-z9y8x7",
                "label": "unknown-headless-vps",
            },
            "network": {
                "country": "RU",
                "asn": "AS48666",
                "is_vpn": True,
                "is_proxy_or_tor": True,
            },
            "auth_method": "PASSWORD",
            "mfa_used": False,
        },
    )
    assert response.status_code == 200, response.text
    trust = response.json()["trust"]
    assert trust["tci"] < 60, trust["tci"]
    assert trust["state"] in {"SUSPICIOUS", "CRITICAL", "BLOCKED"}
    factors = {factor["name"]: factor for factor in trust["factors"]}
    # 100 - vpn_penalty(20) - tor_penalty(45); with a country baseline it would
    # also lose the "new country" credit and land at 0.
    assert factors["network"]["score"] <= 40
    assert {"VPN_DETECTED", "PROXY_OR_TOR_DETECTED"} <= set(factors["network"]["reasons"])
    assert factors["device"]["score"] < 70
    assert {"NEW_DEVICE", "DEVICE_KNOWN_NOT_REGISTERED"} & set(factors["device"]["reasons"])
    assert "DEVICE_LOW_HISTORY" in factors["device"]["reasons"]
    assert factors["identity"]["score"] < 70
    evidence_types = {item["type"] for item in trust["evidence"]}
    assert "DEVICE_CHANGE" in evidence_types


@pytest.mark.asyncio
async def test_trust_endpoint_returns_the_current_assessment(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await send_telemetry(client, session_id, NORMAL_FEATURES)

    response = await client.get(f"{API}/trust/{session_id}", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["session_id"] == session_id
    assert 0 <= body["tci"] <= 100
    assert body["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert body["trend"] in {"RISING", "STABLE", "FALLING", "INSUFFICIENT_DATA"}


@pytest.mark.asyncio
async def test_tci_history_is_recorded(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    for _ in range(4):
        await send_telemetry(client, session_id, NORMAL_FEATURES)

    response = await client.get(f"{API}/trust/{session_id}/history", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert len(body["points"]) >= 5  # login + 4 telemetry evaluations
    assert all("tci" in point for point in body["points"])


# ------------------------------------------------------------------- SOC views
@pytest.mark.asyncio
async def test_soc_overview_reports_headline_metrics(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await send_telemetry(client, session_id, NORMAL_FEATURES)

    response = await client.get(f"{API}/soc/overview", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["active_sessions"] >= 1
    assert body["average_tci"] is not None
    assert body["trust_model_version"]
    assert "not a probability" in body["disclaimer"]


@pytest.mark.asyncio
async def test_soc_session_list_and_detail(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    for _ in range(2):
        await send_telemetry(client, session_id, NORMAL_FEATURES)

    listing = await client.get(f"{API}/soc/sessions", headers=AUTH)
    assert listing.status_code == 200
    rows = listing.json()
    assert any(row["session_id"] == session_id for row in rows)

    detail = await client.get(f"{API}/soc/sessions/{session_id}", headers=AUTH)
    assert detail.status_code == 200
    body = detail.json()
    assert body["session"]["session_id"] == session_id
    assert body["trust"]["factors"]
    assert len(body["tci_history"]) >= 3
    assert body["baselines"]["core"]["observations"] > 0
    assert body["baselines"]["core"]["features"] > 0


@pytest.mark.asyncio
async def test_users_and_devices_are_listed(client, seeded):
    users = await client.get(f"{API}/users", headers=AUTH)
    assert users.status_code == 200
    usernames = {user["username"] for user in users.json()}
    assert {"alice.chen", "marcus.reed", "priya.nair"} <= usernames

    devices = await client.get(f"{API}/devices", headers=AUTH)
    assert devices.status_code == 200
    assert len(devices.json()) >= 4  # three user devices + the attacker VPS


# ------------------------------------------------------------- privacy & auth
@pytest.mark.asyncio
async def test_raw_typed_characters_are_rejected(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    response = await send_telemetry(
        client, session_id, {"typing": {"characters": "hunter2", "meanDwellTime": 110.0}}
    )
    assert response.status_code == 422
    assert "Raw behavioral data" in response.json()["error"]


@pytest.mark.asyncio
async def test_raw_text_values_are_rejected(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    response = await send_telemetry(
        client, session_id, {"typing": {"meanDwellTime": 110.0, "note": "user typed a sentence"}}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_wrong_password_is_rejected(client, seeded):
    response = await client.post(
        f"{API}/auth/login",
        headers=AUTH,
        json={
            "username": "alice.chen",
            "password": "wrong-password",
            "device": ALICE_DEVICE,
        },
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_unknown_user_and_bad_password_return_the_same_error(client, seeded):
    """No user enumeration."""
    unknown = await client.post(
        f"{API}/auth/login",
        headers=AUTH,
        json={"username": "no-such-user", "password": "whatever", "device": ALICE_DEVICE},
    )
    bad = await client.post(
        f"{API}/auth/login",
        headers=AUTH,
        json={"username": "alice.chen", "password": "wrong", "device": ALICE_DEVICE},
    )
    assert unknown.status_code == bad.status_code == 401
    assert unknown.json()["error"] == bad.json()["error"]


@pytest.mark.asyncio
async def test_mfa_is_required_when_enabled(client, seeded):
    response = await login(client, mfa=None)
    assert response.status_code == 401
    assert "MFA" in response.json()["error"]


@pytest.mark.asyncio
async def test_calls_without_a_valid_api_key_are_rejected(client, seeded):
    response = await client.get(
        f"{API}/soc/overview", headers={"X-TrustPulse-API-Key": "not-a-real-key"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_unknown_session_returns_404(client, seeded):
    response = await client.get(f"{API}/trust/does-not-exist", headers=AUTH)
    assert response.status_code == 404


# --------------------------------------------------------------- lifecycle
@pytest.mark.asyncio
async def test_session_can_be_ended_and_is_no_longer_active(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await send_telemetry(client, session_id, NORMAL_FEATURES)

    response = await client.post(f"{API}/session/{session_id}/end", headers=AUTH)
    assert response.status_code == 200
    assert response.json()["status"] == "TERMINATED"

    overview = (await client.get(f"{API}/soc/overview", headers=AUTH)).json()
    assert overview["active_sessions"] == 0


@pytest.mark.asyncio
async def test_server_side_session_registration_works(client, seeded):
    response = await client.post(
        f"{API}/session",
        headers=AUTH,
        json={
            "user_id": "U002",
            "device": {
                "fingerprint": "dev-marcus-thinkpad-x1-d4e5f6",
                "label": "marcus-thinkpad",
            },
            "network": {"country": "GB", "asn": "AS2856"},
            "auth_method": "PASSWORD",
            "mfa_used": False,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user_id"] == "U002"
    assert body["trust_state"] in {"TRUSTED", "DEGRADED", "SUSPICIOUS", "CRITICAL", "BLOCKED"}


# ------------------------------------------------------------- transparency
@pytest.mark.asyncio
async def test_trust_model_configuration_is_exposed(client, seeded):
    response = await client.get(f"{API}/config/trust-model", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["weights"]["behavior"] == 0.30
    assert body["state_bands"][0]["state"] == "TRUSTED"
    assert body["hysteresis"]["escalation_confirmations"] == 2
    assert "BEHAVIOR_DEVIATION" in body["evidence_types"]
    assert "not a probability" in body["disclaimer"]


@pytest.mark.asyncio
async def test_action_catalogue_is_exposed(client, seeded):
    response = await client.get(f"{API}/config/actions", headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["actions"]["CREATE_API_KEY"]["risk"] == 90
    assert body["actions"]["VIEW_DASHBOARD"]["risk"] == 10
    assert {"min_risk", "band"} <= set(body["bands"][0].keys())


@pytest.mark.asyncio
async def test_platform_health_reports_dependencies(client, seeded):
    response = await client.get(f"{API}/platform/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["trust_model_version"]


@pytest.mark.asyncio
async def test_baseline_learning_is_reported_in_the_telemetry_response(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    body = (await send_telemetry(client, session_id, NORMAL_FEATURES)).json()
    assert body["learned"]["core_observations"] > 0
    assert "promotion" in body["learned"]
    assert "shadow_learned" in body["learned"]


@pytest.mark.asyncio
async def test_openapi_documents_the_platform_api(client, seeded):
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    paths = set(json.loads(response.text)["paths"].keys())
    for expected in (
        "/api/v1/auth/login",
        "/api/v1/session",
        "/api/v1/telemetry",
        "/api/v1/trust/evaluate",
        "/api/v1/trust/{session_id}",
        "/api/v1/soc/overview",
    ):
        assert expected in paths
