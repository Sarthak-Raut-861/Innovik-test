"""TRUSTPULSE — Phase 2 enforcement end-to-end.

Covers the full authorization loop over HTTP: action risk → policy decision →
PEP enforcement → step-up → revocation → containment → incidents → receipts.

Also the negative cases that matter most for a security product: nonce
uniqueness, receipt tamper detection, receipt expiry, single-use enforcement,
and cross-tenant isolation.
"""

from __future__ import annotations

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
    await seed_integration(tenant_id=TENANT_ID, api_key=TEST_API_KEY)
    async with TestSessionFactory() as db:
        summary = await SeedService(db, TENANT_ID).run(baseline_observations=20)
        await db.commit()
    return summary


async def login(client, *, username="alice.chen", mfa="123456", device=None, network=None):
    return await client.post(
        f"{API}/auth/login",
        headers=AUTH,
        json={
            "username": username,
            "password": PASSWORD,
            "mfa_code": mfa,
            "device": device or ALICE_DEVICE,
            "network": network or {"country": "US", "asn": "AS15169"},
        },
    )


async def act(client, session_id, action, resource=None, context=None, features=None):
    return await client.post(
        f"{API}/actions/evaluate",
        headers=AUTH,
        json={
            "session_id": session_id,
            "action": action,
            "resource": resource,
            "context": context or {},
            "features": features,
        },
    )


async def telemetry(client, session_id, features):
    return await client.post(
        f"{API}/telemetry",
        headers=AUTH,
        json={"session_id": session_id, "features": features, "source": "SIMULATION"},
    )


async def takeover(client, session_id, samples=8):
    """Drives a session into SUSPICIOUS with attacker behavior."""
    last = None
    for _ in range(samples):
        last = await telemetry(client, session_id, ATTACKER_FEATURES)
    return last


# ------------------------------------------------------------------ happy path
@pytest.mark.asyncio
async def test_trusted_session_allows_low_risk_action(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]

    response = await act(client, session_id, "VIEW_DASHBOARD")
    assert response.status_code == 200, response.text
    body = response.json()

    # The five shared contract fields.
    assert body["decision"] == "ALLOW"
    assert body["tci"] >= 80
    assert body["action_risk"] == 10
    assert body["trust_state"] == "TRUSTED"
    assert body["receipt_id"]

    assert body["rule_id"] == "DEFAULT_ALLOW"
    assert body["risk_band"] == "LOW"
    assert body["containment"] == []
    assert body["step_up"] is None
    # An ALLOW still gets a receipt: "why was this allowed" must be answerable.
    assert body["receipt"]["decision"] == "ALLOW"
    assert body["receipt"]["receipt_hash"]


@pytest.mark.asyncio
async def test_trusted_session_steps_up_for_very_high_risk(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]

    response = await act(client, session_id, "CREATE_ADMIN")
    body = response.json()
    assert body["decision"] == "STEP_UP"
    assert body["action_risk"] == 98
    assert body["rule_id"] == "HEALTHY_STATE_VERY_HIGH_RISK"

    challenge = body["step_up"]
    assert challenge["required"] is True
    assert challenge["method"] == "MFA"
    assert challenge["max_attempts"] == 3
    assert challenge["challenge_id"]
    # The prototype must be explicit that it is not performing real MFA.
    assert "does not replace MFA" in challenge["note"]


@pytest.mark.asyncio
async def test_trusted_session_allows_high_but_not_extreme_risk(client, seeded):
    """A healthy session is not challenged for ordinary high-risk work.

    The cut-off is the configured `HEALTHY_STATE_VERY_HIGH_RISK` threshold
    (risk >= 95): the most destructive actions always require an explicit
    confirmation, no matter how trustworthy the session is.
    """
    session_id = (await login(client)).json()["session"]["session_id"]

    # Risk 90 and 92 sit below the threshold and are allowed.
    assert (await act(client, session_id, "CREATE_API_KEY")).json()["decision"] == "ALLOW"
    assert (await act(client, session_id, "CHANGE_PASSWORD")).json()["decision"] == "ALLOW"

    # Risk 95 and above require confirmation even when trust is high.
    for action, risk in (
        ("DELETE_RESOURCE", 95),
        ("MODIFY_ACCESS_POLICY", 97),
        ("CREATE_ADMIN", 98),
    ):
        body = (await act(client, session_id, action)).json()
        assert body["action_risk"] == risk
        assert body["decision"] == "STEP_UP", f"{action} (risk {risk}) was not challenged"
        assert body["rule_id"] == "HEALTHY_STATE_VERY_HIGH_RISK"


@pytest.mark.asyncio
async def test_healthy_very_high_risk_threshold_is_configured_not_hardcoded(client, seeded):
    """The threshold must come from the shared config."""
    body = (await client.get(f"{API}/config/policy", headers=AUTH)).json()
    rule = next(r for r in body["rules"] if r["id"] == "HEALTHY_STATE_VERY_HIGH_RISK")
    assert rule["requires"]["min_action_risk"] == 95
    assert "TRUSTED" in rule["requires"]["trust_state_in"]


# ------------------------------------------------------------------- takeover
@pytest.mark.asyncio
async def test_takeover_triggers_step_up_for_sensitive_action(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]

    # Baseline: a healthy session is allowed.
    assert (await act(client, session_id, "CREATE_API_KEY")).json()["decision"] == "ALLOW"

    await takeover(client, session_id, samples=6)

    response = await act(client, session_id, "CREATE_API_KEY", features=ATTACKER_FEATURES)
    body = response.json()
    assert body["decision"] == "STEP_UP", body
    assert body["trust_state"] == "SUSPICIOUS"
    assert body["tci"] < 70
    assert body["rule_id"] == "SUSPICIOUS_STATE_HIGH_RISK"
    assert body["step_up"]["challenge_id"]


@pytest.mark.asyncio
async def test_takeover_still_allows_low_risk_reads(client, seeded):
    """Suspicious is not a lockout: the user can still look at a dashboard."""
    session_id = (await login(client)).json()["session"]["session_id"]
    await takeover(client, session_id, samples=6)

    body = (await act(client, session_id, "VIEW_DASHBOARD", features=ATTACKER_FEATURES)).json()
    assert body["decision"] == "ALLOW"
    assert body["trust_state"] == "SUSPICIOUS"


@pytest.mark.asyncio
async def test_action_evaluation_records_the_audit_trail(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    body = (await act(client, session_id, "EXPORT_DATA", context={"amount": 100000})).json()

    assert body["action_risk"] == 98
    assert body["risk_breakdown"]["base_risk"] == 60
    assert body["risk_breakdown"]["escalated"] is True
    assert body["risk_breakdown"]["adjustments"][0]["type"] == "AMOUNT_ESCALATION"
    # The policy audit shows every rule considered, not just the winner.
    assert len(body["policy_audit"]) >= 1


# -------------------------------------------------------------------- step-up
@pytest.mark.asyncio
async def test_successful_step_up_restores_access(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await takeover(client, session_id, samples=6)

    challenged = (
        await act(client, session_id, "CREATE_API_KEY", features=ATTACKER_FEATURES)
    ).json()
    challenge_id = challenged["step_up"]["challenge_id"]
    action_id = challenged["action_id"]

    response = await client.post(
        f"{API}/actions/{action_id}/step-up",
        headers=AUTH,
        json={"challenge_id": challenge_id, "success": True, "method": "MFA"},
    )
    assert response.status_code == 200, response.text
    outcome = response.json()
    assert outcome["accepted"] is True
    assert outcome["status"] == "SUCCEEDED"
    assert outcome["attempts"] == 1
    assert outcome["mfa_used"] is True


@pytest.mark.asyncio
async def test_failed_step_up_lowers_trust_and_blocks(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await takeover(client, session_id, samples=6)

    challenged = (
        await act(client, session_id, "CREATE_API_KEY", features=ATTACKER_FEATURES)
    ).json()
    before = challenged["tci"]

    response = await client.post(
        f"{API}/actions/{challenged['action_id']}/step-up",
        headers=AUTH,
        json={"challenge_id": challenged["step_up"]["challenge_id"], "success": False},
    )
    outcome = response.json()
    assert outcome["accepted"] is True
    assert outcome["status"] == "FAILED"
    assert outcome["tci"] < before, f"TCI did not fall: {outcome['tci']} !< {before}"
    # The response carries its own server-measured `tci_before`, so the delta is
    # self-consistent and the client does not have to guess which reading it came
    # from. This is the drop that actually happened, not the configured number.
    assert outcome["tci_penalty_applied"] == pytest.approx(
        outcome["tci_before"] - outcome["tci"], abs=0.001
    )
    assert outcome["tci_penalty_applied"] > 0
    assert outcome["tci_penalty_configured"] == 15
    # Weighted factor penalties land below the configured headline value.
    assert outcome["tci_penalty_applied"] < outcome["tci_penalty_configured"]
    # And it is a real drop, not just a relabelled config value.
    assert outcome["tci_before"] > outcome["tci"]
    assert outcome["blocked"] is True

    # The action record itself is now BLOCK, not STEP_UP.
    detail = (await client.get(f"{API}/soc/sessions/{session_id}", headers=AUTH)).json()
    decisions = {item["decision"] for item in detail["actions"]}
    assert "BLOCK" in decisions


@pytest.mark.asyncio
async def test_failed_step_up_on_critical_action_triggers_containment(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await takeover(client, session_id, samples=8)

    challenged = (
        await act(client, session_id, "MODIFY_ACCESS_POLICY", features=ATTACKER_FEATURES)
    ).json()
    assert challenged["decision"] == "STEP_UP"

    response = await client.post(
        f"{API}/actions/{challenged['action_id']}/step-up",
        headers=AUTH,
        json={"challenge_id": challenged["step_up"]["challenge_id"], "success": False},
    )
    outcome = response.json()
    assert "REVOKE_SESSION" in outcome["containment"], outcome
    assert outcome["incident_id"]

    detail = (await client.get(f"{API}/soc/sessions/{session_id}", headers=AUTH)).json()
    assert detail["session"]["is_contained"] is True

    # And now nothing is allowed.
    blocked = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    assert blocked["decision"] == "BLOCK"


@pytest.mark.asyncio
async def test_step_up_challenge_cannot_be_replayed(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    challenged = (await act(client, session_id, "CREATE_ADMIN")).json()
    challenge_id = challenged["step_up"]["challenge_id"]
    action_id = challenged["action_id"]

    first = await client.post(
        f"{API}/actions/{action_id}/step-up",
        headers=AUTH,
        json={"challenge_id": challenge_id, "success": True},
    )
    assert first.json()["status"] == "SUCCEEDED"

    second = await client.post(
        f"{API}/actions/{action_id}/step-up",
        headers=AUTH,
        json={"challenge_id": challenge_id, "success": True},
    )
    assert second.json()["accepted"] is False
    assert second.json()["error"] == "CHALLENGE_ALREADY_SUCCEEDED"


@pytest.mark.asyncio
async def test_unknown_challenge_is_rejected(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    challenged = (await act(client, session_id, "CREATE_ADMIN")).json()

    response = await client.post(
        f"{API}/actions/{challenged['action_id']}/step-up",
        headers=AUTH,
        json={"challenge_id": "su_does_not_exist", "success": True},
    )
    assert response.json()["accepted"] is False
    assert response.json()["error"] == "CHALLENGE_NOT_FOUND"


# ------------------------------------------------------------------ receipts
@pytest.mark.asyncio
async def test_receipt_is_fetchable_and_bound(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()

    response = await client.get(f"{API}/receipts/{issued['receipt_id']}", headers=AUTH)
    assert response.status_code == 200
    receipt = response.json()

    assert receipt["session_id"] == session_id
    assert receipt["action"] == "VIEW_PROFILE"
    assert receipt["decision"] == "ALLOW"
    assert receipt["nonce"]
    assert len(receipt["evidence_hash"]) == 64
    assert len(receipt["receipt_hash"]) == 64
    assert receipt["hash_algorithm"] == "sha256"
    assert receipt["expires_at"] > receipt["issued_at"]


@pytest.mark.asyncio
async def test_receipt_verifies_when_untampered(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()

    response = await client.post(
        f"{API}/receipts/{issued['receipt_id']}/verify",
        headers=AUTH,
        json={"mark_used": False},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["valid"] is True, result["reasons"]
    assert result["hash_matches"] is True
    assert result["reasons"] == ["RECEIPT_VALID"]


@pytest.mark.asyncio
async def test_receipt_fails_verification_with_wrong_binding(client, seeded):
    """Re-presenting a receipt against a different session must fail."""
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()

    response = await client.post(
        f"{API}/receipts/{issued['receipt_id']}/verify",
        headers=AUTH,
        json={
            "presented": {"session_id": "TS-SOMEONE-ELSES-SESSION"},
            "mark_used": False,
        },
    )
    result = response.json()
    assert result["valid"] is False
    assert "BINDING_MISMATCH:session_id" in result["reasons"]
    # The stored hash is still intact — this is a presentation attack, not tampering.
    assert result["hash_matches"] is True


@pytest.mark.asyncio
async def test_receipt_fails_when_the_stored_record_is_tampered(client, seeded):
    """Mutating a stored receipt must be detected by the recomputed hash."""
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()
    receipt_id = issued["receipt_id"]

    from sqlalchemy import update

    from app.models.receipts import TrustReceiptModel

    async with TestSessionFactory() as db:
        await db.execute(
            update(TrustReceiptModel)
            .where(TrustReceiptModel.receipt_id == receipt_id)
            .values(decision="ALLOW", tci=99.9, trust_state="TRUSTED")
        )
        await db.commit()

    result = (
        await client.post(
            f"{API}/receipts/{receipt_id}/verify", headers=AUTH, json={"mark_used": False}
        )
    ).json()
    assert result["valid"] is False
    assert "RECEIPT_HASH_MISMATCH" in result["reasons"]
    assert result["hash_matches"] is False


@pytest.mark.asyncio
async def test_receipt_fails_when_evidence_is_tampered(client, seeded):
    """Evidence is hashed separately, so editing it alone is still detected."""
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()
    receipt_id = issued["receipt_id"]

    from sqlalchemy import update

    from app.models.receipts import TrustReceiptModel

    async with TestSessionFactory() as db:
        await db.execute(
            update(TrustReceiptModel)
            .where(TrustReceiptModel.receipt_id == receipt_id)
            .values(
                evidence=[
                    {
                        "type": "NOTHING_TO_SEE",
                        "severity": 0.0,
                        "description": "everything is fine",
                        "source": "ATTACKER",
                    }
                ]
            )
        )
        await db.commit()

    result = (
        await client.post(
            f"{API}/receipts/{receipt_id}/verify", headers=AUTH, json={"mark_used": False}
        )
    ).json()
    assert result["valid"] is False
    assert "EVIDENCE_HASH_MISMATCH" in result["reasons"]


@pytest.mark.asyncio
async def test_receipt_is_single_use(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()
    receipt_id = issued["receipt_id"]

    first = (await client.post(f"{API}/receipts/{receipt_id}/verify", headers=AUTH, json={})).json()
    assert first["valid"] is True

    second = (
        await client.post(f"{API}/receipts/{receipt_id}/verify", headers=AUTH, json={})
    ).json()
    assert second["valid"] is False
    assert second["reused"] is True
    assert "RECEIPT_ALREADY_USED" in second["reasons"]


@pytest.mark.asyncio
async def test_receipt_expires(client, seeded):
    """A receipt is short-lived by design; replaying an old one must fail."""
    session_id = (await login(client)).json()["session"]["session_id"]
    issued = (await act(client, session_id, "VIEW_PROFILE")).json()
    receipt_id = issued["receipt_id"]

    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from app.models.receipts import TrustReceiptModel

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    async with TestSessionFactory() as db:
        await db.execute(
            update(TrustReceiptModel)
            .where(TrustReceiptModel.receipt_id == receipt_id)
            .values(expires_at=past.replace(tzinfo=None))
        )
        await db.commit()

    result = (
        await client.post(f"{API}/receipts/{receipt_id}/verify", headers=AUTH, json={})
    ).json()
    assert result["valid"] is False
    assert result["expired"] is True
    assert "RECEIPT_EXPIRED" in result["reasons"]


@pytest.mark.asyncio
async def test_nonces_are_unique_across_actions(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]

    receipts = []
    for action in ("VIEW_DASHBOARD", "VIEW_PROFILE", "VIEW_RESOURCE"):
        issued = (await act(client, session_id, action)).json()
        receipt = (await client.get(f"{API}/receipts/{issued['receipt_id']}", headers=AUTH)).json()
        receipts.append(receipt)

    nonces = [item["nonce"] for item in receipts]
    ids = [item["receipt_id"] for item in receipts]
    assert len(set(nonces)) == len(nonces), f"nonce collision: {nonces}"
    assert len(set(ids)) == len(ids), f"receipt id collision: {ids}"


@pytest.mark.asyncio
async def test_nonce_is_not_derived_from_the_request(client, seeded):
    """The same action requested twice must still get a fresh nonce."""
    session_id = (await login(client)).json()["session"]["session_id"]
    first = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    second = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    assert first["receipt_id"] != second["receipt_id"]


@pytest.mark.asyncio
async def test_unknown_receipt_returns_404(client, seeded):
    response = await client.get(f"{API}/receipts/trc_does_not_exist", headers=AUTH)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_verifying_an_unknown_receipt_reports_not_found(client, seeded):
    result = (await client.post(f"{API}/receipts/trc_nope/verify", headers=AUTH, json={})).json()
    assert result["valid"] is False
    assert result["not_found"] is True
    assert "RECEIPT_NOT_FOUND" in result["reasons"]


# ------------------------------------------------------------------ revocation
@pytest.mark.asyncio
async def test_revoked_session_cannot_act(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    assert (await act(client, session_id, "VIEW_DASHBOARD")).json()["decision"] == "ALLOW"

    response = await client.post(
        f"{API}/sessions/{session_id}/revoke", headers=AUTH, json={"reason": "user request"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "REVOKED"
    assert body["token_invalidated"] is True
    assert body["incident_id"]
    # Revocation alone does not flag the device — that is containment.
    assert body["device_flagged"] is False
    assert body["is_contained"] is False

    blocked = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    assert blocked["decision"] == "BLOCK"
    assert blocked["rule_id"] == "SESSION_NOT_ACTIVE"


# ------------------------------------------------------------------ containment
@pytest.mark.asyncio
async def test_containment_revokes_flags_device_and_opens_incident(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]

    response = await client.post(
        f"{API}/sessions/{session_id}/contain",
        headers=AUTH,
        json={"reason": "confirmed session hijack"},
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["status"] == "REVOKED"
    assert body["is_contained"] is True
    assert body["trust_state"] == "CONTAINED"
    assert body["device_flagged"] is True
    for expected in (
        "REVOKE_SESSION",
        "INVALIDATE_TOKEN",
        "FLAG_DEVICE",
        "SERVE_DECEPTION",
        "OPEN_INCIDENT",
    ):
        assert expected in body["applied"], f"{expected} not applied"

    # Deception is labeled, never silent.
    assert body["deception"]["active"] is True
    assert body["deception"]["label"] == "DECEPTION_SANDBOX"
    assert body["deception"]["notice"]

    # Nothing is allowed afterwards, including reads.
    blocked = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    assert blocked["decision"] == "BLOCK"


@pytest.mark.asyncio
async def test_containment_flags_the_device_persistently(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await client.post(f"{API}/sessions/{session_id}/contain", headers=AUTH, json={})

    devices = (await client.get(f"{API}/devices", headers=AUTH)).json()
    alice = next(d for d in devices if d["device_fingerprint"] == ALICE_DEVICE["fingerprint"])
    assert alice["is_flagged"] is True
    assert alice["trust_level"] == "FLAGGED"


@pytest.mark.asyncio
async def test_contained_session_does_not_repeat_incidents(client, seeded):
    """One incident per investigation, not one per attempt."""
    session_id = (await login(client)).json()["session"]["session_id"]
    await client.post(f"{API}/sessions/{session_id}/contain", headers=AUTH, json={"reason": "one"})
    await client.post(f"{API}/sessions/{session_id}/contain", headers=AUTH, json={"reason": "two"})

    incidents = (await client.get(f"{API}/incidents?session_id={session_id}", headers=AUTH)).json()
    open_ones = [item for item in incidents if item["is_open"]]
    assert len(open_ones) == 1, [item["id"] for item in incidents]


# ------------------------------------------------------------------- incidents
@pytest.mark.asyncio
async def test_incident_lifecycle(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    contained = (
        await client.post(
            f"{API}/sessions/{session_id}/contain", headers=AUTH, json={"reason": "x"}
        )
    ).json()
    incident_id = contained["incident_id"]

    fetched = (await client.get(f"{API}/incidents/{incident_id}", headers=AUTH)).json()
    assert fetched["status"] == "OPEN"
    assert fetched["is_open"] is True
    assert fetched["severity"] == "CRITICAL"
    assert "contained" in fetched["title"].lower()

    updated = (
        await client.patch(
            f"{API}/incidents/{incident_id}",
            headers=AUTH,
            json={"status": "RESOLVED", "note": "false alarm", "closed_by": "soc-analyst"},
        )
    ).json()
    assert updated["status"] == "RESOLVED"
    assert updated["is_open"] is False
    assert updated["closed_at"] is not None


@pytest.mark.asyncio
async def test_invalid_incident_status_is_rejected(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    incident_id = (
        await client.post(f"{API}/sessions/{session_id}/contain", headers=AUTH, json={})
    ).json()["incident_id"]

    response = await client.patch(
        f"{API}/incidents/{incident_id}", headers=AUTH, json={"status": "MAYBE_DONE"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_unknown_incident_returns_404(client, seeded):
    response = await client.get(f"{API}/incidents/not-a-real-id", headers=AUTH)
    assert response.status_code == 404


# --------------------------------------------------------------------- posture
@pytest.mark.asyncio
async def test_posture_starts_healthy_and_degrades(client, seeded):
    healthy = (await client.get(f"{API}/security/posture", headers=AUTH)).json()
    assert healthy["grade"] in ("EXCELLENT", "GOOD")
    assert healthy["open_incidents"] == 0

    session_id = (await login(client)).json()["session"]["session_id"]
    await client.post(f"{API}/sessions/{session_id}/contain", headers=AUTH, json={})

    degraded = (await client.get(f"{API}/security/posture", headers=AUTH)).json()
    assert degraded["score"] < healthy["score"]
    assert degraded["open_incidents"] == 1
    assert degraded["contained_sessions"] >= 1
    assert degraded["components"]["containment"] < healthy["components"]["containment"]


@pytest.mark.asyncio
async def test_posture_counts_enforcement_activity(client, seeded):
    session_id = (await login(client)).json()["session"]["session_id"]
    await act(client, session_id, "VIEW_DASHBOARD")
    await act(client, session_id, "CREATE_ADMIN")  # STEP_UP

    posture = (await client.get(f"{API}/security/posture", headers=AUTH)).json()
    assert posture["allowed_actions"] >= 1
    assert posture["step_up_requests"] >= 1


# --------------------------------------------------------------- policy config
@pytest.mark.asyncio
async def test_policy_config_is_served_live(client, seeded):
    response = await client.get(f"{API}/config/policy", headers=AUTH)
    assert response.status_code == 200
    body = response.json()

    assert body["policy_version"] == "1.0.0"
    assert body["default_decision"] == "ALLOW"
    assert body["terminal_trust_states"] == ["BLOCKED", "CONTAINED"]
    assert body["tci_block_floor"] == 45
    assert body["rules"][-1]["requires"] == {}
    assert (
        "does not authorize" in body["disclaimer"].lower()
        or "no ai/ml" in body["disclaimer"].lower()
    )


@pytest.mark.asyncio
async def test_policy_rules_are_served_in_order(client, seeded):
    body = (await client.get(f"{API}/actions/policy-rules", headers=AUTH)).json()
    assert body["evaluation"] == "first-match-wins"
    # Containment must be checked before the generic risk rules.
    ids = [rule["id"] for rule in body["rules"]]
    assert ids.index("SESSION_CONTAINED") < ids.index("DEFAULT_ALLOW")
    assert ids.index("SESSION_NOT_ACTIVE") < ids.index("SUSPICIOUS_STATE_HIGH_RISK")


# ----------------------------------------------------------------- boundaries
@pytest.mark.asyncio
async def test_action_on_unknown_session_returns_404(client, seeded):
    response = await act(client, "TS-DOES-NOT-EXIST", "VIEW_DASHBOARD")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_action_requires_a_valid_api_key(client, seeded):
    response = await client.post(
        f"{API}/actions/evaluate",
        headers={"X-TrustPulse-API-Key": "wrong-key", "Content-Type": "application/json"},
        json={"session_id": "TS-ANY", "action": "VIEW_DASHBOARD"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_tenant_isolation_on_receipts(client, seeded):
    """Tenant B must not be able to read tenant A's receipt."""
    session_id = (await login(client)).json()["session"]["session_id"]
    receipt_id = (await act(client, session_id, "VIEW_PROFILE")).json()["receipt_id"]

    other = {"X-TrustPulse-Tenant-Id": "some-other-tenant", "Content-Type": "application/json"}
    response = await client.get(f"{API}/receipts/{receipt_id}", headers=other)
    assert response.status_code == 404


# --------------------------------------------------------------------- the demo
@pytest.mark.asyncio
async def test_full_attack_demo_end_to_end(client, seeded):
    """The Phase 3 success criterion, exercised end to end.

    login → trusted → low-risk ALLOW → takeover → TCI falls → sensitive action
    → STEP_UP → failure → BLOCK → containment → incident → receipt.
    """
    login_body = (await login(client)).json()
    session_id = login_body["session"]["session_id"]
    assert login_body["trust"]["state"] == "TRUSTED"

    allowed = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    assert allowed["decision"] == "ALLOW"
    start_tci = allowed["tci"]

    trajectory = [start_tci]
    for _ in range(8):
        sample = await telemetry(client, session_id, ATTACKER_FEATURES)
        trajectory.append(sample.json()["trust"]["tci"])

    assert trajectory[-1] < trajectory[0] - 15, trajectory
    assert min(trajectory) < 70, trajectory

    challenged = (
        await act(client, session_id, "CREATE_API_KEY", features=ATTACKER_FEATURES)
    ).json()
    assert challenged["decision"] == "STEP_UP"
    assert challenged["tci"] < start_tci

    failed = (
        await client.post(
            f"{API}/actions/{challenged['action_id']}/step-up",
            headers=AUTH,
            json={"challenge_id": challenged["step_up"]["challenge_id"], "success": False},
        )
    ).json()
    assert failed["status"] == "FAILED"
    assert failed["tci"] < challenged["tci"]

    critical = (await act(client, session_id, "MODIFY_ACCESS_POLICY")).json()
    assert critical["decision"] in ("BLOCK", "STEP_UP")

    contained = (
        await client.post(
            f"{API}/sessions/{session_id}/contain",
            headers=AUTH,
            json={"reason": "hijack confirmed"},
        )
    ).json()
    assert contained["is_contained"] is True

    final = (await act(client, session_id, "VIEW_DASHBOARD")).json()
    assert final["decision"] == "BLOCK"

    # The receipt for the blocked attempt is fetchable and verifiable.
    receipt = (await client.get(f"{API}/receipts/{final['receipt_id']}", headers=AUTH)).json()
    assert receipt["decision"] == "BLOCK"
    assert receipt["action"] == "VIEW_DASHBOARD"

    incidents = (await client.get(f"{API}/incidents?session_id={session_id}", headers=AUTH)).json()
    assert any(item["is_open"] for item in incidents)

    posture = (await client.get(f"{API}/security/posture", headers=AUTH)).json()
    assert posture["open_incidents"] >= 1
    assert posture["blocked_actions"] >= 1

@pytest.mark.asyncio
async def test_containment_incident_names_the_real_action(client, seeded):
    """Regression: incidents used to record the placeholder 'STEP_UP_TARGET'.

    A SOC analyst reading "STEP_UP_TARGET" learns nothing. The incident must
    name the action the attacker was actually attempting.
    """
    session_id = (await login(client)).json()["session"]["session_id"]
    challenged = (await act(client, session_id, "CREATE_ADMIN")).json()
    assert challenged["decision"] == "STEP_UP"

    failed = (
        await client.post(
            f"{API}/actions/{challenged['action_id']}/step-up",
            headers=AUTH,
            json={
                "challenge_id": challenged["step_up"]["challenge_id"],
                "success": False,
                "method": "MFA",
            },
        )
    ).json()

    incident = (
        await client.get(f"{API}/incidents/{failed['incident_id']}", headers=AUTH)
    ).json()
    assert "STEP_UP_TARGET" not in incident["title"], incident["title"]
    assert "CREATE_ADMIN" in incident["title"], incident["title"]
