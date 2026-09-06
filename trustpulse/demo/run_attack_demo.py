"""TRUSTPULSE — Phase 2 attack demo.

Drives the complete authorization loop against a running API:

    login → trusted session → low-risk ALLOW
          → simulated takeover → TCI falls
          → sensitive action → STEP_UP
          → step-up fails → trust drops further
          → BLOCK → containment → incident
          → receipt + hash + verification
          → SOC posture

Run:  python demo/run_attack_demo.py [--base http://127.0.0.1:8000]

Everything here is deterministic. No real attacker is involved: the "attacker"
is a fixed set of derived behavioral features that deviate sharply from the
seeded persona baseline.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

API_KEY = "tp_demo_trustpulse_key_0001"
PERSONAS = pathlib.Path(__file__).resolve().parent / "seed_data" / "personas.json"


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, payload: dict | None = None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{self.base}/api/v1{path}",
            data=body,
            method=method,
            headers={"Content-Type": "application/json", "X-TrustPulse-API-Key": API_KEY},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return error.code, {"raw": raw.decode(errors="replace")}

    def get(self, path: str):
        return self.call("GET", path)

    def post(self, path: str, payload: dict | None = None):
        return self.call("POST", path, payload)

    def patch(self, path: str, payload: dict | None = None):
        return self.call("PATCH", path, payload)


def rule(text: str = "") -> None:
    print(text)


def attacker_features(personas: dict) -> dict:
    """Extracts the seeded attacker payload.

    The attacker profile stores its feature groups at the top level next to a
    `description` string, so the description must be stripped rather than
    assumed absent.
    """
    profile = personas.get("attacker_profile") or {}
    features = {
        key: value
        for key, value in profile.items()
        if isinstance(value, dict) and key in ("typing", "mouse", "click", "scroll")
    }
    if not features:
        raise SystemExit(
            "personas.json has no attacker_profile feature groups; cannot run the attack demo"
        )
    return features


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="alice.chen")
    parser.add_argument("--attack-samples", type=int, default=8)
    args = parser.parse_args()

    api = Api(args.base)
    personas = json.loads(PERSONAS.read_text(encoding="utf-8"))
    entry = next(
        (item for item in personas["users"] if item["username"] == args.username),
        personas["users"][0],
    )
    device = dict(entry["device"])
    attacker = attacker_features(personas)

    print("=" * 74)
    print("TRUSTPULSE AI — Phase 2 attack demo")
    print("Authenticate once. Trust continuously. Authorize every action. Prove why.")
    print("=" * 74)

    # ---------------------------------------------------------------- 1. login
    status, body = api.post(
        "/auth/login",
        {
            "username": entry["username"],
            "password": entry.get("demo_password", "TrustDemo!234"),
            "mfa_code": "123456" if entry.get("mfa_enabled") else None,
            "device": {
                "fingerprint": device["fingerprint"],
                "label": device.get("label", "demo-device"),
                "platform": device.get("platform", "Linux"),
                "browser": device.get("browser", "Chrome"),
            },
            "network": {"country": "US", "asn": "AS15169"},
        },
    )
    if status != 200:
        print(f"login failed ({status}): {body}", file=sys.stderr)
        return 1

    session_id = body["session"]["session_id"]
    trust = body["trust"]
    rule("\n[1] Legitimate user authenticates")
    print(f"    session      : {session_id}")
    print(f"    user         : {entry['username']}  ({entry.get('role')})")
    print(f"    device       : {device['fingerprint']}")
    print(f"    auth         : {body['session']['auth_method']}")
    print(
        f"    TCI          : {trust['tci']:.1f}  {trust['state']}  "
        f"evidence={trust['confidence']}"
    )

    # ------------------------------------------------------- 2. low-risk action
    status, low = api.post(
        "/actions/evaluate",
        {"session_id": session_id, "action": "VIEW_DASHBOARD", "context": {}},
    )
    rule("\n[2] Low-risk action on a trusted session")
    print(f"    VIEW_DASHBOARD  risk={low['action_risk']:<3} -> {low['decision']:<8} "
          f"rule={low['rule_id']}")
    print(f"    receipt      : {low['receipt_id']}")
    start_tci = low["tci"]

    # ------------------------------------------------------------- 3. takeover
    rule("\n[3] Session hijacked — attacker behavior, same device and network")
    trajectory = [start_tci]
    for index in range(1, args.attack_samples + 1):
        status, sample = api.post(
            "/telemetry",
            {"session_id": session_id, "features": attacker, "source": "SIMULATION"},
        )
        sample_trust = sample["trust"]
        trajectory.append(sample_trust["tci"])
        print(
            f"    sample #{index:<2}      anomaly={sample['anomaly_score']:.3f}  "
            f"TCI {sample_trust['tci']:>5}  {sample_trust['state']}"
        )
    print(f"    TCI trajectory: {' -> '.join(f'{t:.0f}' for t in trajectory[:2])} ... "
          f"-> {trajectory[-1]:.1f}")

    # ------------------------------------------------- 4. sensitive action
    status, challenged = api.post(
        "/actions/evaluate",
        {
            "session_id": session_id,
            "action": "CREATE_API_KEY",
            "context": {},
            "features": attacker,
        },
    )
    rule("\n[4] Attacker attempts a sensitive action")
    print(f"    CREATE_API_KEY  risk={challenged['action_risk']:<3} -> "
          f"{challenged['decision']:<8} rule={challenged['rule_id']}")
    print(f"    TCI at decision: {challenged['tci']:.1f}  state={challenged['trust_state']}")
    if challenged.get("step_up"):
        challenge = challenged["step_up"]
        print(f"    step-up      : {challenge['method']} required "
              f"(max {challenge['max_attempts']} attempts)")
        print(f"    note         : {challenge['note'][:72]}...")

    # ------------------------------------------------------- 5. step-up fails
    rule("\n[5] Attacker cannot pass the step-up challenge")
    status, failed = api.post(
        f"/actions/{challenged['action_id']}/step-up",
        {
            "challenge_id": challenged["step_up"]["challenge_id"],
            "success": False,
            "method": "MFA",
        },
    )
    print(f"    result       : {failed.get('status')}  "
          f"attempt {failed.get('attempts')}/{failed.get('max_attempts')}")
    print(f"    TCI          : {failed.get('tci_before'):.1f} -> {failed.get('tci'):.1f}  "
          f"(-{failed.get('tci_penalty_applied'):.2f} observed, "
          f"{failed.get('tci_penalty_configured'):.0f} configured)  "
          f"{failed.get('trust_state')}")
    if failed.get("containment"):
        print(f"    containment  : {', '.join(failed['containment'])}")
        print(f"    incident     : {failed.get('incident_id')}")

    # -------------------------------------------------------- 6. now blocked
    status, blocked = api.post(
        "/actions/evaluate", {"session_id": session_id, "action": "VIEW_DASHBOARD", "context": {}}
    )
    rule("\n[6] Even low-risk actions are now denied")
    print(f"    VIEW_DASHBOARD  risk={blocked['action_risk']:<3} -> {blocked['decision']:<8} "
          f"rule={blocked['rule_id']}")
    print(f"    reason       : {blocked['reason']}")

    # --------------------------------------------------------- 7. containment
    status, contained = api.post(
        f"/sessions/{session_id}/contain", {"reason": "confirmed session hijack (demo)"}
    )
    rule("\n[7] Operator contains the session")
    print(f"    applied      : {', '.join(contained['applied'])}")
    print(f"    trust state  : {contained['trust_state']}   device flagged: "
          f"{contained['device_flagged']}")
    if contained.get("deception"):
        print(f"    deception    : {contained['deception']['label']} (labeled, not silent)")
    print(f"    incident     : {contained.get('incident_id')}")

    # ----------------------------------------------------------- 8. receipts
    rule("\n[8] Every decision produced a verifiable Trust Receipt")
    for label, receipt_id in (
        ("ALLOW  VIEW_DASHBOARD", low["receipt_id"]),
        ("BLOCK  VIEW_DASHBOARD", blocked["receipt_id"]),
    ):
        status, receipt = api.get(f"/receipts/{receipt_id}")
        print(f"    {label}")
        print(f"      receipt      : {receipt['receipt_id']}")
        print(f"      decision     : {receipt['decision']}  TCI {receipt['tci']:.1f}  "
              f"risk {receipt['action_risk']}")
        print(f"      nonce        : {receipt['nonce']}")
        print(f"      evidence_hash: {receipt['evidence_hash'][:32]}...")
        print(f"      receipt_hash : {receipt['receipt_hash'][:32]}...")

        # 1. Inspect without consuming the receipt.
        status, verified = api.post(f"/receipts/{receipt_id}/verify", {"mark_used": False})
        print(f"      inspect      : valid={verified['valid']}  reasons={verified['reasons']}")

        # 2. Present it for real — this consumes the nonce.
        status, used = api.post(f"/receipts/{receipt_id}/verify", {"mark_used": True})
        print(f"      first use    : valid={used['valid']}  reasons={used['reasons']}")

        # 3. Present the very same receipt again. This is the actual replay.
        status, replay = api.post(f"/receipts/{receipt_id}/verify", {"mark_used": True})
        print(f"      replay       : valid={replay['valid']}  reasons={replay['reasons']}")

    # ----------------------------------------------------- 9. tamper detection
    rule("\n[9] A forged presentation is rejected")
    # Issue a fresh receipt so the binding mismatch is the only failure shown;
    # a consumed receipt would report RECEIPT_ALREADY_USED and mask it.
    status, fresh = api.post(
        "/actions/evaluate",
        {"session_id": session_id, "action": "VIEW_PROFILE", "context": {}},
    )
    forged_receipt = fresh["receipt_id"]
    status, forged = api.post(
        f"/receipts/{forged_receipt}/verify",
        {"presented": {"session_id": "TS-SOMEONE-ELSES-SESSION"}, "mark_used": False},
    )
    print(f"    valid={forged['valid']}  reasons={forged['reasons']}")
    print(f"    stored hash still intact: {forged['hash_matches']} "
          f"(presentation attack, not tampering)")

    # ---------------------------------------------------------- 10. incidents
    rule("\n[10] Incident record")
    status, incidents = api.get(f"/incidents?session_id={session_id}")
    for item in incidents:
        print(f"    [{item['severity']}] {item['title']}")
        print(f"      status={item['status']}  TCI at detection={item['tci_at_detection']:.1f}  "
              f"state={item['trust_state_at_detection']}")
        print(f"      containment: {', '.join(item['containment_actions'][:5])}")

    # ----------------------------------------------------------- 11. posture
    rule("\n[11] Security posture")
    status, posture = api.get("/security/posture")
    print(f"    score={posture['score']:.1f}  grade={posture['grade']}")
    print("    components : " + ", ".join(
        f"{k}={v:.0f}" for k, v in posture["components"].items()
    ))
    print(f"    open incidents={posture['open_incidents']}  "
          f"contained sessions={posture['contained_sessions']}  "
          f"blocked actions={posture['blocked_actions']}")

    rule("\n" + "=" * 74)
    rule("Demo complete. The attacker authenticated successfully and was still stopped —")
    rule("because trust is continuous, not a one-time gate.")
    rule("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
