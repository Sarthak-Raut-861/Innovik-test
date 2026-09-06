"""Deterministic end-to-end demo runner for TRUSTPULSE (Phase 1).

Drives the full trust loop against a running API:

    login -> normal telemetry -> simulated takeover -> privacy guard -> SOC view

Run:  python demo/run_demo.py [--base http://127.0.0.1:8000]

This is the same trajectory the Phase 3 attack demo will narrate; in Phase 1 it
covers trust only (risk/policy/receipts/proof arrive in Phases 2-3).
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


def load_personas() -> dict:
    """Demo data: personas, the attacker profile, and the seeded devices.

    The seeded device fingerprint matters: Trusted Core baselines are built per
    (user, device), so logging in from a device with no baseline would leave the
    attacker undetectable (cold start scores every observation as normal).
    """
    with PERSONAS.open() as handle:
        return json.load(handle)

NORMAL_FEATURES = {
    "typing": {
        "meanDwellTime": 114,
        "dwellStdDev": 25,
        "meanFlightTime": 90,
        "flightStdDev": 30,
        "typingSpeed": 6.0,
        "pauseRate": 0.13,
    },
    "mouse": {
        "meanVelocity": 830,
        "velocityStdDev": 255,
        "meanAcceleration": 2150,
        "directionChangeRate": 3.3,
        "totalDistance": 18000,
        "movementDuration": 4100,
        "meanPauseTime": 335,
    },
    "click": {"clickCount": 17, "meanInterval": 930, "intervalStdDev": 300, "clickFrequency": 1.1},
    "scroll": {
        "meanVelocity": 1520,
        "totalDistance": 9100,
        "meanPauseDuration": 610,
        "eventRate": 6.1,
    },
}

# Replaced below with the seeded attacker profile if it defines one.
_SEEDED_ATTACKER_FEATURES: dict = {}

ATTACKER_FEATURES = {
    "typing": {
        "meanDwellTime": 380,
        "dwellStdDev": 12,
        "meanFlightTime": 300,
        "flightStdDev": 9,
        "typingSpeed": 2.1,
        "pauseRate": 0.02,
    },
    "mouse": {
        "meanVelocity": 9000,
        "velocityStdDev": 60,
        "meanAcceleration": 41000,
        "directionChangeRate": 0.4,
        "totalDistance": 92000,
        "movementDuration": 900,
        "meanPauseTime": 40,
    },
    "click": {"clickCount": 64, "meanInterval": 155, "intervalStdDev": 12, "clickFrequency": 6.4},
    "scroll": {
        "meanVelocity": 18000,
        "totalDistance": 240000,
        "meanPauseDuration": 30,
        "eventRate": 42,
    },
}


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, payload: dict | None = None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{self.base}/api/v1{path}",
            data=body,
            method=method,
            headers={
                "Content-Type": "application/json",
                "X-TrustPulse-API-Key": API_KEY,
            },
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="alice.chen")
    parser.add_argument("--password", default="TrustDemo!234")
    parser.add_argument("--normal", type=int, default=5)
    parser.add_argument("--attack", type=int, default=10)
    args = parser.parse_args()

    api = Api(args.base)
    personas = load_personas()
    attack_features = attacker_features(personas)

    # The victim's own registered device — this is the device whose Trusted Core
    # baseline was seeded, so a takeover on it is detectable.
    entry = next(
        (item for item in personas["users"] if item["username"] == args.username),
        personas["users"][0],
    )
    device = dict(entry["device"])

    status, body = api.post(
        "/auth/login",
        {
            "username": entry["username"],
            "password": entry.get("demo_password", args.password),
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
    print("=" * 72)
    print("TRUSTPULSE AI — Phase 1 trust loop")
    print("=" * 72)
    print(f"session      : {session_id}")
    print(f"user         : {body['session'].get('username')}")
    print(f"device       : {device['fingerprint']}")
    print(
        f"LOGIN        : TCI {trust['tci']:>5} {trust['state']:<10} "
        f"evidence={trust['confidence']} trend={trust['trend']}"
    )

    def emit(label: str, features: dict, index: int) -> None:
        status, result = api.post(
            "/telemetry",
            {"session_id": session_id, "features": features, "source": "SIMULATION"},
        )
        if status != 200:
            print(f"  {label} #{index} failed ({status}): {result}")
            return
        next_trust = result["trust"]
        print(
            f"{label:<22}#{index:<2} anomaly={result['anomaly_score']:.3f}  "
            f"TCI {next_trust['tci']:>5}  {next_trust['state']:<10} trend={next_trust['trend']}"
        )

    print("-- normal behavior (the legitimate user) --")
    for index in range(1, args.normal + 1):
        emit("NORMAL", NORMAL_FEATURES, index)

    print("-- simulated session takeover (same device, same network) --")
    for index in range(1, args.attack + 1):
        emit("ATTACKER", attack_features, index)

    print("-- privacy guard: raw typed characters must be rejected --")
    status, body = api.post(
        "/telemetry",
        {
            "session_id": session_id,
            "features": {"characters": "hunter2", "typing": {"sampleCount": 5}},
            "source": "SIMULATION",
        },
    )
    print(f"  http={status} error={body.get('error')} type={body.get('error_type')}")

    print("-- SOC overview --")
    status, overview = api.get("/soc/overview")
    if status == 200:
        print(
            f"  active={overview['active_sessions']} suspicious={overview['suspicious_sessions']} "
            f"contained={overview['contained_sessions']} avg_tci={overview['average_tci']}"
        )

    status, detail = api.get(f"/soc/sessions/{session_id}")
    if status == 200 and detail.get("trust"):
        print("-- evidence for this session --")
        for record in detail["trust"]["evidence"][:6]:
            print(f"  [{record['type']}] {record['description']}")
        print(f"  baselines: core_obs={detail['baselines']['core']['observations']} "
              f"shadow_obs={detail['baselines']['shadow']['observations']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
