# TRUSTPULSE API Reference

Base path: `/api/v1` · OpenAPI: `GET /openapi.json` · Swagger UI: `/docs`

Two route families coexist:

- **Platform (`/api/v1/...`)** — the continuous-trust surface built for the platform. This is what
  TrustDev and the SOC dashboard use.
- **Legacy (`/v1/...`)** — the pre-existing integration surface from earlier phases. Still mounted.

## Authentication

| Header | Purpose |
|---|---|
| `X-TrustPulse-API-Key` | Server-side integration key. Full scopes: read, write, telemetry, risk. |
| `Authorization: Bearer <key>` | Same key, bearer form. |
| `X-TrustPulse-Public-Key` | Non-secret browser SDK key. Scopes limited to `telemetry`, `read`. |
| `X-TrustPulse-Tenant-Id` | Optional; must match the credential's tenant or the request is rejected. |

Tenant isolation is derived from the credential — a caller cannot override it with a header.

The development fallback (tenant header alone, no credential) is enabled by default for local work
and **must** be disabled in production via `ALLOW_DEVELOPMENT_AUTH_FALLBACK=false`.

Errors are uniform — a human-readable `error` plus a structured `details` object:

```json
{ "error": "Invalid API key", "details": {} }
```

Validation failures put the field-level problems in `details`:

```json
{ "error": "Request validation failed",
  "details": [ { "loc": ["body", "device", "fingerprint"], "msg": "String should have at least 8 characters" } ] }
```

---

## Auth & session

### `POST /api/v1/auth/login`

Creates a user (if unknown), registers the device, opens a session and returns the initial trust
assessment.

```json
{
  "username": "alice.chen",
  "password": "TrustDemo!234",
  "mfa_code": "123456",
  "device": { "fingerprint": "dev-alice-work-macbook-a1b2c3", "platform": "macOS", "browser": "Chrome" },
  "network": { "country": "US", "asn": "AS15169", "is_vpn": false, "is_proxy_or_tor": false }
}
```

→ `200`

```json
{
  "session": { "session_id": "TS-5CC387862A89", "status": "ACTIVE", "username": "alice.chen", "trust_state": "TRUSTED" },
  "token": "pt_live_...",
  "trust": { "session_id": "TS-5CC387862A89", "tci": 86.0, "state": "TRUSTED", "confidence": "LOW", "trend": "INSUFFICIENT_DATA", "factors": [], "evidence": [], "warnings": [] }
}
```

Notes:
- Passwords are verified against a PBKDF2-SHA256 digest and never logged.
- Unknown user and wrong password return a byte-identical `401` body —
  `{"error": "Invalid credentials", "details": {}}` — so the endpoint cannot be used to enumerate
  usernames.
- `confidence` is legitimately `LOW` at login — no behavioral observation exists yet — even when TCI
  is high. Score and evidence strength are independent.
- The app token is returned **once** and stored only as a SHA-256 digest in `sessions.extra`.

### `POST /api/v1/session`

Opens a session for an already-known user (no credential check). Used by server-side integrations.

### `POST /api/v1/session/{session_id}/end`

Closes the session. Runs a final assessment with `trigger="SESSION_END"`.

---

## Telemetry

### `POST /api/v1/telemetry`

Accepts **derived features only**. Raw behavioral data is rejected.

```json
{
  "session_id": "TS-5CC387862A89",
  "features": {
    "typing": { "meanDwellTime": 112, "dwellStdDev": 24, "meanFlightTime": 88, "typingSpeed": 6.1, "pauseRate": 0.12 },
    "mouse":  { "meanVelocity": 820, "velocityStdDev": 260, "meanAcceleration": 2100, "directionChangeRate": 3.4, "meanPauseTime": 340 },
    "click":  { "clickCount": 18, "meanInterval": 940, "intervalStdDev": 310, "clickFrequency": 1.1 },
    "scroll": { "meanVelocity": 1500, "totalDistance": 9200, "meanPauseDuration": 620, "eventRate": 6.2 }
  },
  "network": { "country": "US", "asn": "AS15169" },
  "source": "SDK"
}
```

→ `200`

```json
{
  "accepted": true,
  "features_received": 21,
  "anomaly_score": 0.078,
  "trust": { "tci": 90.3, "state": "TRUSTED", "...": "..." },
  "learned": { "shadow_learned": true, "core_observations": 29, "shadow_observations": 13 }
}
```

→ `422` for raw data (verified against the running API):

```json
{ "error": "Raw behavioral data is not accepted",
  "details": {
    "reason": "Rejected telemetry key 'characters': raw data is never accepted by TRUSTPULSE",
    "policy": "TRUSTPULSE only accepts derived aggregate features."
  } }
```

Rejected key patterns include `characters`, `clipboard`, `selection`, `text`, `password`, `token`,
`email`, `phone`, `ssn`. This is unconditional — there is no flag to disable it.

**Learning rule:** the observation is scored against the Trusted Core *before* any learning
happens, and is only absorbed into the Adaptive Shadow when the session's trust state is not in
`SUSPICIOUS / CRITICAL / BLOCKED / CONTAINED` and there is no open incident. Rejected observations
are counted, never stored as features. This is the baseline-poisoning guard.

---

## Trust

### `POST /api/v1/trust/evaluate`

Re-evaluates a session. Accepts optional `features`, `network` and `trigger`.

### `GET /api/v1/trust/{session_id}`

Latest `TrustResult`:

```json
{
  "session_id": "TS-5CC387862A89",
  "tci": 61.0,
  "confidence": "HIGH",
  "trend": "FALLING",
  "state": "SUSPICIOUS",
  "previous_state": "DEGRADED",
  "state_changed": true,
  "raw_band": "SUSPICIOUS",
  "hysteresis_applied": false,
  "factors": [
    { "name": "behavior", "score": 0, "configured_weight": 0.3, "effective_weight": 0.3,
      "available": true, "contribution": 0.0,
      "reasons": ["BASELINE_DEVIATION", "SUSTAINED_BEHAVIORAL_DEVIATION"] }
  ],
  "evidence": [
    { "type": "BASELINE_DEVIATION", "severity": 0.62,
      "description": "mouse_acceleration is 25.4 sigma higher/faster than the trusted baseline (observed 41000.0 vs baseline 2269.1)",
      "source": "ANOMALY_DETECTION" }
  ],
  "warnings": ["FACTOR_UNAVAILABLE:network"],
  "evaluations": 16,
  "trigger": "TELEMETRY"
}
```

Semantics:

- **`tci`** is a weighted sum clamped to 0–100. It is an engineering index, not a probability.
- **`effective_weight`** differs from `configured_weight` when a factor has no evidence: available
  weights are renormalised so a blind spot is excluded rather than scored as distrust. Such a factor
  reports `available: false` and adds a `FACTOR_UNAVAILABLE:<name>` warning.
- **`confidence`** describes evidence strength, independent of the score: HIGH ≥ 8 evidence-bearing
  features, MEDIUM ≥ 4, else LOW.
- **`trend`** compares against prior TCIs: `RISING`, `STABLE`, `FALLING`, or `INSUFFICIENT_DATA`.

### `GET /api/v1/trust/{session_id}/history`

```json
{
  "session_id": "TS-5CC387862A89",
  "points": [ { "observed_at": "...", "tci": 90.3, "state": "TRUSTED", "trigger": "TELEMETRY", "state_changed": false } ],
  "state_timeline": [ { "observed_at": "...", "from": "TRUSTED", "to": "DEGRADED", "tci": 72.4, "trigger": "TELEMETRY" } ]
}
```

---

## SOC

### `GET /api/v1/soc/overview`

```json
{ "active_sessions": 4, "suspicious_sessions": 3, "contained_sessions": 0, "open_incidents": 0,
  "average_tci": 64.88, "blocked_actions": 0, "step_up_requests": 0,
  "trust_model_version": "1.0.0", "disclaimer": "TCI is an engineering trust index, not a probability..." }
```

### `GET /api/v1/soc/sessions?limit=50`

One summary row per session, newest activity first.

### `GET /api/v1/soc/sessions/{session_id}`

Full analyst view: session, latest `trust`, `tci_history`, `evidence`, `actions`, `baselines`
(Trusted Core and Adaptive Shadow observation counts, versions, rejected counts), `incidents`.

---

## Transparency

### `GET /api/v1/config/trust-model`

The live, effective configuration: `schema_version`, `source` (the file actually loaded), `weights`,
`state_bands`, `hysteresis`, `action_risk_profiles`, `evidence_types`, `disclaimer`.

### `GET /api/v1/config/actions`

Action risk catalogue plus band definitions.

### `GET /api/v1/actions/known`

Declared action names an integration may submit.

### `GET /api/v1/users` · `GET /api/v1/devices` · `GET /api/v1/platform/health`

---

## Authorization (Phase 2)

All eleven endpoints are live and verified. Request and response shapes are the
real wire format, captured from a running API, and mirrored in
`shared/schemas/trust.ts` under contract test.

### `POST /api/v1/actions/evaluate`

The enforcement call. The PEP re-evaluates trust, scores the action, runs the
policy rules, and — unless the decision is `STEP_UP` — issues a Trust Receipt.
This is the only endpoint that can authorize an action.

```json
{
  "session_id": "TS-4F9CD1E3E044",
  "action": "CREATE_API_KEY",
  "resource": "project/trustdev/api-keys",
  "context": { "amount": 120000, "privileged": false },
  "features": { "typing": { }, "mouse": { } }
}
```

Response (`ActionDecisionResponse`):

| Field | Meaning |
|---|---|
| `action_id` | Server-generated identifier for this evaluation |
| `decision` | `ALLOW` · `STEP_UP` · `BLOCK` · `REVOKE` · `CONTAIN` |
| `rule_id` | Which policy rule fired, e.g. `SUSPICIOUS_STATE_HIGH_RISK` |
| `reason` | Human-readable explanation |
| `tci`, `trust_state` | Trust at the moment of the decision |
| `action_risk`, `risk_band` | Scored risk 0–100 and its band |
| `risk_breakdown` | Base risk, named adjustments, per-dimension scores |
| `policy_audit` | **Every** rule evaluated in order, with why each did not match |
| `receipt_id`, `receipt` | Trust Receipt for the decision |
| `step_up` | Challenge descriptor; present only when `decision === "STEP_UP"` |
| `containment`, `incident_id` | Set when the decision contained the session |
| `policy_version`, `warnings`, `trust` | Policy provenance and full evaluation |

`policy_audit` is what makes "why" answerable. For a `CREATE_ADMIN` request it
returns ten entries, e.g.
`{"rule_id": "SESSION_NOT_ACTIVE", "decision": "BLOCK", "matched": false, "skipped": "session_status is ACTIVE"}`.

### `POST /api/v1/actions/{action_id}/step-up`

Reports the outcome of a step-up challenge. TRUSTPULSE requires the challenge;
your application or IdP performs it.

```json
{ "challenge_id": "su_9f1c…", "success": false, "method": "MFA" }
```

`StepUpResolveResponse` reports `tci_before`, `tci`, `tci_penalty_configured`
(the configured intent) and `tci_penalty_applied` (the drop that actually
happened) as **three distinct fields** — they are deliberately not collapsed
into one number.

### `GET /api/v1/actions/policy-rules` · `GET /api/v1/config/policy`

The effective rule list and the step-up / receipt / containment configuration,
as loaded from `shared/constants/trust_model.json`.

### `GET /api/v1/receipts/{receipt_id}` · `POST /api/v1/receipts/{receipt_id}/verify`

Fetch a receipt, or verify a presentation of one.

```json
{
  "presented": { "session_id": "TS-…", "user_id": "U001", "nonce": "…" },
  "check_binding": true,
  "mark_used": false
}
```

`mark_used: false` inspects without consuming; `mark_used: true` (the default)
presents it for real and burns the nonce. A second presentation returns
`valid: false` with `RECEIPT_ALREADY_USED`.

Verification reasons include `RECEIPT_VALID`, `RECEIPT_HASH_MISMATCH`,
`RECEIPT_EXPIRED`, `RECEIPT_REVOKED`, `RECEIPT_ALREADY_USED` and
`BINDING_MISMATCH:<field>`.

### `GET /api/v1/incidents` · `GET`/`PATCH /api/v1/incidents/{incident_id}`

Query with `?status=OPEN&session_id=…&severity=HIGH&limit=50`. `PATCH` moves an
incident between `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED` and
`FALSE_POSITIVE`. There is no `CLOSED` status.

### `GET /api/v1/security/posture`

Aggregate posture: `score`, `grade` (`EXCELLENT`/`GOOD`/`FAIR`/`POOR`/`CRITICAL`),
the four `components` (`trust_health`, `containment`, `incident_pressure`,
`enforcement`), and counts of open incidents, contained sessions and blocked
actions.

### `POST /api/v1/sessions/{session_id}/revoke` · `/contain`

Operator actions. `/contain` applies the configured containment actions and
returns the labelled deception descriptor if one was served.

---

## Planned (Phase 3)

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/proofs/create` | Merkle aggregation and anchoring of receipts |
| `POST /api/v1/proofs/verify` | Verify a receipt against its Merkle proof |
| `GET /api/v1/ws/soc` (WebSocket) | Real-time SOC updates |

---

## Shared contracts

```ts
type TrustResult = {
  session_id: string;
  tci: number;                 // 0-100 engineering index
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  trend: 'RISING' | 'STABLE' | 'FALLING' | 'INSUFFICIENT_DATA';
  state: 'TRUSTED' | 'DEGRADED' | 'SUSPICIOUS' | 'CRITICAL' | 'BLOCKED' | 'CONTAINED';
  evidence: EvidenceRecord[];
};

type ActionRequest = {
  session_id: string;
  user_id: string;
  action: string;
  resource?: string;
  context?: Record<string, unknown>;
};

type Decision = {
  decision: 'ALLOW' | 'STEP_UP' | 'BLOCK' | 'REVOKE' | 'CONTAIN';
  tci: number;
  action_risk: number;
  trust_state: string;
  receipt_id?: string;
};
```

There is deliberately no `PENDING`: the PEP always terminates in a verdict.

Mirrored in `frontend/src/types/trust.ts` and `shared/schemas/trust.ts`. The
shared mirror carries the full Phase 2 surface — `EnforcementDecision`,
`StepUpChallenge`, `StepUpResolution`, `ConsideredRule`, `ActionRiskAssessment`,
`ContainmentResult`, `IncidentRecord`, `SecurityPosture` and `PolicyRule` — and
`backend/tests/test_shared_contract.py` diffs it against the live Pydantic
models and the policy engine's actual predicate dispatch, so the mirror cannot
drift silently.
