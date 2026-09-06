# TRUSTPULSE AI — Architecture

## 1. Architectural philosophy: Detection ≠ Decision ≠ Explanation

TRUSTPULSE enforces an immutable separation:

```text
┌──────────────────────────────┐
│          DETECTION           │  SDK collectors → derived features
│  Behavioral / statistical /  │  Anomaly detection vs baselines
│  ML anomaly identification   │  NON-AUTHORITATIVE evidence
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│           DECISION           │  Server-side trust engine + policy engine
│  Deterministic, auditable    │  ALLOW / STEP_UP / BLOCK / REVOKE / CONTAIN
│  Backend is the authority    │  Zero frontend enforcement
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│         EXPLANATION          │  Evidence records, receipts, Merkle proofs
│  Audit trails & SecOps notes │  Post-decision justification
│  Never affects decisions     │  Zero enforcement power
└──────────────────────────────┘
```

No ML component may authorize, block, revoke, modify policy, or compute authoritative risk. AI
**recommends**; the Policy Enforcement Point **decides**. The explanation layer describes a decision
that has already been made and cannot change it.

## 2. The trust loop

```text
Browser SDK                TRUSTPULSE backend
───────────                ──────────────────
DOM events
   │  (in memory only;      ┌──────────────────────────────────────────┐
   │   never persisted)     │ Feature extraction                       │
   ▼                        │ 21 derived features, privacy-guarded     │
Typing / pointer /          └──────────────────┬───────────────────────┘
click / scroll collectors                      ▼
   │                      ┌────────────────────────────────────────────┐
   │  POST /telemetry     │ Anomaly detection                          │
   └─────────────────────▶│ statistical z-score  +  IsolationForest    │
     derived aggregates    │ vs Trusted Core (and Adaptive Shadow)      │
      only                 └──────────────────┬─────────────────────────┘
                                              ▼
                          ┌────────────────────────────────────────────┐
                          │ Trust fusion  T = F(I,D,B,N,C,H)           │
                          │ → TCI 0-100, confidence, trend, evidence   │
                          └──────────────────┬─────────────────────────┘
                                             ▼
                          ┌────────────────────────────────────────────┐
                          │ State machine with hysteresis              │
                          │ TRUSTED…BLOCKED / CONTAINED                │
                          └──────────────────┬─────────────────────────┘
                                             ▼
                          ┌────────────────────────────────────────────┐
                          │ Policy engine + PEP (Phase 2)              │
                          │ trust state × action risk → decision       │
                          └──────────────────┬─────────────────────────┘
                                             ▼
                          ┌────────────────────────────────────────────┐
                          │ Trust Receipt → SHA-256 → Merkle (Phase 3) │
                          └────────────────────────────────────────────┘
```

## 3. Layers and ownership

| Layer | Location | Owns | Must never |
|---|---|---|---|
| Collection | `frontend/src/trustpulse-sdk/` | Derived interaction features | Read `event.key`, element text, input values; score trust; authorize |
| Feature extraction | `ml/feature_extraction/` | 21 numeric features, privacy guard | Accept raw data; persist raw events |
| Baselines | `ml/baseline/` | Trusted Core + Adaptive Shadow | Absorb observations from untrusted sessions |
| Anomaly detection | `ml/anomaly_detection/` | Anomaly score + evidence | Make a decision |
| Trust fusion | `ml/trust_fusion/` | Weighted TCI, confidence, trend | Decide authorization |
| Trust engine | `backend/app/services/trust_engine/` | Factor scores, state machine, evidence | Trust a single signal absolutely |
| Policy + PEP | `backend/app/services/policy/`, `enforcement/` (Phase 2) | The only authorization decision | Be bypassed by any client |
| Proof | `backend/app/services/receipts/`, `blockchain/` (Phase 3) | Receipts, Merkle roots, anchoring | Store raw behavioral data |

## 4. Configuration as the single source of truth

Every weight, band, hysteresis parameter and action risk lives in
`shared/constants/trust_model.json` (schema `1.0.0`). Nothing is hard-coded in the engines.

Resolution order in `backend/app/core/trust_config.py`:

1. `TRUST_MODEL_CONFIG_PATH` — explicit file path
2. `<repo>/shared/constants/trust_model.json`
3. `$SHARED_DIR/constants/trust_model.json` (default `/app/shared`)

Then convenience environment overrides are applied on top:

- `TCI_WEIGHT_IDENTITY|DEVICE|BEHAVIOR|NETWORK|SESSION|HISTORY`
- `TCI_COLD_START`
- `TRUST_STATE_TRUSTED_MIN|DEGRADED_MIN|SUSPICIOUS_MIN|CRITICAL_MIN|BLOCKED_MIN`
- `ACTION_RISK_<ACTION_NAME>` (clamped 0–100)
- `TRUST_MODEL_OVERRIDES` — JSON deep-merged over the base config

The effective configuration is validated at load (`TrustConfigError` on invalid weights, non-
decreasing bands, or unknown states) and served live from `GET /api/v1/config/trust-model` so an
analyst can see exactly what produced a decision.

## 5. Trust computation

```
TCI = clamp( Σᵢ effective_weightᵢ × scoreᵢ , 0, 100 )
```

Default weights: identity 0.15, device 0.20, **behavior 0.30**, network 0.15, session 0.10,
history 0.10.

**Unavailable factors are excluded, not penalised.** If a factor has no evidence (for example a
first login with no network history), it reports `available: false`, the remaining weights are
renormalised, and a `FACTOR_UNAVAILABLE:<name>` warning is attached. A blind spot must not be
scored as distrust.

**Confidence is independent of the score.** It reports how much evidence backs the number:
HIGH ≥ 8 evidence-bearing features, MEDIUM ≥ 4, else LOW. A login can be TRUSTED with LOW
confidence — the number is fine, the evidence base is thin.

**State bands:** TRUSTED ≥ 85, DEGRADED ≥ 70, SUSPICIOUS ≥ 50, CRITICAL ≥ 30, BLOCKED ≥ 0.

**Hysteresis** prevents a single noisy sample from flipping a session:

| Rule | Default | Effect |
|---|---|---|
| `escalation_confirmations` | 2 | A gradual fall is held one extra evaluation before escalating |
| `decisive_drop` | 15 | A TCI drop ≥ 15 escalates immediately |
| `decisive_depth` | 10 | Scoring ≥ 10 below the current state's floor escalates immediately |
| `multi_level_escalation` | 2 | A drop spanning ≥ 2 bands escalates immediately |
| `recovery_buffer` / `recovery_confirmations` | 6 / 3 | Recovery needs sustained improvement above the band |
| `no_auto_recovery_states` | BLOCKED, CONTAINED | Terminal states need operator action |
| `no_recovery_with_open_incident` | true | An open incident blocks recovery |

A first-ever assessment short-circuits hysteresis (`INITIAL_ASSESSMENT`) — there is no history to
corroborate against, so "escalation held pending confirmation" would be meaningless.

## 6. Baselines and poisoning resistance

Two baselines per (tenant, user, device):

- **Trusted Core** — slow-learning, conservative (`alpha = 0.05`). The reference for anomaly
  scoring. Built only from observations taken while the session was trustworthy.
- **Adaptive Shadow** — fast-learning (`alpha = 0.25`, `min_obs = 8`) so legitimate drift (new
  mouse, new keyboard, new commute) is absorbed without opening a hole in the Core.

Guardrails:

1. An observation is scored against the Core **before** any learning occurs.
2. Learning is gated: `SUSPICIOUS / CRITICAL / BLOCKED / CONTAINED` sessions, or any session with
   an open incident, never contribute features. Rejections are counted, not stored.
3. Shadow → Core promotion requires the shadow to be *consistent* (distance ≤ 1.2) and the session
   trustworthy; otherwise it returns explicit reasons
   (`SESSION_NOT_TRUSTWORTHY`, `OPEN_INCIDENT`, `SHADOW_NOT_CONSISTENT`).
4. A session cannot corroborate its own baseline: network baselines are seeded from **prior**
   sessions only, never from the observation currently being scored.

## 7. Privacy architecture

| Rule | Enforcement point |
|---|---|
| Never store passwords | PBKDF2-SHA256 digest + salt; no plaintext field exists |
| Never capture typed characters | SDK records timing deltas only; `event.key` is never read |
| Never accept raw behavioral data | `assert_no_raw_data` → `RawDataRejectedError` → HTTP 422 |
| Derived aggregates only | Feature vector is numeric by construction |
| No plaintext IPs | Stored as SHA-256 digests |
| App tokens returned once | Only the SHA-256 digest is persisted |
| Nothing raw on-chain | Phase 3 anchors hashes and Merkle roots only |

The privacy guard is unconditional — there is deliberately no flag to disable it.

## 8. Data model

21 tables. The 12 platform tables added in Phase 1 (migration `0002_trust_platform`):

`users`, `devices`, `sessions` (extended), `behavior_features`, `trusted_baselines`,
`shadow_baselines`, `trust_states`, `actions`, `action_risk_profiles`, `security_events`,
`trust_receipts`, `proof_records` — plus `platform_incidents` for containment/incident records.

Design notes:

- Sessions extend the existing `sessions` table rather than introducing a parallel table:
  `user_ref_id` / `device_ref_id` FKs (named `fk_sessions_user_ref_id` /
  `fk_sessions_device_ref_id` so SQLite batch mode can rebuild them), plus
  `baseline_network_country` and `baseline_network_asn`.
- Devices are keyed by a unique `device_fingerprint`.
- Everything is tenant-scoped via `customer_tenant_id`.
- `receipts` and `proof_records` are created up front so Phase 2/3 add behaviour, not schema churn.

## 9. Deployment

```text
┌──────────────┐   /api (nginx proxy)   ┌──────────────┐   SQLAlchemy   ┌────────────┐
│  frontend    │ ──────────────────────▶│   backend    │ ──────────────▶│ PostgreSQL │
│  nginx+SPA   │                        │  FastAPI     │                └────────────┘
└──────────────┘                        │              │   state/cache  ┌────────────┐
       ▲                                │  trust       │ ──────────────▶│   Redis    │
       │ telemetry                      │  engine      │                └────────────┘
┌──────┴───────┐                        │  PEP (Ph.2)  │
│ Browser SDK  │                        └──────┬───────┘
│ (TrustDev)   │                               │
└──────────────┘                        ┌──────▼───────┐
                                        │  telemetry   │
                                        │  worker      │
                                        └──────────────┘
```

The browser only ever talks to one origin; nginx proxies `/api` to the backend so no client needs
to know the backend host. PostgreSQL and Redis are optional for local development — the backend
falls back to SQLite and an in-memory state manager, logging a warning at startup.

The Docker build context is the `trustpulse/` root (not `backend/`), because the backend image needs
`ml/` and `shared/`.
