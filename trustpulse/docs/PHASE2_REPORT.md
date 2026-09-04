# TrustPulse AI — Phase 2 Security Backend Report

**Version:** 2.0.0  
**Date:** 2026-09-04  
**Path:** `trustpulse/backend`

---

## 1. Architecture Implemented

The Phase 2 backend is a reusable, tenant-scoped security service that preserves the
required pipeline:

```text
Telemetry -> Detection -> Risk Evidence -> Action Risk -> Deterministic Policy -> Security Decision
```

It never runs `Telemetry -> LLM -> BLOCK`, never lets a behavioral model authorize
directly, and never trusts a browser-provided risk score.

### Layers

| Layer | Location |
|---|---|
| HTTP API | `app/api/routes/*` |
| Authentication / tenant scope | `app/api/dependencies.py` |
| Config / security / logging / Redis | `app/core/*` |
| SQLAlchemy models | `app/models/*` |
| Pydantic schemas | `app/schemas/*` |
| Services | `app/services/*` |
| Detection / risk / policy engines | `app/engines/*` |
| Repositories (tenant scoped) | `app/repositories/*` |
| Background telemetry worker | `app/workers/*` |
| Alembic migrations | `migrations/` |

### Data flow

1. Customer application creates a session with `POST /v1/sessions`.
2. Browser SDK posts telemetry batches to `POST /v1/telemetry`.
3. Backend validates session binding, replay, sequence, freshness, schema, ranges.
4. Valid telemetry is persisted to PostgreSQL; behavioral baselines update via a
   candidate/trusted baseline model (synchronously by default, or via the background
   worker when `TELEMETRY_ASYNC_PROCESSING=true`).
5. For a sensitive action, the customer application calls `POST /v1/risk/evaluate`.
6. The risk service performs a **fresh** evaluation (not the last background score),
   fuses signals, computes action risk, runs the policy engine, and records a decision.

## 2. Files Created

The backend was enhanced/created under `trustpulse/backend`:

```
app/api/dependencies.py
app/api/routes/actions.py
app/api/routes/incidents.py
app/core/metrics.py
app/models/integration_client.py
app/repositories/integrations.py
app/services/action_risk_service.py
app/services/audit_service.py
app/services/behavioral_service.py
app/services/incident_service.py
app/services/policy_service.py
app/workers/telemetry_worker.py
app/workers/telemetry_worker_main.py
migrations/env.py
migrations/script.py.mako
migrations/versions/0001_initial.py
alembic.ini
Dockerfile
.env.example
scripts/create_integration.py
tests/conftest.py
tests/test_api.py
tests/test_security.py
tests/test_multi_tenancy.py
tests/test_behavioral_engines.py
tests/test_action_risk.py
tests/test_failure_modes.py
docs/PHASE2_REPORT.md
```

## 3. Files Modified

```
app/main.py                     secure headers, request-size cap, metrics, worker, OpenAPI auth schemes
app/core/config.py              production settings and fail-safe configuration
app/core/exceptions.py          authentication, tenant, replay, stale, validation, unavailable errors
app/core/redis.py               replay, sequence, rate limits, queues, decision state, safe fallback
app/core/security.py            FNV-1a compat, API-key hashing, secret redaction
app/core/logging.py             structured JSON security logs
app/models/*                    baseline history/rollback, telemetry rejection, integration clients
app/schemas/*                   hardened telemetry ranges, action/incident schemas
app/repositories/*              tenant-scoped repos + rollback + integrations
app/services/session_service.py audit + SDK binding + terminal state rules
app/services/telemetry_service.py robust validation + rejected-event persistence + queue
app/services/risk_service.py    fresh eval + hysteresis + incident + audit
app/engines/*                   robust z-score, drift, policy engine, baseline protection
app/api/routes/*                auth via integration credentials
app/api/__init__.py             incidents/actions routers
docker-compose.yml              postgres + redis + backend + worker + test-server
pyproject.toml / requirements   Python 3.12 target, ruff/mypy config
```

## 4. Database Schema

Migrations in `migrations/versions/0001_initial.py`.

| Table | Purpose |
|---|---|
| `integration_clients` | tenant + public key (non-secret) + API key hash |
| `sessions` | session binding, subject/device pseudonyms, status/version |
| `telemetry_events` | event payload, sequence, freshness, validation/rejection state |
| `behavioral_profiles` | trusted/candidate baselines, version, confidence, observation count |
| `risk_assessments` | behavior/device/network/history signals + confidence |
| `action_requests` | generic action + risk level + optional amount/currency/resource |
| `security_decisions` | ALLOW/STEP_UP/BLOCK/ISOLATE + policy version/rule |
| `incidents` | severity, status, trigger, decision reference |
| `audit_logs` | immutable-style structured audit (secrets redacted) |

This is TrustPulse's **own** database. It never connects to the customer's banking
database directly.

## 5. API Endpoints

All under `/v1`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/sessions` | register/bind a session |
| GET | `/sessions/{id}` | read session for tenant |
| PATCH | `/sessions/{id}/status` | PAUSED/TERMINATED/ISOLATED/ACTIVE |
| POST | `/telemetry` | SDK batch telemetry ingestion |
| POST | `/telemetry/batch` | backward-compatible alias |
| POST | `/risk/evaluate` | fresh action risk + policy decision |
| GET | `/incidents` | list tenant incidents |
| GET | `/incidents/{id}` | get incident |
| POST | `/incidents/{id}/resolve` | resolve/close incident |
| GET | `/actions` | list action requests |
| GET | `/actions/{id}` | get action request |
| GET | `/actions/catalog` | generic built-in action risk catalog |
| GET | `/health` | liveness + dependency state |
| GET | `/health/ready` | readiness (DB required, Redis reported) |
| GET | `/health/metrics` | non-sensitive counters |

OpenAPI: `/docs`, `/redoc`, `/openapi.json`.

## 6. Redis Usage

Redis stores only temporary/high-speed data; PostgreSQL remains authoritative.

* Replay event IDs (`tp:{tenant}:replay:{event_id}`, SET NX)
* Monotonic sequence per session+SDK instance (`tp:{tenant}:seq:{session}:{sdk}`)
* Tenant/session fixed-window rate limits
* Short-lived decision/hysteresis state (`tp:{tenant}:decision:{session}`)
* Session cache stub
* Background telemetry queue (`tp:{tenant}:queue:telemetry`)

If Redis is unavailable, the backend switches to an in-memory fallback and reports
degraded durability for replay/rate-limit guarantees in `/health`.

## 7. Security Controls

* **Integration authentication**: server API key (`Authorization: Bearer` or
  `X-TrustPulse-API-Key`) for app-to-TrustPulse calls; non-secret `X-TrustPulse-Public-Key`
  for browser SDK identification with server-side session binding.
* **Tenant isolation**: every repository query is tenant-scoped; cross-tenant tests pass.
* **Replay protection**: event ID and sequence progression enforced with Redis.
* **Flood protection**: request-body cap, batch/feature size caps, per-tenant and
  per-session rate limits, queue limits, priority to background processing.
* **Secret management**: all secrets via env; API keys stored as SHA-256 hashes.
* **Structured logging**: JSON logs with recursive secret redaction.
* **Secure headers**: CSP, X-Frame-Options, nosniff, referrer policy, no-store.
* **Fail-safe**: DB/unavailable risk engine returns 503 and never converts UNKNOWN→ALLOW
  for critical actions.
* **Baseline poisoning protection**: candidate baseline cannot auto-overwrite trusted baseline.

## 8. Test Results

Run from `trustpulse/backend`:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Result (local sandbox, Python 3.11 runtime):

```text
78 passed in 3.17s
```

Coverage suites:

* `test_api.py` — sessions, telemetry, risk, incidents, actions, health
* `test_security.py` — missing credentials, replay, stale, invalid session, rate limit
* `test_multi_tenancy.py` — read/modify/evaluate/telemetry isolation
* `test_behavioral_engines.py` — no baseline, normal, anomaly, drift, NaN/Inf, missing features
* `test_action_risk.py` — LOW/MEDIUM/HIGH/CRITICAL
* `test_policy_engine.py` — ALLOW/STEP_UP/BLOCK/ISOLATE
* `test_failure_modes.py` — Redis fallback, DB unavailable, behavioral engine failure, queue failure

Lint:

```bash
ruff check .   # All checks passed!
```

## 9. Commands to Start the System

### Local (no external services, SQLite + Redis fallback)

```bash
cd trustpulse/backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Docker (PostgreSQL + Redis + backend + worker)

```bash
cd trustpulse
TRUSTPULSE_DB_PASSWORD=dev_db_pw TRUSTPULSE_REDIS_PASSWORD=dev_redis_pw docker compose up --build
```

OpenAPI: `http://localhost:8000/docs`

### Create integration credentials

```bash
cd trustpulse/backend
. .venv/bin/activate
python scripts/create_integration.py --tenant acme-bank --name "Acme Bank Web"
```

## 10. Example SDK -> Backend Request

```json
POST /v1/telemetry
X-TrustPulse-Public-Key: pk_...
X-TrustPulse-Session-Id: app-session-123
Content-Type: application/json

{
  "batchId": "b-1",
  "sentAt": 1788490000000,
  "packets": [
    {
      "sessionId": "app-session-123",
      "sdkInstanceId": "sdk-inst-abc",
      "eventId": "evt-1",
      "sequenceNumber": 1,
      "timestamp": 1788490000000,
      "schemaVersion": "1.0.0",
      "sdkVersion": "1.0.0",
      "eventType": "behavioral_batch",
      "features": {
        "feature_schema_version": "1.0.0",
        "typing": {"sampleCount": 45, "meanDwellTime": 95.3},
        "mouse": {"sampleCount": 120, "meanVelocity": 350.0}
      },
      "integrity": "<fnv1a>"
    }
  ]
}
```

## 11. Example Risk Evaluation

```http
POST /v1/risk/evaluate
Authorization: Bearer tp_...
Content-Type: application/json
```

```json
{
  "session_id": "app-session-123",
  "action": {"type": "LARGE_TRANSFER", "amount": 50000, "currency": "INR"}
}
```

Response:

```json
{
  "decision": "STEP_UP",
  "session_confidence": 54,
  "confidence_level": "GUARDED",
  "action_risk": "CRITICAL",
  "reason_codes": ["CONFIDENCE_TOO_LOW_FOR_ACTION", "ACTION_RISK_CRITICAL"],
  "policy_version": "v1",
  "policy_rule_id": "critical-step-up",
  "decision_id": "<uuid>",
  "evaluated_at": "...",
  "decision_expires_at": "..."
}
```

## 12. Known Limitations

* **Prototype level**: policy thresholds, signal weights, action catalog, and baseline
  learning are not yet calibrated against real false-positive/false-negative data.
* **Not production-ready for adversarial deployment**: no TLS termination inside the app,
  no secrets-manager integration, no per-tenant RBAC admin UI, no Prometheus/OTel metrics,
  no API-key rotation/revocation UI, no data retention jobs.
* **Network signal is not available** (no threat-intelligence integration in Phase 2).
* **Device evidence is deliberately conservative**; robust device fingerprinting is future work.
* **Hysteresis is process/Redis-state based** and is not persisted as an authoritative
  decision policy.
* **SQLite is supported only for local/test**; production must use PostgreSQL.
* The development tenant-header fallback is enabled by default for convenience and MUST be
  disabled in production.

## 13. Recommended Phase 3

1. Production calibration pipeline (FPR, FNR, precision, recall, latency).
2. Per-tenant policy configuration with RBAC and immutable audit of policy changes.
3. Threat-intelligence / IP risk signals (without trusting any single source).
4. Device trust registry with consent-aware hashed device correlation.
5. Prometheus/OTel + distributed tracing + persistent metrics.
6. API-key rotation, scopes, per-tenant rate-limit quotas.
7. Honeypot/deception infrastructure for `ISOLATE` (explicitly out of scope for Phase 2).
8. Optional LLM explanation AFTER a decision, with zero decision power.
9. Data retention/erasure (GDPR-compatible) and export for audit.
10. Load testing and production-ready observability dashboards.
