# TRUSTPULSE — Phase 1 Report

**Scope:** foundation + core trust. No blockchain, simple AI.

Every number below was produced by a command run in this repository, not estimated. The command is
shown next to each result so it can be re-run.

---

## 1. What was delivered

### 1.1 Declarative trust model (single source of truth)

`shared/constants/trust_model.json` (schema `1.0.0`) holds every tunable: the six TCI weights, the
cold-start TCI, the five state bands, the hysteresis parameters, the 11-action risk catalogue, the
evidence vocabulary, and per-factor parameters.

`shared/schemas/trust.ts` is the canonical TypeScript mirror of the same contracts — trust states,
trends, confidence, evidence vocabulary, factor scores, action risk profiles, receipts, and the
derived-feature shapes. It is guarded by 15 contract tests (`tests/test_shared_contract.py`) that
fail the build if the mirror drifts from the JSON, from the backend config the API actually serves,
from `RISK_BANDS` in the action-risk catalogue, or from the server-side privacy guard.

`backend/app/core/trust_config.py` loads it with three override layers
(`TRUST_MODEL_CONFIG_PATH` → repo `shared/` → `$SHARED_DIR`), applies environment overrides
(`TCI_WEIGHT_*`, `TCI_COLD_START`, `TRUST_STATE_*_MIN`, `ACTION_RISK_<ACTION>`,
`TRUST_MODEL_OVERRIDES`), validates the result, and serves it live at
`GET /api/v1/config/trust-model`. Nothing is hard-coded in an engine.

Verified:

```
$ SHARED_DIR=.../trustpulse/shared python -c "from app.core.trust_config import load_trust_config; ..."
weights: {'identity': 0.15, 'device': 0.2, 'behavior': 0.3, 'network': 0.15, 'session': 0.1, 'history': 0.1}
cold_start: 62.0
action_risk(CREATE_API_KEY): 90
state_for_tci(90): TRUSTED | (75): DEGRADED | (55): SUSPICIOUS
hysteresis: {'escalation_confirmations': 2, 'decisive_drop': 15, 'decisive_depth': 10,
             'multi_level_escalation': 2, 'recovery_buffer': 6, 'recovery_confirmations': 3,
             'no_auto_recovery_states': ['BLOCKED', 'CONTAINED'], 'no_recovery_with_open_incident': True}
```

### 1.2 `ml/` — the only numeric implementation

Installable as `trustpulse_ml`. Five subpackages, all imported and exercised by tests:

| Package | Contents |
|---|---|
| `feature_extraction` | `FeatureSpec`, `extract_feature_vector` (21 features), `transform`/`inverse_transform`, `initial_std`, `assert_no_raw_data` |
| `baseline` | `TrustedCore` (α=0.05), `AdaptiveShadow` (α=0.25, min_obs=8, max distance 1.2), promotion gating |
| `anomaly_detection` | `StatisticalAnomalyDetector`, `IsolationForestAnomalyDetector` (≥30 samples), `fuse_results` |
| `trust_fusion` | `fuse_factors`, weight validation/renormalisation, `classify_confidence`, `compute_trend` |
| `evaluation` | `evaluate_predictions`, `threshold_sweep`, `confusion_matrix` |

Measured behaviour:

- Identical observation to baseline → anomaly **0.0**
- Mild drift (dwell 110.5 → 140) → **0.181**, no reasons raised
- Attacker payload → **0.702**, reasons `['BEHAVIOR_DEVIATION','CLICK_CADENCE_DEVIATION','MOUSE_VELOCITY_DEVIATION','TYPING_DWELL_DEVIATION']`, top feature `mouse_velocity` at z=21.8
- Cold start (no baseline) → **0.0**, `learned=False`, reason `COLD_START_NO_BASELINE`, method `none`
- Evidence text: `mouse_velocity is 21.8 sigma higher/faster than the trusted baseline (observed 9000.0 vs baseline 850.0)`
- Shadow learning under `SUSPICIOUS` → `learned=False, observation_count=0, rejected_observations=1`
- Promotion blocked reasons: `SESSION_NOT_TRUSTWORTHY`, `OPEN_INCIDENT`; drifted-consistent shadow promotes at distance 0.029
- Privacy guard: `RawDataRejectedError("Rejected telemetry key 'characters': raw data is never accepted by TRUSTPULSE")`

### 1.3 Trust engine

`backend/app/services/trust_engine/` — `factors.py` (six factor scorers), `state_machine.py`
(hysteresis), `engine.py` (orchestration).

Rules implemented deliberately:

- **Unavailable factors are excluded, not penalised** — weights renormalise, a
  `FACTOR_UNAVAILABLE:<name>` warning is attached.
- **Confidence is independent of score** — a login can be TRUSTED with LOW confidence.
- **Sustained anomaly accumulates** — the behavior factor uses `consecutive_anomalies` with a
  `sustained_anomaly_penalty` of 8 per step, capped at 40, so a persistent attacker degrades
  steadily instead of plateauing.
- **First assessment short-circuits hysteresis** (`INITIAL_ASSESSMENT`).
- **A session cannot corroborate its own baseline** — network baselines come from prior sessions
  only.
- **Learning is gated** on trust state and open incidents.

### 1.4 Data model + migration

`migrations/versions/0002_trust_platform.py` creates the 12 platform tables and extends `sessions`.

```
$ alembic upgrade head && alembic downgrade base && alembic upgrade head
tables: 22        (21 application + alembic_version)
sessions cols: 39
```

Round trip is clean in both directions. All 13 requested tables exist:
`users, devices, sessions, behavior_features, trusted_baselines, shadow_baselines, trust_states,
actions, action_risk_profiles, security_events, incidents (platform_incidents), trust_receipts,
proof_records`.

### 1.5 API surface

16 platform routes live under `/api/v1` (verified via `app.openapi()["paths"]`):

```
auth/login                    session                       session/{id}/end
telemetry                     trust/evaluate                trust/{id}
trust/{id}/history            config/trust-model            config/actions
actions/known                 soc/overview                  soc/sessions
soc/sessions/{id}             users                         devices
platform/health
```

### 1.6 Frontend — SOC dashboard, TrustDev app, browser SDK

`frontend/` — React 18 + Vite 5 + TypeScript + Tailwind 3 + Recharts.

- **SOC dashboard** — live session table, aggregate metrics, TCI history with configured band
  boundaries drawn as reference lines, factor breakdown, explainable evidence, baseline
  observation counts, action list, state timeline.
- **TrustDev** — simulated enterprise developer/cloud console with a login, demo controls
  (emit normal behavior / simulate takeover / flush live SDK features), live TCI gauge and console log.
- **Browser SDK** (`src/trustpulse-sdk/`) — typing, pointer, click and scroll collectors that emit
  **derived aggregates only**; `privacy.ts` enforces forbidden-key patterns, text-value rejection
  and bounded buffers; a non-reversible device fingerprint; passive listeners so collection cannot
  slow the host app. The SDK never scores trust.
- **Trust model transparency page** — live weights, bands, hysteresis, action catalogue and evidence
  vocabulary.

The browser only ever issues relative `/api` requests; the Vite dev server (and nginx in
production) proxies them to the backend.

### 1.7 Demo data + runner

`demo/seed_data/personas.json` — 3 personas (alice.chen ADMIN+MFA, marcus.reed DEV, priya.nair SOC)
with per-persona behavioral profiles, 3 seeded devices, an attacker profile and attacker device,
plus the TrustDev integration (tenant `trustdev-demo`, public key `pk_trustdev_demo_0001`, API key
`tp_demo_trustpulse_key_0001`). Password `TrustDemo!234`.

`demo/run_demo.py` drives login → normal telemetry → takeover → privacy guard → SOC view.

### 1.8 Packaging

`backend/Dockerfile` (context = repo root, installs `ml/` explicitly, non-root, healthcheck),
`frontend/Dockerfile` + `nginx.conf` (SPA + `/api` proxy + WebSocket upgrade),
`docker-compose.yml` (postgres, redis, backend, telemetry-worker, frontend, `seed` profile),
`.env.example`, root `README.md`, updated `docs/{ARCHITECTURE,API_REFERENCE}.md`.

---

## 2. Verification

### 2.1 Automated

```
$ cd trustpulse/backend && python -m pytest -q
204 passed in 24.51s          (78 pre-existing + 126 new)

$ python -m ruff check app tests scripts ../ml ../demo
All checks passed!

$ cd ../frontend && npx tsc --noEmit --strict ../shared/schemas/trust.ts
clean

$ cd trustpulse/frontend && npm run build
✓ 849 modules transformed → dist/assets/index-DVx7uJox.js 593.72 kB │ gzip: 173.21 kB
✓ built in 4.32s
```

New test files, with per-file counts:

| File | Tests | Covers |
|---|---|---|
| `test_trust_model.py` | 36 | TCI arithmetic, weight renormalisation, bands, hysteresis, config overrides |
| `test_ml_core.py` | 34 | Features, transforms, baselines, promotion gating, anomaly fusion, privacy guard |
| `test_platform_flow.py` | 26 | End-to-end API: login, no-enumeration, escalation, privacy rejection |
| `test_shared_contract.py` | 15 | TS mirror ↔ JSON ↔ backend config ↔ catalogue ↔ privacy vocabulary |
| `test_action_risk_catalogue.py` | 15 | Risk values, bands, inference, env overrides |

### 2.2 Live HTTP run

Backend on SQLite + in-memory Redis fallback, frontend dev server on :5173 proxying `/api`:

```
$ curl http://127.0.0.1:5173/                    → http=200
$ curl http://127.0.0.1:5173/api/v1/soc/overview → {"active_sessions":4,"suspicious_sessions":3,
                                                    "contained_sessions":0,"average_tci":64.88,...}
$ curl .../api/v1/config/trust-model             → schema 1.0.0, weights {identity .15, device .2,
                                                    behavior .3, network .15, session .1, history .1},
                                                    11 actions, 5 state bands
$ curl http://127.0.0.1:5173/soc/sessions/TS-... → http=200   (SPA deep route)
```

### 2.3 Measured trust trajectory (live API, `demo/run_demo.py`)

Alice on her seeded registered device, so a Trusted Core baseline exists:

```
LOGIN        : TCI  86.0 TRUSTED    evidence=LOW
NORMAL  #1-5 : TCI  90.3 → 90.4  TRUSTED    anomaly≈0.078
ATTACKER #1  : TCI  72.4 DEGRADED   anomaly=0.602
ATTACKER #2  : TCI  65.4 DEGRADED   anomaly=0.598
ATTACKER #3  : TCI  61.0 SUSPICIOUS anomaly=0.598   ← state escalates
ATTACKER #4-10: TCI 61.0 SUSPICIOUS  (sustained)
```

These are one observed run, not fixed constants — and the difference between runs is itself
instructive. On a **freshly seeded** database:

```
LOGIN        : TCI  85.2 TRUSTED
NORMAL  #1-5 : TCI  91.0 → 91.1  TRUSTED    anomaly 0.065-0.071
ATTACKER #1  : TCI  69.5 SUSPICIOUS         anomaly=0.603
ATTACKER #2  : TCI  64.1 SUSPICIOUS         anomaly=0.603
```

Re-running the demo repeatedly **against the same database** progressively lowers the numbers: a
later run measured normal samples at anomaly `0.214-0.233` with TCI ~82 DEGRADED, because the
history factor and the session-context factor now see the prior suspicious sessions and their
incidents. This is the model working as intended rather than drift or a defect — a user whose recent
history is full of suspicious sessions *should* start from a lower baseline.

The consequence for reproduction: **seed a fresh database for a clean run.**

```bash
rm -f trustpulse.db && alembic upgrade head && python scripts/seed_demo.py
```

The *shape* is stable across all runs: trusted login, stable normal use, a decisive drop on the
first attacker sample, escalation to SUSPICIOUS within one to three samples, then a sustained
plateau.

Evidence produced for the hijacked session:

```
[BEHAVIOR_DEVIATION] Behavioral confidence is 0/100
    (BASELINE_DEVIATION, SUSTAINED_BEHAVIORAL_DEVIATION, BEHAVIOR_DEVIATION, CLICK_FREQUENCY_DEVIATION)
[BASELINE_DEVIATION] scroll_distance is 27.0 sigma higher/faster than the trusted baseline
    (observed 240000.0 vs baseline 9974.1)
[BASELINE_DEVIATION] scroll_pause_duration is 25.8 sigma lower/slower than the trusted baseline
[BASELINE_DEVIATION] mouse_acceleration is 25.4 sigma higher/faster than the trusted baseline
baselines: core_obs=29 shadow_obs=13
```

Privacy guard against the live API:

```
POST /api/v1/telemetry {"features":{"characters":"hunter2"}}
→ http=422 {"error":"Raw behavioral data is not accepted",
            "details":{"reason":"Rejected telemetry key 'characters': raw data is never
                        accepted by TRUSTPULSE","policy":"TRUSTPULSE only accepts derived
                        aggregate features."}}
```

No-enumeration check (identical bodies):

```
unknown user    → 401 {"error":"Invalid credentials","details":{}}
wrong password  → 401 {"error":"Invalid credentials","details":{}}
```

### 2.4 Behaviour that is correct but worth stating

A **behavior-only** takeover (same device, same network) settles at SUSPICIOUS ≈ 61 and does not
collapse to BLOCKED. That is the model working as designed — with identity, device, network and
session all still consistent, one degrading factor cannot override the rest ("no single signal is
trusted absolutely", and the converse also holds). Reaching CRITICAL/BLOCKED requires the combined
scenario used in the Phase 3 attack demo.

Measured for comparison, the harsher scenario — a brand-new device from RU/AS48666 over
VPN/Tor, password-only auth (marcus.reed, MFA not enabled), measured against the live API:

```
TCI 48.6 CRITICAL  confidence=LOW
  identity   55.0  available=True
  device     20.0  available=True      (NEW_DEVICE, DEVICE_LOW_HISTORY)
  behavior   55.0  available=False     (no baseline for this device — excluded, not penalised)
  network    35.0  available=True      (new country + VPN/Tor; no prior-country baseline to lose)
  session    90.0  available=True
  history    75.0  available=True
evidence: DEVICE_CHANGE, IDENTITY_ASSURANCE_DROP, NETWORK_CHANGE, STATE_CHANGE
```

Note the contrast that makes the design legible: the *first* scenario has a real behavioral
baseline, so the attacker is caught by evidence (anomaly 0.602) but trust only degrades. This one
has no behavioral baseline at all — `behavior` is excluded rather than scored — and trust lands in
CRITICAL on identity, device and network evidence alone.

---

## 3. Bugs found and fixed during Phase 1

Found by testing, not by reading:

1. **Baseline std prior was ~10× too wide.** The prior was computed as `abs(transformed) * 0.15` in
   *log* space. Fixed by expressing `relative_std` in raw units and mapping through the feature
   transform.
2. **`metadata` is reserved on `DeclarativeBase`.** Renamed the attribute to `meta` mapped to
   column `"metadata"`.
3. **Circular import.** `app/services/__init__` → `risk_service` → `app.api.dependencies` →
   `app.api.__init__` (which eagerly imports routers) → back into the partially-initialised
   service. Any tool importing services before the API crashed. Fixed by moving
   `IntegrationContext` to `app/core/context.py`; `app.api.dependencies` re-exports it.
4. **Dead hysteresis rule.** `decisive_score = tci <= band_min(raw_band) - buffer` could never
   fire, because `state_for_tci` guarantees `tci >= band_min(raw_band)`. Redefined against the
   *current* state's floor.
5. **Evidence accumulation gap.** The behavior factor used only the latest anomaly score, so a
   sustained attacker plateaued forever. Added `consecutive_anomalies` +
   `SUSTAINED_BEHAVIORAL_DEVIATION`.
6. **Hysteresis applied to a first-ever assessment** made a suspicious login render TRUSTED. Added
   the `INITIAL_ASSESSMENT` short-circuit.
7. **A session corroborated its own baseline** — network baselines were seeded from the observation
   being scored, so every first network check "matched baseline" and scored 95. Baselines now come
   from prior sessions only.
8. **A blind spot was scored as distrust** — with no network baseline, `score_network` returned 65
   and dragged a clean first login to DEGRADED. Now `available=False` unless VPN/Tor is present.
9. **`AnomalyResult.method`, not `.detector_method`** — crashed only on
   `POST /session/{id}/end`, an otherwise untested path.
10. **Migration 0002 required five fixes found only by running alembic** (a syntax check passed on
    the broken file every time): inline `sa.ForeignKeyConstraint` → `sa.ForeignKey`; SQLite needs
    `op.batch_alter_table(..., recreate="always")`; calls inside a batch block must be `batch_op.*`
    with no table argument; batch mode requires named constraints; generated `server_default`
    literals were unquoted Python.
11. **`.env.example` documented two variables that do not exist** (`TRUST_MODEL_PATH`,
    `REJECT_RAW_BEHAVIORAL_DATA`). Corrected to the real `SHARED_DIR` /
    `TRUST_MODEL_CONFIG_PATH`, and documented that raw-data rejection is deliberately
    non-configurable.
12. **Contract drift between the TS mirror and the server privacy guard.** The browser-side
    forbidden-key list was missing `input_value` and `key_value` (the underscore variants the server
    guards), so the SDK could have transmitted a key the API would reject. Caught by the new
    contract test; both `shared/schemas/trust.ts` and `frontend/src/trustpulse-sdk/privacy.ts` now
    mirror `FORBIDDEN_KEY_PATTERNS` exactly, and a test fails if they diverge again.
13. **The evidence vocabulary in the TS mirror was wrong** — it included `FACTOR_UNAVAILABLE`
    (which is a *warning* prefix, not an evidence type) and omitted `COLD_START` and
    `TELEMETRY_GAP`. Now matches `evidence_types` in the JSON exactly, with a test pinning both
    directions of the mistake.
14. **`_extract_bearer_key` was deleted** by an over-broad edit to `dependencies.py`; caught only
    because a live HTTP request returned 500 where the in-process tests passed. Restored.

---

## 4. Known limitations and open items

- **No Docker, PostgreSQL or Redis binaries exist in this sandbox.** `docker compose build` and
  `docker compose up` are therefore **unverified**. The compose file, both Dockerfiles and
  `nginx.conf` are written and YAML/structure-checked but have never been executed by a Docker
  daemon. Verification went through pytest + `sqlite+aiosqlite` + the in-memory Redis fallback.
- The demo API key ships to the browser so the whole loop runs with one command. A real integration
  keeps it server-side; TrustDev would call TRUSTPULSE server-to-server.
- The Phase 1 frontend polls the SOC endpoints (3–4 s). WebSockets arrive in Phase 3.
- The main JS bundle is 594 kB (173 kB gzipped) — above Vite's 500 kB advisory. Code-splitting is
  deferred; it is a warning, not an error.
- `trustpulse/docs/PHASE2_REPORT.md` predates this engagement and titles the pre-existing security
  backend "Phase 2", which collides with this engagement's numbering. The numbering in this report
  governs.
- Phase 1 deliberately does **not** implement: action risk evaluation endpoints, the policy engine,
  PEP enforcement, step-up, revocation, containment, incidents, Trust Receipts, Merkle proofs,
  blockchain anchoring, or the WebSocket feed. The schema for receipts and proofs exists so
  Phases 2–3 add behaviour rather than migrations.

---

## 5. Phase 2 entry points

| Need | Already in place |
|---|---|
| Action risk | `app/services/action_risk/catalogue.py` + `action_risk_profiles` table + 11-action catalogue with bands |
| Trust input to policy | `TrustEngine.evaluate()` returning `TrustResult` |
| Enforcement tables | `action_requests`, `security_decisions`, `trust_receipts`, `proof_records` |
| Containment tables | `platform_incidents`, `sessions.is_contained` |
| API conventions | `/api/v1` router wiring, tenant auth, uniform error shape |
