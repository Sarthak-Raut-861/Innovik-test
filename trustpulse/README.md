# TRUSTPULSE AI

**Evidence-Centric Continuous Digital Trust Platform**

> Authenticate once. Trust continuously. Authorize every sensitive action. Prove why.

TRUSTPULSE keeps re-evaluating a session *after* authentication. A user logs in once; from then on
every sensitive action is authorized against the trust the session has earned, and every decision
ships with the evidence that explains it.

**What TRUSTPULSE is not:**

- **Not** a session-timeout / inactivity system. It measures behavior, not idleness.
- **Not** an MFA replacement. It consumes authentication strength as one input.
- **Not** an IAM replacement. Your IdP still owns identity; TRUSTPULSE owns continuous trust.
- **Not** a probability model. TCI is an engineering trust index (0–100), not a likelihood.

---

## Status

| Phase | Scope | Status |
|---|---|---|
| **1** | Shared trust model, ML core, data model, trust engine, SOC dashboard, SDK, demo data | ✅ complete |
| **2** | Action risk catalogue, policy engine, PEP enforcement, step-up, revocation, containment, incidents, Trust Receipts | ✅ complete |
| **3** | SHA-256 receipt proofs, Merkle anchoring, verification UI, WebSockets, TrustDev integration, attack demo | ⏳ next |

See [`docs/PHASE1_REPORT.md`](docs/PHASE1_REPORT.md) for what Phase 1 delivered,
and [`docs/PHASE2_ENFORCEMENT.md`](docs/PHASE2_ENFORCEMENT.md) for Phase 2 — including the
seven bugs that running the code turned up and how each was fixed.

---

## Quick start

### With Docker

```bash
cp .env.example .env          # then change the passwords
docker compose up --build
docker compose run --rm --profile tools seed
```

- SOC dashboard: http://localhost:5173
- API docs: http://localhost:8000/docs

### Without Docker (needs Python 3.11+ and Node 20+)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
pip install ./ml                          # the trustpulse_ml package

# 1) create the schema and seed the demo data
cd backend
DATABASE_URL="sqlite+aiosqlite:///./trustpulse.db" alembic upgrade head
DATABASE_URL="sqlite+aiosqlite:///./trustpulse.db" python scripts/seed_demo.py

# 2) run the API
DATABASE_URL="sqlite+aiosqlite:///./trustpulse.db" uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then, in a second terminal:

```bash
cd frontend
npm install && npm run dev    # http://localhost:5173, proxies /api to :8000
```

PostgreSQL and Redis are optional for local work: without them the backend falls back to SQLite
and an in-memory state manager (both log a warning at startup).

### Run the demo

```bash
python demo/run_demo.py --base http://127.0.0.1:8000        # trust trajectory
python demo/run_attack_demo.py --base http://127.0.0.1:8000 # full attack loop
```

Seeded credentials: `alice.chen` / `marcus.reed` / `priya.nair`, password `TrustDemo!234`,
MFA code any 6 digits (prototype simulation).

---

## The trust loop

```text
        ┌──────────────────────────────────────────────────────────────┐
        │  Browser SDK — derived interaction features only             │
        │  (typing rhythm, pointer kinematics, click cadence, scroll)  │
        └───────────────────────────┬──────────────────────────────────┘
                                    │  POST /api/v1/telemetry
                                    ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  TRUST ENGINE     T = F(I, D, B, N, C, H)  →  TCI 0–100      │
        │  anomaly detection vs Trusted Core + Adaptive Shadow         │
        │  trust state with hysteresis  +  explainable evidence        │
        └───────────────────────────┬──────────────────────────────────┘
                                    ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  POLICY ENGINE + PEP  (Phase 2)   session trust × action risk│
        │  → ALLOW / STEP_UP / BLOCK / REVOKE / CONTAIN                │
        └───────────────────────────┬──────────────────────────────────┘
                                    ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  TRUST RECEIPT → SHA-256 → Merkle root → anchor (Phase 3)    │
        └──────────────────────────────────────────────────────────────┘
```

**Detection never decides.** The ML components produce evidence; the server-side Policy Enforcement
Point is the only thing that can authorize an action.

### The six factors

`TCI = Σ weightᵢ × scoreᵢ`, clamped to 0–100. Weights are configurable and renormalised at runtime,
so a factor with no evidence is excluded rather than scored as distrust.

| Factor | Default weight | Signal |
|---|---|---|
| Identity | 0.15 | Authentication strength, MFA, credential age |
| Device | 0.20 | Device registration, history, integrity signals |
| **Behavior** | **0.30** | Deviation from the user's trusted behavioral baseline |
| Network | 0.15 | Country / ASN stability, VPN / Tor |
| Session | 0.10 | Session age, prior anomalies within the session |
| History | 0.10 | Rolling TCI history for this user + device |

### Trust states

`TRUSTED ≥ 85 · DEGRADED ≥ 70 · SUSPICIOUS ≥ 50 · CRITICAL ≥ 30 · BLOCKED ≥ 0`

Transitions are hysteresis-gated so a single noisy sample cannot flip a session: escalation needs
confirmation (or a decisive TCI drop), recovery needs sustained improvement, and `BLOCKED` /
`CONTAINED` never auto-recover.

### Authorizing an action

Trust alone is not a decision. Every sensitive action is scored 0–100 from a
configured catalogue, then run against an ordered rule list, and the result is
`ALLOW`, `STEP_UP` or `BLOCK`.

```text
TrustEngine ──► PolicyEngine ──► PEP ──► decision + Trust Receipt
 (observes)      (recommends)   (enforces)
```

The ML layer and the policy engine are **advisory**. Only the server-side Policy
Enforcement Point can authorize an action: it is the sole code path that writes
an action record, issues a receipt, opens an incident or contains a session.

Eleven rules ship in `shared/constants/trust_model.json`, first match wins, and
the last must be a catch-all. A rule set with no catch-all is rejected at load
time. **An unknown predicate never matches** — it is skipped and recorded, so a
typo in a rule cannot silently weaken enforcement.

Every decision returns a `policy_audit` listing *every* rule that was evaluated
and why each one did not match. That is what makes "why was this blocked?"
answerable by an analyst rather than by reading code.

Every terminal decision issues a **Trust Receipt**: a SHA-256 hash-bound record
of who, what, when, at what trust level, under which rule — single-use, with a
short expiry, and verifiable against the evidence it cites.


---

## Repository layout

```text
trustpulse/
├── shared/constants/trust_model.json   # single source of truth for all tunables
├── ml/                                 # trustpulse_ml: features, baselines, anomaly, fusion
├── backend/
│   ├── app/api/routes/                 # /api/v1 platform endpoints
│   ├── app/core/trust_config.py        # config loader + env overrides
│   ├── app/models/                     # SQLAlchemy models (21 tables; 12 added in Phase 1)
│   ├── app/services/trust_engine/      # factors, state machine, engine
│   ├── app/services/platform/          # identity, trust, seed
│   ├── app/services/action_risk/       # catalogue + context-aware evaluator
│   ├── app/services/policy/            # ordered rule engine (recommends only)
│   ├── app/services/enforcement/       # PEP — the only thing that enforces
│   ├── app/services/receipts/          # hash-bound, single-use Trust Receipts
│   ├── app/services/incidents/         # incident lifecycle + security posture
│   └── migrations/                     # Alembic (0001 initial, 0002 trust platform)
├── frontend/                           # React + Vite + TS + Tailwind + Recharts
│   └── src/trustpulse-sdk/             # browser SDK (privacy-first collectors)
├── sdk/                                # published TS SDK package
├── demo/                               # personas, run_demo.py, run_attack_demo.py
├── docs/                               # architecture, security model, API reference
├── docker-compose.yml
└── .env.example
```

---

## Privacy and security rules

These are enforced in code, not just policy:

- **No passwords stored.** PBKDF2-SHA256 digests only; login failures are identical for unknown
  users and wrong passwords (no enumeration).
- **No typed characters, ever.** The SDK never reads `event.key`; only timing deltas are kept, and
  the server rejects any payload containing raw data with HTTP 422.
- **Derived features only.** Means, standard deviations and rates — never raw event streams.
- **No raw behavioral data on the blockchain** (Phase 3 stores hashes and Merkle roots only).
- **IPs stored as SHA-256 digests**, never in plaintext.
- **Baseline poisoning guard.** Observations from `SUSPICIOUS`-or-worse sessions are counted as
  rejected and never reach the Trusted Core; promotion from the Adaptive Shadow is gated on trust
  state and open incidents.
- **No hard-coded thresholds.** Every weight, band and hysteresis parameter comes from
  `shared/constants/trust_model.json` and is overridable by environment.

## Verification

```bash
cd backend
python -m pytest -q          # 299 tests
python -m ruff check app tests scripts ../ml ../demo
```

```bash
cd frontend
npm install && npm run build # tsc -b && vite build
```

## Honest limitations

This is a prototype, and it is deliberately explicit about that:

- Behavioral signals **raise evidence**; they are not proof of identity and are not claimed to be
  impossible to copy.
- The scoring model is a transparent, weighted statistical baseline — not a scientifically
  validated biometric system.
- The demo key ships to the browser so the whole loop runs with one command; a real integration
  keeps it server-side.
- Action risk, policy enforcement, receipts and proofs are **not** implemented until Phases 2–3.

## License

Prototype — internal use.
