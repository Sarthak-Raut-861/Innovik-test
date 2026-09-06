# TRUSTPULSE — Phase 2 Report: Risk-Aware Authorization & Enforcement

**Status:** complete and verified.
**Scope:** action risk, policy decisions, the server-side PEP, step-up, revocation, containment,
security posture, evidence, Trust Receipts and incidents.

Phase 1 established *how trustworthy a session is*. Phase 2 answers the question that actually
matters to an integrating application: **given that trust level, may this specific action
proceed?**

---

## 1. What Phase 2 adds

| Component | Path | Role |
| --- | --- | --- |
| Action risk evaluator | `backend/app/services/action_risk/evaluator.py` | Scores an action 0–100 from the catalogue plus context |
| Policy engine | `backend/app/services/policy/engine.py` | Recommends ALLOW / STEP_UP / BLOCK from an ordered rule list |
| **Policy Enforcement Point** | `backend/app/services/enforcement/pep.py` | The **only** component that produces an enforced decision |
| Receipt service | `backend/app/services/receipts/service.py` | Issues and verifies signed, single-use Trust Receipts |
| Incident & posture service | `backend/app/services/incidents/service.py` | Incident lifecycle and aggregate security posture |
| API surface | `backend/app/api/routes/platform_authorization.py` | 11 endpoints under `/api/v1` |
| Contract schemas | `backend/app/schemas/authorization.py`, `shared/schemas/trust.ts` | Wire formats, mirrored and test-guarded |

### The enforcement boundary

This is the architectural point Phase 2 exists to make real:

```
TrustEngine  ──► PolicyEngine ──► PEP ──► decision + receipt
 (observes)      (recommends)    (enforces)
```

The ML layer and the policy engine are advisory. `PolicyEngine.decide()` returns a
`PolicyDecision`; only `PolicyEnforcementPoint.enforce()` returns an `EnforcementResult`, and it
is the only code path that writes an `ActionModel` row, issues a receipt, opens an incident or
contains a session. A model that recommends `ALLOW` cannot authorise anything, because nothing
downstream of it trusts the recommendation.

---

## 2. Action risk

Eleven actions are declared in `shared/constants/trust_model.json`
(`action_risk_profiles`); undeclared names are inferred as MEDIUM and flagged
`source: "INFERRED"` rather than guessed silently.

| Action | Risk | | Action | Risk |
| --- | --- | --- | --- | --- |
| `VIEW_DASHBOARD` | 10 | | `CHANGE_PASSWORD` | 85 |
| `VIEW_PROFILE` | 15 | | `CREATE_API_KEY` | 90 |
| `VIEW_RESOURCE` | 20 | | `DELETE_RESOURCE` | 95 |
| `CHANGE_PROFILE` | 30 | | `CHANGE_SECURITY_SETTINGS` | 95 |
| `EXPORT_DATA` | 60 | | `MODIFY_ACCESS_POLICY` | 97 |
| | | | `CREATE_ADMIN` | 98 |

Context escalations, all configurable and all recorded as named adjustments:

- `amount` ≥ 25 000 → 80; ≥ 100 000 → 98 (`AMOUNT_ESCALATION`)
- `privileged: true` → +8 (`PRIVILEGE_ESCALATION`)
- production resource or context → +6 (`PRODUCTION_RESOURCE`)

Bands: LOW < 30, MEDIUM 30–59, HIGH 60–84, CRITICAL ≥ 85.

---

## 3. Policy decisions

Eleven ordered rules, first match wins, final rule must be a catch-all. The engine refuses to
construct with an empty rule list (`ValueError`) rather than defaulting to allow.

| # | Rule | Decision | Requires |
| --- | --- | --- | --- |
| 1 | `SESSION_NOT_ACTIVE` | BLOCK | session not active |
| 2 | `SESSION_CONTAINED` | BLOCK | contained |
| 3 | `TERMINAL_TRUST_STATE` | BLOCK | trust state terminal |
| 4 | `TCI_FLOOR_EXCEEDED` | BLOCK | TCI ≤ 45 **and** risk ≥ 30 |
| 5 | `CRITICAL_STATE_HIGH_RISK` | BLOCK | CRITICAL, risk ≥ 60 |
| 6 | `CRITICAL_STATE_MEDIUM_RISK` | STEP_UP | CRITICAL, risk ≥ 30 |
| 7 | `SUSPICIOUS_STATE_HIGH_RISK` | STEP_UP | SUSPICIOUS, risk ≥ 60 |
| 8 | `SUSPICIOUS_STATE_MEDIUM_RISK` | STEP_UP | SUSPICIOUS, risk ≥ 30 |
| 9 | `DEGRADED_STATE_CRITICAL_RISK` | STEP_UP | DEGRADED, risk ≥ 85 |
| 10 | `HEALTHY_STATE_VERY_HIGH_RISK` | STEP_UP | TRUSTED/DEGRADED, risk ≥ 95 |
| 11 | `DEFAULT_ALLOW` | ALLOW | catch-all |

A hard `TCI_FLOOR_GUARD` runs **before** rule evaluation and emits the warning
`TCI_BELOW_AUTHORIZATION_FLOOR`, so a misconfigured rule set cannot authorise below the floor.

**Unknown predicates never match.** `_test_predicate` returns
`(False, "unknown predicate ...")` for a name it does not recognise, and the skip is recorded in
`considered`. A typo in a rule cannot silently weaken enforcement.

---

## 4. Step-up

TRUSTPULSE does not own MFA — the integrating application or its IdP does. What TRUSTPULSE owns
is the **requirement** and the **record of the outcome**. A challenge is therefore a descriptor,
not an authentication.

Configured: methods `[MFA]`, TTL 300 s, max 3 attempts, `failure_tci_penalty` 15,
`block_on_failure_min_risk` 60, `contain_on_failure_min_risk` 85.

A failed step-up on an action at or above risk 85 triggers containment immediately; at or above
60 the action is blocked.

---

## 5. Trust Receipts

Every terminal decision issues a receipt bound to user + device + session + action + resource +
nonce, with a short expiry (TTL 90 s, hard maximum 900 s).

`receipt_id = "trc_" + sha256(canonical_json({session_id, action, resource, nonce}))[:32]`

Verification recomputes the hash over the canonical payload and checks: hash integrity, expiry,
binding against presented values, revocation, and single use. Nonces are unique per
`(tenant, nonce)` at the database level, not just in application code.

`evidence_hash` folds only `type`, `severity` (4dp), `description` and `source`, sorted by
`(type, description)` — so it is stable under list reordering and independent of when an
observation was recorded.

---

## 6. Containment

Configured actions: `REVOKE_SESSION`, `INVALIDATE_TOKEN`, `FLAG_DEVICE`, `OPEN_INCIDENT`,
`SERVE_DECEPTION`. Auto-containment fires on `BLOCKED` for actions of risk ≥ 85.

The deception response is **always labelled** (`DECEPTION_SANDBOX`) and the label is returned to
the operator. TRUSTPULSE does not serve an undisclosed deception.

---

## 7. Verification

```
pytest -q            → 299 passed in 45.21s
ruff check app tests scripts ../ml ../demo  → All checks passed
frontend: tsc --noEmit --strict shared/schemas/trust.ts → exit 0
```

Per module:

| Module | Tests |
| --- | --- |
| `test_policy_engine.py` | 68 |
| `test_enforcement_flow.py` | 39 |
| `test_trust_model.py` | 36 |
| `test_ml_core.py` | 34 |
| `test_platform_flow.py` | 26 |
| `test_shared_contract.py` | 22 |
| `test_api.py` | 21 |
| `test_action_risk_catalogue.py` | 15 |
| `test_security.py` | 13 |
| `test_behavioral_engines.py` | 9 |
| `test_action_risk.py` | 7 |
| `test_failure_modes.py` | 5 |
| `test_multi_tenancy.py` | 4 |

**No new database migration was required.** Phase 1's schema (migration `0002`) already covered
`actions`, `trust_receipts`, `proof_records`, `platform_incidents` and `security_events`. Verified
by running `alembic upgrade head` against a fresh database and diffing every model table and
column against `sqlite_master` / `PRAGMA table_info`: 0 missing tables, 0 missing columns across
`actions` (20), `trust_receipts` (28), `platform_incidents` (17), `security_events` (13) and
`sessions` (39).

### Live attack demo

`demo/run_attack_demo.py` drives the whole loop over real HTTP against a running API. Measured
output from a fresh database:

```
[1] login                TCI 87.3  TRUSTED   (alice.chen, PASSWORD_MFA)
[2] VIEW_DASHBOARD       risk 10   → ALLOW   rule=DEFAULT_ALLOW
[3] takeover, 8 samples  anomaly 0.600  TCI 86 → 69 → … → 54.8  SUSPICIOUS
[4] CREATE_API_KEY       risk 90   → STEP_UP rule=SUSPICIOUS_STATE_HIGH_RISK
[5] step-up fails        TCI 54.8 → 51.6  (-3.19 observed, 15 configured)
                         containment: REVOKE_SESSION, INVALIDATE_TOKEN, FLAG_DEVICE,
                                      OPEN_INCIDENT, SERVE_DECEPTION
[6] VIEW_DASHBOARD       risk 10   → BLOCK   rule=SESSION_NOT_ACTIVE
[7] operator containment trust_state=CONTAINED  device flagged
[8] receipts             verify valid=True; replay valid=False RECEIPT_ALREADY_USED
[9] forged binding       valid=False BINDING_MISMATCH:session_id
[10] incident            [HIGH] Session contained: CREATE_API_KEY blocked at TCI 51.6
[11] posture             score 57.5  grade POOR
```

The attacker authenticated successfully and was still stopped.

---

## 8. Bugs found and fixed while verifying Phase 2

Each of these was caught by running the code, not by reading it.

1. **Every receipt failed verification after a database round trip.** `receipt_payload` hashed
   `issued_at.isoformat()`. An in-memory datetime is timezone-aware
   (`2026-09-06T07:02:50.289973+00:00`); the same instant read back from SQLite is naive
   (`2026-09-06T07:02:50.289973`). Different bytes, different digest. Fixed with
   `canonical_timestamp()`, which normalises to UTC, drops the offset and truncates microseconds.

2. **A step-up challenge could be replayed.** `extra = dict(session.extra or {})` is a *shallow*
   copy, so mutating a nested challenge also mutated what SQLAlchemy had already loaded. The
   flush then compared old against new, found them equal, and emitted no UPDATE — the challenge
   stayed `PENDING` forever. Seven call sites had the same latent bug. Fixed with `read_extra()`
   (deep copy) and `write_extra()` (explicit `flag_modified`).

3. **The step-up TCI penalty never landed.** `_apply_tci_penalty` set `session.tci` and the
   `evaluate()` call immediately after it overwrote the value from the fused factors. Meanwhile
   both the session-context factor and the history factor already penalise
   `session.step_up_failures` — a column the PEP never wrote. Fixed by incrementing the column and
   flushing *before* evaluation, and deleting the no-op. The session factor's penalty is now
   configurable (`session_context.step_up_failure_penalty` = 15, `_max` = 30) instead of
   hard-coded.

4. **Incidents named a placeholder, not the action.** The challenge descriptor never stored the
   action name, so containment always logged `STEP_UP_TARGET`. A SOC analyst reading that learns
   nothing. Fixed by threading the real action through `_build_step_up_challenge`; a regression
   test asserts the incident title contains `CREATE_ADMIN` and not the placeholder.

5. **The response reported a penalty that had not been applied.** `tci_penalty_applied: 15`
   echoed the configured value while the real drop was 3.19. The response now carries
   `tci_before`, `tci_penalty_applied` (measured) and `tci_penalty_configured` (intent) as three
   distinct fields, all derived from one rounded TCI so they cannot disagree.

6. **The demo silently tested nothing.** `personas.get("attacker_profile", {}).get("behavior")`
   missed — the attacker features sit at the top level next to a `description` string — so it fell
   back to the *victim's own* persona and reported anomaly 0.027 instead of 0.600. Both demo
   scripts now raise rather than fall back.

7. **The TypeScript mirror advertised predicates the engine ignores.** `trust.ts` offered
   `tci_below`, `tci_at_least`, `is_contained`, `session_status_in` and `risk_band_in`; the engine
   dispatches on `max_tci`, `min_tci`, `contained`, `session_status`, `session_status_not`. It
   also advertised `PENDING` as a decision and `CLOSED` as an incident status, neither of which
   exists. All were corrected and a contract test now diffs the mirror against the engine's
   actual dispatch table — verified to fail when the mirror is deliberately broken.

---

## 9. Honest limitations

- Step-up is **simulated**. The challenge descriptor is real; the authentication is not performed.
  An integrating application must wire its own MFA and report the outcome back.
- Action risk is a **configured catalogue**, not a learned model. It is auditable and
  deterministic, which is the point, but it will not discover a risky action nobody declared.
- Posture scoring is a weighted composite of four components. It is an operational signal for
  triage, not a measure of security.
- Receipts are hash-bound and single-use, but **not yet anchored**. Merkle aggregation and
  blockchain anchoring are Phase 3.
- The Docker, PostgreSQL and Redis paths are written but **not verified in this environment** —
  no `docker`, `psql` or `redis-server` binary is available. Everything above ran on SQLite with
  the in-memory Redis fallback.
