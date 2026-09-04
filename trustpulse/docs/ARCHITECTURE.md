# TrustPulse AI — System Architecture Specification

## 1. Architectural Philosophy: Detection ≠ Decision ≠ Explanation

TrustPulse enforces an immutable tripartite architectural separation:

```text
┌──────────────────────────────┐
│          DETECTION           │  SDK Collectors & Telemetry Pipeline
│  Behavioral / Statistical /  │  Feature Extraction
│  ML anomaly identification   │  Non-authoritative Evidence
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│           DECISION           │  Server-side Deterministic Policy Engine
│  Authoritative Rules & Risk  │  ALLOW / STEP_UP / BLOCK / ISOLATE
│  Backend is the Authority    │  Zero Frontend Execution
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│         EXPLANATION          │  Optional LLM Explainability Pipeline
│  Audit trails & SecOps notes │  Audited Post-Decision Justification
│  Never affects decisions     │  Zero Decision/Enforcement Power
└──────────────────────────────┘
```

The LLM MUST NEVER authorize, block, revoke, modify policies, calculate authoritative risk, or generate primary evidence.

---

## 2. Component Layout

```text
trustpulse/
├── sdk/                 # Phase 1: Reusable client-side SDK (@trustpulse/sdk)
│   ├── src/             # TypeScript source code
│   ├── tests/           # Unit, integration, and security test suites
│   ├── dist/            # Compiled distribution bundles (ESM, CJS, d.ts)
│   └── package.json
├── backend/             # Phase 2: Ingestion gateway, behavioral engine, risk engine
├── dashboard/           # Phase 3: SecOps monitoring dashboard
├── docs/                # Architecture, security model, and API documentation
└── example/             # Real-world integration testing harness
```

---

## 3. Data Flow

1. **Authentication**: Host application authenticates user via password, passkey, or MFA.
2. **Session Initialization**: Host application initializes `@trustpulse/sdk` passing the newly established `sessionId` and customer `publicKey`.
3. **Behavioral Observation**:
   - Collectors listen to DOM events via capture-phase passive event listeners.
   - Strict privacy checks discard any interaction on sensitive elements (password, OTP, PIN, `data-trustpulse-ignore`).
4. **Local Feature Extraction**:
   - Every `telemetryIntervalMs` (default: 3000ms), the SDK extracts statistical features locally.
   - Raw keystroke arrays and coordinate trajectories are discarded immediately after aggregation.
5. **Transport**:
   - Telemetry batches are signed with an integrity checksum, sequenced monotonically, and posted to `/v1/telemetry` over HTTPS.
6. **Server Evaluation**:
   - Backend validates packet schema, sequence, and integrity.
   - Compares candidate behavioral features against user baseline models.
   - Evaluates action risk when critical transactions occur.
   - Deterministic policy engine issues authorization decision.
