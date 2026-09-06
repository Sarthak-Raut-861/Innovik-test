# Innovik-test

This repository contains **TRUSTPULSE AI — Evidence-Centric Continuous Digital Trust Platform**.

> Authenticate once. Trust continuously. Authorize every sensitive action. Prove why.

**All documentation and code live under [`trustpulse/`](trustpulse/).**

→ **[Read the main README](trustpulse/README.md)** — quick start, architecture, trust model,
privacy rules, verification.

| Document | Contents |
|---|---|
| [`trustpulse/README.md`](trustpulse/README.md) | Overview, quick start, repository layout, limitations |
| [`trustpulse/docs/ARCHITECTURE.md`](trustpulse/docs/ARCHITECTURE.md) | Layering, trust computation, baselines, privacy, deployment |
| [`trustpulse/docs/API_REFERENCE.md`](trustpulse/docs/API_REFERENCE.md) | Endpoints, request/response shapes, shared contracts |
| [`trustpulse/docs/SECURITY_MODEL.md`](trustpulse/docs/SECURITY_MODEL.md) | Security posture and enforcement rules |
| [`trustpulse/docs/PHASE1_REPORT.md`](trustpulse/docs/PHASE1_REPORT.md) | What Phase 1 delivered, with verification evidence |

## Phase status

| Phase | Scope | Status |
|---|---|---|
| **1** | Shared trust model, ML core, data model, trust engine, SOC dashboard, SDK, demo data | ✅ complete |
| **2** | Action risk, policy engine, PEP enforcement, step-up, revocation, containment, incidents, Trust Receipts | ⏳ next |
| **3** | Receipt proofs, Merkle anchoring, verification UI, WebSockets, TrustDev integration, attack demo | ⏳ planned |

## Fastest path to a running system

```bash
cd trustpulse
cp .env.example .env        # then change the passwords
docker compose up --build
docker compose run --rm --profile tools seed
```

- SOC dashboard: http://localhost:5173
- API docs: http://localhost:8000/docs

Without Docker (Python 3.11+, Node 20+), see the
[no-Docker instructions](trustpulse/README.md#without-docker-needs-python-311-and-node-20).

Note: [`trustpulse/docs/PHASE2_REPORT.md`](trustpulse/docs/PHASE2_REPORT.md) predates the current
phase plan and uses different numbering. The table above governs.
