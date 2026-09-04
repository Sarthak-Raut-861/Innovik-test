# TrustPulse AI

Continuous session-security platform.

- **Phase 1 — Web SDK**: `trustpulse/sdk` (`@trustpulse/sdk`)
  privacy-safe behavioral telemetry collectors, feature extraction, session
  management, replay/sequence protection, bounded queue, HTTPS transport.
- **Phase 2 — Security Backend**: `trustpulse/backend`
  tenant-scoped FastAPI backend with PostgreSQL, Redis, telemetry validation,
  behavioral baselines, session confidence, action risk, deterministic policy
  decisions, incidents, audit, and testing.

## Quick links

- Phase 2 report: [`trustpulse/docs/PHASE2_REPORT.md`](trustpulse/docs/PHASE2_REPORT.md)
- Phase 2 API docs: `/docs` when running the backend
- Phase 1 SDK docs: [`trustpulse/sdk/README.md`](trustpulse/sdk/README.md)
- Architecture: [`trustpulse/docs/ARCHITECTURE.md`](trustpulse/docs/ARCHITECTURE.md)
- Security model: [`trustpulse/docs/SECURITY_MODEL.md`](trustpulse/docs/SECURITY_MODEL.md)

## Run Phase 2 locally

```bash
cd trustpulse/backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Run Phase 2 with Docker

```bash
cd trustpulse
TRUSTPULSE_DB_PASSWORD=dev_db_pw TRUSTPULSE_REDIS_PASSWORD=dev_redis_pw \
  docker compose up --build
```
