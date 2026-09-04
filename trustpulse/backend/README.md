# TrustPulse AI — Security Backend (Phase 2)

Production-oriented, multi-tenant, reusable security backend that receives
`@trustpulse/sdk` telemetry, maintains behavioral baselines, computes evidence-based
session confidence and action risk, and produces deterministic security decisions
(`ALLOW`, `STEP_UP`, `BLOCK`, `ISOLATE`).

See `docs/PHASE2_REPORT.md` (one level up under `trustpulse/docs`) for the full
Phase 2 engineering report.

## Stack

* Python 3.12 target
* FastAPI + Pydantic v2
* SQLAlchemy 2.x async + Alembic
* PostgreSQL (authoritative) / SQLite for local tests
* Redis (temporary state, replay, rate limits, queues)
* pytest + httpx, Ruff, mypy configuration

## Quick start (local)

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Tests

```bash
. .venv/bin/activate
pytest -q
ruff check .
```
