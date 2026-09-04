"""
TrustPulse AI — API Router Assembly.
"""

from fastapi import APIRouter

from app.api.routes import actions, health, incidents, risk, sessions, telemetry

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(sessions.router)
api_router.include_router(telemetry.router)
api_router.include_router(risk.router)
api_router.include_router(incidents.router)
api_router.include_router(actions.router)
