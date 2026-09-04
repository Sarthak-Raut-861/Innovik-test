"""
TrustPulse AI - FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import logger
from app.core.redis import redis_manager
from app.models.base import Base, engine
from app.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")

    # Initialize database schema
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized (SQLite/PostgreSQL)")

    # Initialize Redis (with in-memory fallback)
    await redis_manager.initialize()

    yield

    # Graceful shutdown
    await redis_manager.close()
    await engine.dispose()
    logger.info("TrustPulse backend shutdown complete.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "TrustPulse AI — Continuous Session Security Platform. "
        "Production-grade behavioral telemetry analysis, session confidence scoring, "
        "and risk-based action authorization for web applications."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler for TrustPulse domain errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    from app.core.exceptions import TrustPulseException
    if isinstance(exc, TrustPulseException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message, "details": exc.details},
        )
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


# Mount all API routes under /v1
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", include_in_schema=False)
async def root():
    return {
        "product": "TrustPulse AI",
        "version": settings.VERSION,
        "docs": "/docs",
    }
