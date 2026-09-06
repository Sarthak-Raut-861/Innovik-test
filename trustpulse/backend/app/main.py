"""
TrustPulse AI — FastAPI Application Entry Point.
"""

import time
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from trustpulse_ml.feature_extraction.features import RawDataRejectedError

from app.api import api_router
from app.api.routes import platform_authorization, platform_soc, platform_trust
from app.core.config import settings
from app.core.exceptions import TrustPulseException
from app.core.logging import logger, setup_logging
from app.core.metrics import metrics
from app.core.redis import redis_manager
from app.models.base import Base, engine
from app.workers.telemetry_worker import TelemetryWorker

setup_logging(settings.DEBUG)

_telemetry_worker = TelemetryWorker()

_STARTED_AT = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")

    # For local development convenience we create tables. Production deployments should
    # apply Alembic migrations instead; create_all is idempotent and does not mutate data.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Redis is best-effort; failure falls back to in-memory state with reduced guarantees.
    await redis_manager.initialize()

    if settings.TELEMETRY_ASYNC_PROCESSING:
        await _telemetry_worker.start()

    yield

    await _telemetry_worker.stop()
    await redis_manager.close()
    await engine.dispose()
    logger.info("TrustPulse backend shutdown complete.")


async def secure_headers_middleware(request: Request, call_next):
    """Adds hardening headers to every response."""
    response = await call_next(request)
    if settings.SECURE_HEADERS:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Cache-Control", "no-store")
    return response


async def request_size_middleware(request: Request, call_next):
    """Rejects oversized requests before parsing bodies."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_PAYLOAD_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Payload too large", "max_bytes": settings.MAX_PAYLOAD_BYTES},
                )
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "Invalid content-length header"})
    response = await call_next(request)
    return response


async def metrics_middleware(request: Request, call_next):
    """Records basic request metrics."""
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    metrics.incr("http_requests", 1)
    metrics.set_gauge("http_last_latency_ms", elapsed_ms)
    if response.status_code >= 500:
        metrics.incr("http_errors", 1)
    response.headers.setdefault("X-Request-Time-Ms", str(elapsed_ms))
    return response


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "TrustPulse AI — Continuous Session Security Platform. "
        "Receives SDK telemetry, maintains behavioral baselines, calculates "
        "session confidence and action risk, and produces deterministic "
        "security decisions (ALLOW / STEP_UP / BLOCK / ISOLATE)."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)
app.middleware("http")(secure_headers_middleware)
app.middleware("http")(request_size_middleware)
app.middleware("http")(metrics_middleware)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Do not echo raw inputs; they can contain NaN/Infinity that is not safe to
    # serialize back in a JSON response.
    return JSONResponse(
        status_code=422,
        content={
            "error": "Request validation failed",
            "details": [
                {"loc": list(err.get("loc", [])), "msg": str(err.get("msg", ""))}
                for err in exc.errors()
            ],
        },
    )


@app.exception_handler(TrustPulseException)
async def trustpulse_exception_handler(request: Request, exc: TrustPulseException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "details": exc.details},
    )


@app.exception_handler(RawDataRejectedError)
async def raw_data_rejected_handler(request: Request, exc: RawDataRejectedError):
    """Privacy guard: telemetry carrying raw data is rejected, never stored."""
    logger.warning("Rejected telemetry containing raw data: %s", exc)
    metrics.incr("telemetry_raw_data_rejected")
    return JSONResponse(
        status_code=422,
        content={
            "error": "Raw behavioral data is not accepted",
            "details": {
                "reason": str(exc),
                "policy": "TRUSTPULSE only accepts derived aggregate features.",
            },
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )


app.include_router(api_router, prefix=settings.API_V1_STR)

# TRUSTPULSE platform API (sessions, telemetry, trust, SOC). Kept on its own
# prefix so the SDK-facing /v1 contract is unaffected.
platform_router = APIRouter()
platform_router.include_router(platform_trust.router)
platform_router.include_router(platform_soc.router)
platform_router.include_router(platform_authorization.router)
app.include_router(platform_router, prefix=settings.PLATFORM_API_PREFIX)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {}).update(
        {
            "TrustPulseApiKey": {
                "type": "apiKey",
                "in": "header",
                "name": settings.API_KEY_HEADER,
                "description": "Server-side customer API key for application-to-TrustPulse calls.",
            },
            "TrustPulseBearer": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "API key",
                "description": (
                    "Alternative: Authorization: Bearer <api_key> for server-side calls."
                ),
            },
            "TrustPulsePublicKey": {
                "type": "apiKey",
                "in": "header",
                "name": settings.PUBLIC_KEY_HEADER,
                "description": (
                    "Non-secret SDK public key used by the browser SDK for telemetry "
                    "identification; never used alone for authorization."
                ),
            },
            "TrustPulseTenantHeader": {
                "type": "apiKey",
                "in": "header",
                "name": settings.TENANT_ID_HEADER,
                "description": "Development-only fallback tenant header. Disable in production.",
            },
        }
    )
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi  # type: ignore[method-assign]


@app.get("/", include_in_schema=False)
async def root():
    return {
        "product": "TrustPulse AI",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health",
        "ready": f"{settings.API_V1_STR}/health/ready",
    }
