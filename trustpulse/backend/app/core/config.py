"""
TrustPulse AI — Backend Configuration & Settings.

All secrets MUST come from the environment (or an injected secrets manager).
No secret values are stored in source code.
"""

from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "TrustPulse AI Security Backend"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # ------------------------------------------------------------------ Database
    # PostgreSQL in production; SQLite (aiosqlite) is supported for local dev/tests.
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./trustpulse.db",
        description="Async database URL. Use postgresql+asyncpg://... in production.",
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    # When enabled, the backend refuses to run against sqlite. Use for deploy checks.
    REQUIRE_POSTGRES: bool = False

    # ------------------------------------------------------------------ Redis
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL. Authentication is supported through the URL credentials.",
    )
    REDIS_SOCKET_TIMEOUT_SECONDS: float = 1.0
    REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS: float = 1.0
    REDIS_REPLAY_TTL_SECONDS: int = 86400
    REDIS_SESSION_TTL_SECONDS: int = 3600
    REDIS_QUEUE_TTL_SECONDS: int = 600
    REDIS_QUEUE_REPEAT_MS: int = 100
    REDIS_DECISION_STATE_TTL_SECONDS: int = 120

    # ------------------------------------------------------------------ Security
    API_KEY_HEADER: str = "X-TrustPulse-API-Key"
    PUBLIC_KEY_HEADER: str = "X-TrustPulse-Public-Key"
    SESSION_ID_HEADER: str = "X-TrustPulse-Session-Id"
    SDK_VERSION_HEADER: str = "X-TrustPulse-SDK-Version"
    TENANT_ID_HEADER: str = "X-TrustPulse-Tenant-Id"

    MAX_CLOCK_SKEW_SECONDS: int = 300
    MAX_PAYLOAD_BYTES: int = 1_048_576
    MAX_BATCH_PACKETS: int = 50
    MAX_PACKET_FEATURES_BYTES: int = 48_000

    # ------------------------------------------------------------------ Telemetry limits
    RATE_LIMIT_TELEMETRY_PER_MINUTE: int = 120
    RATE_LIMIT_TELEMETRY_PER_SESSION_PER_MINUTE: int = 60
    RATE_LIMIT_RISK_PER_MINUTE: int = 240

    # ------------------------------------------------------------------ Policy / confidence
    TELEMETRY_SCHEMA_VERSION: str = "1.0.0"
    SDK_VERSION: str = "1.0.0"
    COLD_START_CONFIDENCE: int = 30
    HIGH_CONFIDENCE_THRESHOLD: int = 80
    MODERATE_CONFIDENCE_THRESHOLD: int = 60
    GUARDED_CONFIDENCE_THRESHOLD: int = 30
    LOW_CONFIDENCE_MAX: int = 30
    POLICY_VERSION: str = "v1"
    BASELINE_PROMOTE_MIN_CONFIDENCE: int = 80
    MIN_TRUSTED_OBSERVATIONS: int = 5
    HYSTERESIS_COOLDOWN_SECONDS: int = 60
    HYSTERESIS_ESCALATION_COOLDOWN_SECONDS: int = 15
    MIN_CONFIDENCE_DURATION_SECONDS: int = 30

    # Fail-safe. Never silently convert an unavailable security component into ALLOW
    # for a sensitive action.
    FAILSAFE_DECISION_UNKNOWN: str = "STEP_UP"
    FAILSAFE_DECISION_CRITICAL: str = "BLOCK"

    # ------------------------------------------------------------------ Auth
    # Development/test convenience only. Production MUST set this to False.
    ALLOW_DEVELOPMENT_AUTH_FALLBACK: bool = True
    AUTH_TOKEN_TTL_SECONDS: int = 0  # unused; API keys are long-lived server-side credentials

    # ------------------------------------------------------------------ Processing
    TELEMETRY_ASYNC_PROCESSING: bool = False
    TELEMETRY_QUEUE_MAX_SIZE: int = 10_000

    # ------------------------------------------------------------------ Metrics
    METRICS_ENABLED: bool = True

    # ------------------------------------------------------------------ HTTP
    BACKEND_CORS_ORIGINS: List[str] = ["*"]
    TRUSTED_HOSTS: List[str] = ["*"]
    HTTPS_REDIRECT: bool = False
    SECURE_HEADERS: bool = True
    USE_FORWARDED_PROTO: bool = True

    # ------------------------------------------------------------------ Logging
    LOG_LEVEL: str = "INFO"


settings = Settings()
