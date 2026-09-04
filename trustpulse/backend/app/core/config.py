"""
TrustPulse AI - Backend Configuration & Settings
"""

from typing import List, Optional
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
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Database
    # Default to async SQLite for local/test zero-friction running, overridden by POSTGRES_URL in prod
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./trustpulse.db",
        description="Async database connection string (PostgreSQL or SQLite)",
    )

    # Redis Cache & Telemetry State
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis URL for state cache, replay prevention, and rate limits",
    )
    REDIS_REPLAY_TTL_SECONDS: int = 86400  # 24 hours
    REDIS_SESSION_TTL_SECONDS: int = 3600  # 1 hour

    # Security & Integrity
    API_KEY_HEADER: str = "X-TrustPulse-API-Key"
    PUBLIC_KEY_HEADER: str = "X-TrustPulse-Public-Key"
    SESSION_ID_HEADER: str = "X-TrustPulse-Session-Id"
    SDK_VERSION_HEADER: str = "X-TrustPulse-SDK-Version"
    TENANT_ID_HEADER: str = "X-TrustPulse-Tenant-Id"

    MAX_CLOCK_SKEW_SECONDS: int = 300  # 5 minutes
    MAX_PAYLOAD_BYTES: int = 1_048_576  # 1 MB max request size
    RATE_LIMIT_TELEMETRY_PER_MINUTE: int = 120

    # Policy & Confidence Engine
    COLD_START_CONFIDENCE: int = 40
    HIGH_CONFIDENCE_THRESHOLD: int = 80
    MODERATE_CONFIDENCE_THRESHOLD: int = 60
    GUARDED_CONFIDENCE_THRESHOLD: int = 30
    HYSTERESIS_COOLDOWN_SECONDS: int = 60

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]


settings = Settings()
