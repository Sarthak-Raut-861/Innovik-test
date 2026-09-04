"""
TrustPulse AI — Structured Security Logging.

Logs are JSON structured and recursively scrub secret-looking fields.
Security logs must NEVER contain API keys, tokens, passwords, or private keys.
"""

import json
import logging
import sys
from typing import Any, Dict

from app.core.config import settings
from app.core.security import SecurityUtils


class SecurityJsonFormatter(logging.Formatter):
    """Emits JSON logs and scrubs sensitive keys and secret-looking values."""

    FORBIDDEN_KEYS = {
        "password",
        "secret",
        "token",
        "authorization",
        "api_key",
        "api-key",
        "otp",
        "code",
        "private_key",
        "cookie",
        "session_cookie",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_entry["data"] = self._scrub(record.extra_data)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)

    def _scrub(self, data: Any) -> Any:
        if isinstance(data, dict):
            out: Dict[str, Any] = {}
            for k, v in data.items():
                key_lower = str(k).lower()
                if any(f in key_lower for f in self.FORBIDDEN_KEYS):
                    out[str(k)] = "[REDACTED]"
                elif isinstance(v, str) and SecurityUtils.looks_like_secret(v):
                    out[str(k)] = "[REDACTED]"
                else:
                    out[str(k)] = self._scrub(v)
            return out
        if isinstance(data, list):
            return [self._scrub(item) for item in data]
        return data


def setup_logging(debug: bool = False) -> None:
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    if debug:
        level = logging.DEBUG

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SecurityJsonFormatter())

    root_logger = logging.getLogger("trustpulse")
    root_logger.setLevel(level)
    root_logger.handlers = [handler]
    root_logger.propagate = False

    # Suppress uvicorn default access-log noise in security logs unless debug.
    if not debug:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


logger = logging.getLogger("trustpulse")


def log_extra(**kwargs: Any) -> None:
    """Helper to attach structured metadata to a log record."""
    logger.info("structured", extra={"extra_data": kwargs})
