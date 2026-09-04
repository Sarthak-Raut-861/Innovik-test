"""
TrustPulse AI - Structured Logging Configuration
"""

import logging
import json
import sys
from typing import Any, Dict


class SecurityJsonFormatter(logging.Formatter):
    """
    Emits JSON logs and automatically scrubs sensitive keys (passwords, tokens, keys).
    """

    FORBIDDEN_KEYS = {"password", "secret", "token", "authorization", "api_key", "otp", "code", "private_key"}

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

        return json.dumps(log_entry)

    def _scrub(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                k: "[REDACTED]" if any(f in k.lower() for f in self.FORBIDDEN_KEYS) else self._scrub(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self._scrub(item) for item in data]
        return data


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SecurityJsonFormatter())

    root_logger = logging.getLogger("trustpulse")
    root_logger.setLevel(level)
    root_logger.handlers = [handler]
    root_logger.propagate = False


logger = logging.getLogger("trustpulse")
