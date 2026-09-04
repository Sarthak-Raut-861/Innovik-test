"""
TrustPulse AI - Domain Exceptions
"""

from typing import Optional, List, Dict, Any


class TrustPulseException(Exception):
    """Base exception for all TrustPulse backend errors."""

    def __init__(self, message: str, status_code: int = 400, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class TenantMismatchException(TrustPulseException):
    """Raised when cross-tenant access violation is detected."""

    def __init__(self, message: str = "Access denied: cross-tenant operation prohibited"):
        super().__init__(message=message, status_code=403)


class SessionNotFoundException(TrustPulseException):
    """Raised when a referenced session ID does not exist."""

    def __init__(self, session_id: str):
        super().__init__(message=f"Session '{session_id}' not found", status_code=404)


class ReplayDetectedException(TrustPulseException):
    """Raised when an event ID has already been processed or sequence number is invalid."""

    def __init__(self, message: str = "Replay detected: duplicate event identifier"):
        super().__init__(message=message, status_code=409)


class SequenceRegressionException(TrustPulseException):
    """Raised when an incoming packet has a sequence number lower or equal to last seen."""

    def __init__(self, last_seq: int, received_seq: int):
        super().__init__(
            message=f"Sequence regression: received {received_seq} but expected > {last_seq}",
            status_code=400,
            details={"last_sequence": last_seq, "received_sequence": received_seq},
        )


class StaleTimestampException(TrustPulseException):
    """Raised when client timestamp differs excessively from server time."""

    def __init__(self, delta_seconds: float, max_skew: int):
        super().__init__(
            message=f"Stale telemetry packet: timestamp delta ({delta_seconds:.1f}s) exceeds threshold ({max_skew}s)",
            status_code=400,
        )


class TelemetryValidationException(TrustPulseException):
    """Raised when feature payload contains invalid, out-of-bound, or NaN/Inf values."""

    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message=message, status_code=422, details={"errors": errors or []})


class RateLimitExceededException(TrustPulseException):
    """Raised when tenant or session exceeds request quota."""

    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message=message, status_code=429)
