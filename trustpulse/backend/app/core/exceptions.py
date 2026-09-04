"""
TrustPulse AI — Domain Exceptions.

These exceptions map to stable, documented HTTP error codes in the API.
Secrets must never be placed inside exception messages.
"""

from typing import Any, Dict, List, Optional


class TrustPulseException(Exception):
    """Base exception for all TrustPulse backend errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class AuthenticationException(TrustPulseException):
    """Raised when customer integration credentials are missing or invalid."""

    def __init__(
        self, message: str = "Authentication required: valid integration credential missing"
    ):
        super().__init__(message=message, status_code=401)


class PermissionDeniedException(TrustPulseException):
    """Raised when an authenticated principal is not permitted to perform an operation."""

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message=message, status_code=403)


class TenantMismatchException(TrustPulseException):
    """Raised when cross-tenant access violation is detected."""

    def __init__(self, message: str = "Access denied: cross-tenant operation prohibited"):
        super().__init__(message=message, status_code=403)


class SessionNotFoundException(TrustPulseException):
    """Raised when a referenced session ID does not exist for this tenant."""

    def __init__(self, session_id: str):
        super().__init__(message=f"Session '{session_id}' not found", status_code=404)


class SessionTerminalStateException(TrustPulseException):
    """Raised when an operation targets a session in a terminal state."""

    def __init__(self, session_id: str, state: str):
        super().__init__(
            message=f"Session '{session_id}' is in terminal state '{state}'",
            status_code=409,
            details={"session_id": session_id, "state": state},
        )


class ReplayDetectedException(TrustPulseException):
    """Raised when an event ID has already been processed."""

    def __init__(self, message: str = "Replay detected: duplicate event identifier"):
        super().__init__(message=message, status_code=409)


class SequenceRegressionException(TrustPulseException):
    """Raised when an incoming packet has an impossible sequence number."""

    def __init__(self, last_seq: int, received_seq: int):
        super().__init__(
            message=f"Sequence regression: received {received_seq} but expected > {last_seq}",
            status_code=400,
            details={"last_sequence": last_seq, "received_sequence": received_seq},
        )


class StaleTimestampException(TrustPulseException):
    """Raised when client timestamp differs excessively from server time."""

    def __init__(self, delta_seconds: float, max_skew: int):
        message = (
            f"Stale telemetry packet: timestamp delta ({delta_seconds:.1f}s) "
            f"exceeds threshold ({max_skew}s)"
        )
        super().__init__(
            message=message,
            status_code=400,
            details={
                "timestamp_delta_seconds": round(delta_seconds, 3),
                "max_skew_seconds": max_skew,
            },
        )


class TelemetryValidationException(TrustPulseException):
    """Raised when a feature payload is malformed, out-of-range, or contains NaN/Inf."""

    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message=message, status_code=422, details={"errors": errors or []})


class RateLimitExceededException(TrustPulseException):
    """Raised when tenant/session exceeds configured request quota."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        scope: str = "request",
        retry_after: int = 60,
    ):
        super().__init__(
            message=message,
            status_code=429,
            details={"scope": scope, "retry_after_seconds": retry_after},
        )


class SecurityServiceUnavailableException(TrustPulseException):
    """Raised when a required security infrastructure dependency is unavailable.

    This is deliberately surfaced as a failure rather than silently becoming ALLOW.
    """

    def __init__(self, component: str, message: Optional[str] = None):
        super().__init__(
            message=message or f"Security infrastructure unavailable: {component}",
            status_code=503,
            details={"component": component},
        )


class PolicyError(TrustPulseException):
    """Raised when a configured policy is invalid or inconsistent."""

    def __init__(self, message: str):
        super().__init__(message=message, status_code=500)
