"""Tenant-scoped request context.

This dataclass lives in ``app.core`` rather than ``app.api`` on purpose: services
need it as a type, and importing it from ``app.api`` would re-enter
``app/api/__init__.py`` (which eagerly imports the routers, which import the
services) and create a circular import.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set


@dataclass
class IntegrationContext:
    """Who is calling, and which tenant they are scoped to."""

    tenant_id: str
    actor_type: str  # "API_CLIENT" | "BROWSER_SDK" | "DEVELOPMENT"
    actor_id: str
    public_key: Optional[str] = None
    integration_name: Optional[str] = None
    api_key_hint: Optional[str] = None
    scopes: Set[str] = field(default_factory=lambda: {"read", "write", "telemetry", "risk"})

    def to_audit_metadata(self) -> Dict[str, Any]:
        return {
            "integration_name": self.integration_name,
            "public_key_hint": (self.public_key or "")[:8] or None,
            "api_key_hint": self.api_key_hint,
            "scopes": sorted(self.scopes),
        }


__all__ = ["IntegrationContext"]
