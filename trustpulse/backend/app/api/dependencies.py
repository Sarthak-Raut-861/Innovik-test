"""
TrustPulse AI — API Dependencies.

Provides authenticated, tenant-scoped integration context.

Security model:
  * Browser SDK telemetry identifies the customer integration via a NON-SECRET
    public key and binds to the session created server-side.
  * Customer application API calls authenticate with a server-side API key.
  * Tenant isolation is enforced from the credential-derived tenant_id; a caller
    cannot override it with a tenant header unless the header matches.

Development fallback (tenant header only) is enabled by default for local
testing but MUST be disabled in production.
"""

from typing import Optional

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.context import IntegrationContext  # re-exported for compatibility
from app.core.exceptions import AuthenticationException, TenantMismatchException
from app.core.security import SecurityUtils
from app.models.base import get_db_session
from app.repositories.integrations import IntegrationRepository

__all__ = ["IntegrationContext", "get_integration_context"]


def _extract_bearer_key(request: Request) -> Optional[str]:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    header_key = request.headers.get(settings.API_KEY_HEADER)
    if header_key:
        return header_key.strip()
    return None


async def get_integration_context(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> IntegrationContext:
    """Authenticates the caller and returns a tenant-scoped integration context."""
    public_key = request.headers.get(settings.PUBLIC_KEY_HEADER)
    api_key = _extract_bearer_key(request)
    tenant_header = request.headers.get(settings.TENANT_ID_HEADER)

    repo = IntegrationRepository(db)

    if public_key:
        integrity = await repo.get_by_public_key(public_key)
        if not integrity or integrity.status != "ACTIVE":
            raise AuthenticationException("Invalid or disabled public integration key")
        if tenant_header and tenant_header != integrity.customer_tenant_id:
            raise TenantMismatchException()
        return IntegrationContext(
            tenant_id=integrity.customer_tenant_id,
            actor_type="BROWSER_SDK",
            actor_id=integrity.id,
            public_key=integrity.public_key,
            integration_name=integrity.name,
            api_key_hint=integrity.api_key_hint,
            scopes={"telemetry", "read"},
        )

    if api_key:
        api_key_hash = SecurityUtils.hash_api_key(api_key)
        integrity = await repo.get_by_api_key_hash(api_key_hash)
        if not integrity or integrity.status != "ACTIVE":
            raise AuthenticationException("Invalid API key")
        if tenant_header and tenant_header != integrity.customer_tenant_id:
            raise TenantMismatchException()
        return IntegrationContext(
            tenant_id=integrity.customer_tenant_id,
            actor_type="API_CLIENT",
            actor_id=integrity.id,
            public_key=integrity.public_key,
            integration_name=integrity.name,
            api_key_hint=integrity.api_key_hint,
            scopes={"read", "write", "telemetry", "risk"},
        )

    if tenant_header and settings.ALLOW_DEVELOPMENT_AUTH_FALLBACK:
        return IntegrationContext(
            tenant_id=tenant_header,
            actor_type="DEVELOPMENT",
            actor_id="development-fallback",
            public_key=None,
            integration_name="development-fallback",
            api_key_hint="dev",
            scopes={"read", "write", "telemetry", "risk"},
        )

    raise AuthenticationException()
