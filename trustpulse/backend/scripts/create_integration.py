"""
Create a customer integration credential.

Usage:
    python scripts/create_integration.py --tenant acme-bank --name "Acme Bank Web"

The API key is printed ONCE. Only its SHA-256 hash is stored server-side.
"""

import argparse
import asyncio
import secrets

from sqlalchemy import select

from app.core.logging import setup_logging
from app.core.security import SecurityUtils
from app.models.base import async_session_factory
from app.models.integration_client import IntegrationClientModel
from app.repositories.integrations import IntegrationRepository

setup_logging()


async def main(tenant: str, name: str):
    api_key = "tp_" + secrets.token_urlsafe(32)
    public_key = "pk_" + secrets.token_urlsafe(16)[:40]
    hint = api_key[-4:]

    async with async_session_factory() as db:
        repo = IntegrationRepository(db, tenant)
        existing = await db.execute(
            select(IntegrationClientModel).where(
                IntegrationClientModel.customer_tenant_id == tenant
            )
        )
        if existing.scalars().first():
            print(
                f"Tenant '{tenant}' already has at least one integration. Add a new one if needed."
            )

        await repo.create_credential(
            tenant_id=tenant,
            public_key=public_key,
            api_key_hash=SecurityUtils.hash_api_key(api_key),
            api_key_hint=hint,
            name=name,
        )
        await db.commit()

    print("\n=== TrustPulse integration created ===")
    print(f"tenant:      {tenant}")
    print(f"public_key:  {public_key}")
    print(f"api_key:     {api_key}")
    print(f"api_key_hint:{hint}")
    print("\nStore the API key securely. It will NOT be shown again.")
    print("Browser SDK uses public_key; customer backend uses Authorization: Bearer <api_key>.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a TrustPulse integration credential.")
    parser.add_argument("--tenant", required=True, help="Customer tenant identifier")
    parser.add_argument("--name", default="Default", help="Integration display name")
    args = parser.parse_args()
    asyncio.run(main(args.tenant, args.name))
