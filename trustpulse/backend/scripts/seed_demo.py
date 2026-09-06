"""Seed the TrustDev demo tenant.

Usage:
    python scripts/seed_demo.py
    python scripts/seed_demo.py --tenant trustdev-demo --api-key tp_demo_trustpulse_key_0001

Idempotent. Only credential *digests* are stored — never passwords.
"""

from __future__ import annotations

import argparse
import asyncio
import json

from app.core.logging import setup_logging
from app.models import Base
from app.models.base import async_session_factory, engine
from app.services.platform.seed_service import (
    DEFAULT_API_KEY,
    DEFAULT_PUBLIC_KEY,
    DEFAULT_TENANT_ID,
    SeedService,
)

setup_logging()


async def main(tenant: str, api_key: str, public_key: str, observations: int) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_factory() as db:
        service = SeedService(db, tenant)
        summary = await service.run(
            api_key=api_key, public_key=public_key, baseline_observations=observations
        )
        await db.commit()

    print("\n=== TRUSTPULSE demo data seeded ===")
    print(json.dumps(summary, indent=2))
    print("\nAPI key (demo only):", api_key)
    print("Public key:", public_key)
    print("Demo user password for all seeded users: TrustDemo!234")
    print("MFA code for MFA-enabled users: any 6 digits (prototype simulation)")

    await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed TRUSTPULSE demo data.")
    parser.add_argument("--tenant", default=DEFAULT_TENANT_ID)
    parser.add_argument("--api-key", default=DEFAULT_API_KEY)
    parser.add_argument("--public-key", default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--observations", type=int, default=24)
    args = parser.parse_args()
    asyncio.run(main(args.tenant, args.api_key, args.public_key, args.observations))
