"""TRUSTPULSE — Demo seed service.

Creates the TrustDev demo tenant: integration credential, users (digest only,
never passwords), devices and per-user Trusted Core baselines built from the
derived personas in ``demo/seed_data/personas.json``.

Everything is idempotent: running the seed twice does not duplicate rows, so the
demo can be reset by re-running one command.
"""

from __future__ import annotations

import json
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from trustpulse_ml.baseline.trusted_core import Baseline, TrustedCore
from trustpulse_ml.feature_extraction.features import extract_feature_vector, transform

from app.core.credentials import hash_credential
from app.core.logging import logger
from app.core.security import SecurityUtils
from app.models.device import DeviceModel
from app.models.integration_client import IntegrationClientModel
from app.models.user import UserModel
from app.repositories.integrations import IntegrationRepository
from app.repositories.platform import PlatformRepository

DEFAULT_PERSONAS_PATH = Path(__file__).resolve().parents[4] / "demo" / "seed_data" / "personas.json"
DEFAULT_TENANT_ID = "trustdev-demo"
DEFAULT_PUBLIC_KEY = "pk_trustdev_demo_0001"
DEFAULT_API_KEY = "tp_demo_trustpulse_key_0001"
RANDOM_SEED = 20260906


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _jitter(
    features: Dict[str, Any], rng: np.random.Generator, noise: float = 0.04
) -> Dict[str, Any]:
    """Perturbs a persona slightly so consecutive observations are not identical."""
    out: Dict[str, Any] = {}
    for group, values in features.items():
        if not isinstance(values, dict):
            continue
        out[group] = {}
        for key, value in values.items():
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                factor = 1.0 + float(rng.normal(0.0, noise))
                out[group][key] = max(0.0, float(value) * max(0.2, factor))
            else:
                out[group][key] = value
    return out


class SeedService:
    def __init__(
        self,
        db: AsyncSession,
        tenant_id: str = DEFAULT_TENANT_ID,
        personas_path: Optional[Path] = None,
    ) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.repo = PlatformRepository(db, tenant_id)
        path = personas_path or Path(os.environ.get("DEMO_PERSONAS_PATH", DEFAULT_PERSONAS_PATH))
        self.personas_path = path
        self.data = json.loads(path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------ runner
    async def run(
        self,
        *,
        api_key: str = DEFAULT_API_KEY,
        public_key: str = DEFAULT_PUBLIC_KEY,
        baseline_observations: int = 24,
    ) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            "tenant_id": self.tenant_id,
            "public_key": public_key,
            "api_key_hint": api_key[-4:],
            "users": [],
            "devices": [],
            "baselines": [],
        }

        await self._ensure_integration(api_key=api_key, public_key=public_key)

        for entry in self.data.get("users", []):
            user = await self._ensure_user(entry)
            device = await self._ensure_device(entry["device"], user.id)
            observations = await self._ensure_baseline(
                user=user,
                device=device,
                persona=self.data["personas"][entry["username"]],
                count=baseline_observations,
            )
            summary["users"].append(
                {
                    "external_user_id": user.external_user_id,
                    "username": user.username,
                    "role": user.role,
                }
            )
            summary["devices"].append(
                {
                    "fingerprint": device.device_fingerprint,
                    "trust_level": device.trust_level,
                    "observations": device.observation_count,
                }
            )
            summary["baselines"].append(
                {
                    "user": user.username,
                    "core_observations": observations["core_observations"],
                    "features": observations["features"],
                    "shadow_observations": observations["shadow_observations"],
                }
            )

        await self._ensure_device(self.data["attacker_device"], user_id=None)
        summary["devices"].append(
            {
                "fingerprint": self.data["attacker_device"]["fingerprint"],
                "trust_level": "NEW",
                "observations": 0,
            }
        )
        await self.db.flush()
        return summary

    # ----------------------------------------------------------------- helpers
    async def _ensure_integration(self, *, api_key: str, public_key: str) -> IntegrationClientModel:
        repo = IntegrationRepository(self.db, self.tenant_id)
        existing = await repo.get_by_public_key(public_key)
        if existing is not None:
            return existing
        model = await repo.create_credential(
            tenant_id=self.tenant_id,
            public_key=public_key,
            api_key_hash=SecurityUtils.hash_api_key(api_key),
            api_key_hint=api_key[-4:],
            name="TrustDev Demo Application",
        )
        logger.info("Seeded TrustPulse integration for tenant %s", self.tenant_id)
        return model

    async def _ensure_user(self, entry: Dict[str, Any]) -> UserModel:
        user = await self.repo.get_user_by_external_id(entry["external_user_id"])
        password = entry.get("demo_password")
        if user is None:
            digest, salt = hash_credential(password or "")
            user = UserModel(
                customer_tenant_id=self.tenant_id,
                external_user_id=entry["external_user_id"],
                username=entry["username"],
                display_name=entry.get("display_name"),
                role=entry.get("role", "MEMBER"),
                department=entry.get("department"),
                mfa_enabled=bool(entry.get("mfa_enabled", False)),
                default_auth_method=entry.get("default_auth_method", "PASSWORD"),
                credential_hash=digest,
                credential_salt=salt,
                is_active=True,
            )
            await self.repo.add_user(user)
        elif password and not user.credential_hash:
            user.credential_hash, user.credential_salt = hash_credential(password)
        return user

    async def _ensure_device(self, entry: Dict[str, Any], user_id: Optional[str]) -> DeviceModel:
        device = await self.repo.get_device_by_fingerprint(entry["fingerprint"])
        registered = bool(entry.get("registered", False))
        observations = int(entry.get("observations", 0))
        if device is None:
            device = DeviceModel(
                customer_tenant_id=self.tenant_id,
                device_fingerprint=entry["fingerprint"],
                user_id=user_id,
                label=entry.get("label"),
                platform=entry.get("platform"),
                browser=entry.get("browser"),
                os_name=entry.get("os_name"),
                screen=entry.get("screen"),
                timezone=entry.get("timezone"),
                trust_level="TRUSTED" if registered else ("KNOWN" if observations else "NEW"),
                is_registered=registered,
                observation_count=observations,
                first_seen_at=_now() - timedelta(days=45),
                last_seen_at=_now(),
            )
            await self.repo.add_device(device)
        else:
            device.user_id = device.user_id or user_id
        return device

    async def _ensure_baseline(
        self,
        *,
        user: UserModel,
        device: DeviceModel,
        persona: Dict[str, Any],
        count: int,
    ) -> Dict[str, Any]:
        rng = np.random.default_rng(RANDOM_SEED + hash(user.username) % 10_000)
        learner = TrustedCore()
        baseline = Baseline()
        for _ in range(max(1, count)):
            observation = extract_feature_vector(_jitter(persona, rng))
            baseline = learner.update(baseline, transform(observation))

        await self.repo.upsert_trusted_baseline(
            user.id,
            device.id,
            baseline.to_dict(),
            observation_count=baseline.observation_count,
            version=baseline.version,
            last_observation_at=_now(),
        )

        # A shadow that tracks the core closely: this is the normal steady state.
        shadow = Baseline()
        for _ in range(6):
            observation = extract_feature_vector(_jitter(persona, rng, noise=0.06))
            shadow = learner.update(shadow, transform(observation), alpha=0.25)
        await self.repo.upsert_shadow_baseline(
            user.id,
            device.id,
            shadow.to_dict(),
            observation_count=shadow.observation_count,
            version=shadow.version,
        )
        await self.db.flush()

        return {
            "core_observations": baseline.observation_count,
            "features": len(baseline.means),
            "shadow_observations": shadow.observation_count,
        }


async def list_existing_users(db: AsyncSession, tenant_id: str) -> List[str]:
    result = await db.execute(
        select(UserModel.username).where(UserModel.customer_tenant_id == tenant_id)
    )
    return [row[0] for row in result.all()]


__all__ = ["SeedService", "DEFAULT_TENANT_ID", "DEFAULT_PUBLIC_KEY", "DEFAULT_API_KEY"]
