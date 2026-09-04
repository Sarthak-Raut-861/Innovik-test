"""
TrustPulse AI — Behavioral Profile Repository.
"""

from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import utc_now
from app.models.behavioral_profile import BehavioralProfileModel
from app.repositories.base import BaseRepository


class ProfileRepository(BaseRepository[BehavioralProfileModel]):
    def __init__(self, session: AsyncSession, tenant_id: str):
        super().__init__(BehavioralProfileModel, session, tenant_id)

    async def get_by_subject_device(
        self, subject_id: str, device_id: Optional[str] = None
    ) -> Optional[BehavioralProfileModel]:
        stmt = select(BehavioralProfileModel).where(
            BehavioralProfileModel.customer_tenant_id == self.tenant_id,
            BehavioralProfileModel.subject_id == subject_id,
            BehavioralProfileModel.device_id == device_id,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_or_create(
        self, subject_id: str, device_id: Optional[str] = None, schema_version: str = "1.0.0"
    ) -> BehavioralProfileModel:
        profile = await self.get_by_subject_device(subject_id, device_id)
        if profile is None:
            profile = BehavioralProfileModel(
                customer_tenant_id=self.tenant_id,
                subject_id=subject_id,
                device_id=device_id,
                feature_schema_version=schema_version,
                trusted_baseline=None,
                trusted_baseline_previous=None,
                candidate_baseline=None,
                baseline_version=1,
                confidence=0.0,
                observation_count=0,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            self.session.add(profile)
            await self.session.flush()
        return profile

    async def update_baselines(
        self,
        profile: BehavioralProfileModel,
        trusted_baseline: Optional[Dict[str, Any]] = None,
        trusted_baseline_previous: Optional[Dict[str, Any]] = None,
        candidate_baseline: Optional[Dict[str, Any]] = None,
        confidence: Optional[float] = None,
        observation_count: Optional[int] = None,
        preserve_previous: bool = True,
    ) -> BehavioralProfileModel:
        if trusted_baseline is not None:
            if preserve_previous:
                profile.trusted_baseline_previous = profile.trusted_baseline
            profile.trusted_baseline = trusted_baseline
            profile.baseline_version += 1
        if trusted_baseline_previous is not None:
            profile.trusted_baseline_previous = trusted_baseline_previous
        if candidate_baseline is not None:
            profile.candidate_baseline = candidate_baseline
        if confidence is not None:
            profile.confidence = confidence
        if observation_count is not None:
            profile.observation_count = observation_count

        profile.updated_at = utc_now()
        await self.session.flush()
        return profile

    async def rollback_trusted_baseline(self, profile: BehavioralProfileModel) -> bool:
        """Rolls back to the previous trusted baseline if one exists."""
        if not profile.trusted_baseline_previous:
            return False
        current = profile.trusted_baseline
        profile.trusted_baseline = profile.trusted_baseline_previous
        profile.trusted_baseline_previous = current
        profile.baseline_version = max(1, profile.baseline_version - 1)
        profile.updated_at = utc_now()
        await self.session.flush()
        return True
