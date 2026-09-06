"""TRUSTPULSE platform repository — data access for the trust pipeline.

All queries are tenant-scoped. A missing tenant id is a programming error, so it
is rejected loudly rather than silently widening the query.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import Select, delete, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.baselines import ShadowBaselineModel, TrustedBaselineModel
from app.models.device import DeviceModel
from app.models.observations import (
    ActionModel,
    BehaviorFeatureModel,
    SecurityEventModel,
    TrustStateModel,
)
from app.models.platform_incident import PlatformIncidentModel
from app.models.session import SessionModel
from app.models.user import UserModel


def _require_tenant(tenant_id: str) -> str:
    if not tenant_id:
        raise ValueError("tenant_id is required for every TRUSTPULSE data access")
    return tenant_id


class PlatformRepository:
    """Tenant-scoped data access for users, devices, baselines and trust history."""

    def __init__(self, db: AsyncSession, tenant_id: str) -> None:
        self.db = db
        self.tenant_id = _require_tenant(tenant_id)

    # ------------------------------------------------------------------ users
    async def get_user(self, user_id: str) -> Optional[UserModel]:
        result = await self.db.execute(
            select(UserModel).where(
                UserModel.id == user_id, UserModel.customer_tenant_id == self.tenant_id
            )
        )
        return result.scalars().first()

    async def get_user_by_external_id(self, external_user_id: str) -> Optional[UserModel]:
        result = await self.db.execute(
            select(UserModel).where(
                UserModel.customer_tenant_id == self.tenant_id,
                UserModel.external_user_id == external_user_id,
            )
        )
        return result.scalars().first()

    async def get_user_by_username(self, username: str) -> Optional[UserModel]:
        result = await self.db.execute(
            select(UserModel).where(
                UserModel.customer_tenant_id == self.tenant_id,
                UserModel.username == username,
            )
        )
        return result.scalars().first()

    async def list_users(self, limit: int = 100) -> List[UserModel]:
        result = await self.db.execute(
            select(UserModel)
            .where(UserModel.customer_tenant_id == self.tenant_id)
            .order_by(UserModel.created_at)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def add_user(self, user: UserModel) -> UserModel:
        user.customer_tenant_id = self.tenant_id
        self.db.add(user)
        await self.db.flush()
        return user

    # ---------------------------------------------------------------- devices
    async def get_device_by_fingerprint(self, fingerprint: str) -> Optional[DeviceModel]:
        result = await self.db.execute(
            select(DeviceModel).where(
                DeviceModel.customer_tenant_id == self.tenant_id,
                DeviceModel.device_fingerprint == fingerprint,
            )
        )
        return result.scalars().first()

    async def get_device(self, device_id: str) -> Optional[DeviceModel]:
        result = await self.db.execute(
            select(DeviceModel).where(
                DeviceModel.id == device_id, DeviceModel.customer_tenant_id == self.tenant_id
            )
        )
        return result.scalars().first()

    async def add_device(self, device: DeviceModel) -> DeviceModel:
        device.customer_tenant_id = self.tenant_id
        self.db.add(device)
        await self.db.flush()
        return device

    async def list_devices(self, limit: int = 100) -> List[DeviceModel]:
        result = await self.db.execute(
            select(DeviceModel)
            .where(DeviceModel.customer_tenant_id == self.tenant_id)
            .order_by(DeviceModel.last_seen_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    # --------------------------------------------------------------- sessions
    async def get_session(self, session_row_id: str) -> Optional[SessionModel]:
        result = await self.db.execute(
            select(SessionModel).where(
                SessionModel.id == session_row_id,
                SessionModel.customer_tenant_id == self.tenant_id,
            )
        )
        return result.scalars().first()

    async def get_session_by_session_id(self, session_id: str) -> Optional[SessionModel]:
        result = await self.db.execute(
            select(SessionModel).where(
                SessionModel.customer_tenant_id == self.tenant_id,
                SessionModel.session_id == session_id,
            )
        )
        return result.scalars().first()

    async def list_sessions(
        self,
        *,
        limit: int = 50,
        status: Optional[str] = None,
        trust_state: Optional[str] = None,
    ) -> List[SessionModel]:
        stmt: Select = (
            select(SessionModel)
            .where(SessionModel.customer_tenant_id == self.tenant_id)
            .order_by(desc(SessionModel.last_seen_at))
            .limit(limit)
        )
        if status:
            stmt = stmt.where(SessionModel.status == status)
        if trust_state:
            stmt = stmt.where(SessionModel.trust_state == trust_state)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def add_session(self, session: SessionModel) -> SessionModel:
        session.customer_tenant_id = self.tenant_id
        self.db.add(session)
        await self.db.flush()
        return session

    async def baseline_network_for_user(
        self, user_id: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        """Most frequently observed (country, asn) pair for a user's past sessions."""
        if not user_id:
            return None, None
        result = await self.db.execute(
            select(SessionModel.network_country, SessionModel.network_asn)
            .where(
                SessionModel.customer_tenant_id == self.tenant_id,
                SessionModel.user_ref_id == user_id,
                SessionModel.network_country.is_not(None),
            )
            .order_by(desc(SessionModel.created_at))
            .limit(20)
        )
        rows = result.all()
        if not rows:
            return None, None
        countries = [row[0] for row in rows if row[0]]
        asns = [row[1] for row in rows if row[1]]
        return (
            Counter(countries).most_common(1)[0][0] if countries else None,
            Counter(asns).most_common(1)[0][0] if asns else None,
        )

    # -------------------------------------------------------------- baselines
    async def get_trusted_baseline(
        self, user_id: str, device_id: Optional[str]
    ) -> Optional[TrustedBaselineModel]:
        result = await self.db.execute(
            select(TrustedBaselineModel).where(
                TrustedBaselineModel.customer_tenant_id == self.tenant_id,
                TrustedBaselineModel.user_id == user_id,
                TrustedBaselineModel.device_id == device_id,
            )
        )
        return result.scalars().first()

    async def get_shadow_baseline(
        self, user_id: str, device_id: Optional[str]
    ) -> Optional[ShadowBaselineModel]:
        result = await self.db.execute(
            select(ShadowBaselineModel).where(
                ShadowBaselineModel.customer_tenant_id == self.tenant_id,
                ShadowBaselineModel.user_id == user_id,
                ShadowBaselineModel.device_id == device_id,
            )
        )
        return result.scalars().first()

    async def upsert_trusted_baseline(
        self, user_id: str, device_id: Optional[str], payload: Dict[str, Any], **extra: Any
    ) -> TrustedBaselineModel:
        row = await self.get_trusted_baseline(user_id, device_id)
        if row is None:
            row = TrustedBaselineModel(
                customer_tenant_id=self.tenant_id, user_id=user_id, device_id=device_id
            )
            self.db.add(row)
        row.baseline = payload
        for key, value in extra.items():
            setattr(row, key, value)
        await self.db.flush()
        return row

    async def upsert_shadow_baseline(
        self, user_id: str, device_id: Optional[str], payload: Dict[str, Any], **extra: Any
    ) -> ShadowBaselineModel:
        row = await self.get_shadow_baseline(user_id, device_id)
        if row is None:
            row = ShadowBaselineModel(
                customer_tenant_id=self.tenant_id, user_id=user_id, device_id=device_id
            )
            self.db.add(row)
        row.baseline = payload
        for key, value in extra.items():
            setattr(row, key, value)
        await self.db.flush()
        return row

    # ------------------------------------------------------ behavioral features
    async def add_behavior_feature(self, feature: BehaviorFeatureModel) -> BehaviorFeatureModel:
        feature.customer_tenant_id = self.tenant_id
        self.db.add(feature)
        await self.db.flush()
        return feature

    async def latest_behavior_feature(self, session_row_id: str) -> Optional[BehaviorFeatureModel]:
        result = await self.db.execute(
            select(BehaviorFeatureModel)
            .where(
                BehaviorFeatureModel.customer_tenant_id == self.tenant_id,
                BehaviorFeatureModel.session_id == session_row_id,
            )
            .order_by(desc(BehaviorFeatureModel.observed_at))
            .limit(1)
        )
        return result.scalars().first()

    async def recent_anomaly_scores(self, session_row_id: str, limit: int = 20) -> List[float]:
        """Anomaly scores for a session, newest first (used for evidence accumulation)."""
        result = await self.db.execute(
            select(BehaviorFeatureModel.anomaly_score)
            .where(
                BehaviorFeatureModel.customer_tenant_id == self.tenant_id,
                BehaviorFeatureModel.session_id == session_row_id,
            )
            .order_by(desc(BehaviorFeatureModel.observed_at))
            .limit(limit)
        )
        return [float(row[0] or 0.0) for row in result.all()]

    async def trusted_feature_history(
        self, user_id: str, device_id: Optional[str], limit: int = 200
    ) -> List[Dict[str, float]]:
        """Historical derived features used to fit the optional IsolationForest."""
        stmt = (
            select(BehaviorFeatureModel.features)
            .join(SessionModel, SessionModel.id == BehaviorFeatureModel.session_id)
            .where(
                BehaviorFeatureModel.customer_tenant_id == self.tenant_id,
                BehaviorFeatureModel.user_id == user_id,
                SessionModel.trust_state.in_(["TRUSTED", "DEGRADED"]),
            )
            .order_by(desc(BehaviorFeatureModel.observed_at))
            .limit(limit)
        )
        if device_id:
            stmt = stmt.where(BehaviorFeatureModel.device_id == device_id)
        result = await self.db.execute(stmt)
        return [dict(row[0] or {}) for row in result.all()]

    # ----------------------------------------------------------- trust history
    async def add_trust_state(self, state: TrustStateModel) -> TrustStateModel:
        state.customer_tenant_id = self.tenant_id
        self.db.add(state)
        await self.db.flush()
        return state

    async def recent_trust_states(
        self, session_row_id: str, limit: int = 25
    ) -> List[TrustStateModel]:
        result = await self.db.execute(
            select(TrustStateModel)
            .where(
                TrustStateModel.customer_tenant_id == self.tenant_id,
                TrustStateModel.session_id == session_row_id,
            )
            .order_by(desc(TrustStateModel.observed_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def rolling_tci_for_user(self, user_id: str, limit: int = 20) -> List[float]:
        """Recent TCI samples across this user's sessions (historical evidence)."""
        result = await self.db.execute(
            select(TrustStateModel.tci)
            .where(
                TrustStateModel.customer_tenant_id == self.tenant_id,
                TrustStateModel.user_id == user_id,
            )
            .order_by(desc(TrustStateModel.observed_at))
            .limit(limit)
        )
        return [float(row[0]) for row in result.all() if row[0] is not None]

    # -------------------------------------------------------- security events
    async def add_security_event(self, event: SecurityEventModel) -> SecurityEventModel:
        event.customer_tenant_id = self.tenant_id
        self.db.add(event)
        await self.db.flush()
        return event

    async def security_events_for_session(
        self, session_row_id: str, limit: int = 100
    ) -> List[SecurityEventModel]:
        result = await self.db.execute(
            select(SecurityEventModel)
            .where(
                SecurityEventModel.customer_tenant_id == self.tenant_id,
                SecurityEventModel.session_id == session_row_id,
            )
            .order_by(desc(SecurityEventModel.observed_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    async def count_suspicious_events(self, session_row_id: str) -> int:
        result = await self.db.execute(
            select(func.count())
            .select_from(SecurityEventModel)
            .where(
                SecurityEventModel.customer_tenant_id == self.tenant_id,
                SecurityEventModel.session_id == session_row_id,
                SecurityEventModel.severity >= 0.5,
            )
        )
        return int(result.scalar() or 0)

    # --------------------------------------------------------------- incidents
    async def count_incidents_for_user(self, user_id: str) -> int:
        result = await self.db.execute(
            select(func.count())
            .select_from(PlatformIncidentModel)
            .where(
                PlatformIncidentModel.customer_tenant_id == self.tenant_id,
                PlatformIncidentModel.user_id == user_id,
            )
        )
        return int(result.scalar() or 0)

    async def count_open_incidents_for_user(self, user_id: str) -> int:
        result = await self.db.execute(
            select(func.count())
            .select_from(PlatformIncidentModel)
            .where(
                PlatformIncidentModel.customer_tenant_id == self.tenant_id,
                PlatformIncidentModel.user_id == user_id,
                PlatformIncidentModel.status.in_(["OPEN", "INVESTIGATING"]),
            )
        )
        return int(result.scalar() or 0)

    # ----------------------------------------------------------------- actions
    async def latest_action(self, session_row_id: str) -> Optional[ActionModel]:
        result = await self.db.execute(
            select(ActionModel)
            .where(
                ActionModel.customer_tenant_id == self.tenant_id,
                ActionModel.session_id == session_row_id,
            )
            .order_by(desc(ActionModel.requested_at))
            .limit(1)
        )
        return result.scalars().first()

    async def actions_for_session(self, session_row_id: str, limit: int = 100) -> List[ActionModel]:
        result = await self.db.execute(
            select(ActionModel)
            .where(
                ActionModel.customer_tenant_id == self.tenant_id,
                ActionModel.session_id == session_row_id,
            )
            .order_by(desc(ActionModel.requested_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------- stats
    async def soc_overview(self) -> Dict[str, Any]:
        """Aggregates for the SOC dashboard header."""
        tenant = self.tenant_id

        async def scalar(stmt) -> Any:
            result = await self.db.execute(stmt)
            return result.scalar()

        active = await scalar(
            select(func.count())
            .select_from(SessionModel)
            .where(SessionModel.customer_tenant_id == tenant, SessionModel.status == "ACTIVE")
        )
        suspicious = await scalar(
            select(func.count())
            .select_from(SessionModel)
            .where(
                SessionModel.customer_tenant_id == tenant,
                SessionModel.trust_state.in_(["SUSPICIOUS", "CRITICAL", "BLOCKED"]),
                SessionModel.status.in_(["ACTIVE", "PAUSED"]),
            )
        )
        contained = await scalar(
            select(func.count())
            .select_from(SessionModel)
            .where(SessionModel.customer_tenant_id == tenant, SessionModel.is_contained.is_(True))
        )
        incidents = await scalar(
            select(func.count())
            .select_from(PlatformIncidentModel)
            .where(
                PlatformIncidentModel.customer_tenant_id == tenant,
                PlatformIncidentModel.status.in_(["OPEN", "INVESTIGATING"]),
            )
        )
        average_tci = await scalar(
            select(func.avg(SessionModel.tci)).where(
                SessionModel.customer_tenant_id == tenant,
                SessionModel.tci.is_not(None),
                SessionModel.status.in_(["ACTIVE", "PAUSED"]),
            )
        )
        blocked_actions = await scalar(
            select(func.count())
            .select_from(ActionModel)
            .where(
                ActionModel.customer_tenant_id == tenant,
                ActionModel.decision.in_(["BLOCK", "REVOKE", "CONTAIN"]),
            )
        )
        step_ups = await scalar(
            select(func.count())
            .select_from(ActionModel)
            .where(ActionModel.customer_tenant_id == tenant, ActionModel.decision == "STEP_UP")
        )
        return {
            "active_sessions": int(active or 0),
            "suspicious_sessions": int(suspicious or 0),
            "contained_sessions": int(contained or 0),
            "open_incidents": int(incidents or 0),
            "average_tci": round(float(average_tci), 2) if average_tci is not None else None,
            "blocked_actions": int(blocked_actions or 0),
            "step_up_requests": int(step_ups or 0),
        }

    async def delete_session_cascade(self, session_row_id: str) -> None:
        """Test/demo helper: removes a session and its dependent rows."""
        for model in (
            TrustStateModel,
            BehaviorFeatureModel,
            SecurityEventModel,
            ActionModel,
        ):
            await self.db.execute(
                delete(model).where(
                    model.customer_tenant_id == self.tenant_id,
                    model.session_id == session_row_id,
                )
            )
        await self.db.execute(
            delete(SessionModel).where(
                SessionModel.id == session_row_id,
                SessionModel.customer_tenant_id == self.tenant_id,
            )
        )
        await self.db.flush()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


__all__ = ["PlatformRepository", "utcnow"]
