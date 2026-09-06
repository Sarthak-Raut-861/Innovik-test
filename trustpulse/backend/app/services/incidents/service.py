"""TRUSTPULSE — Incidents and security posture.

Two responsibilities that sit next to enforcement:

* **Incidents** — the lifecycle record of a trust collapse. The PEP opens them;
  this service owns listing, updating and closing them. Closing an incident
  matters because an open incident blocks trust recovery and blocks baseline
  promotion, so a stale incident would wedge a legitimate user permanently.
* **Security posture** — a tenant-level roll-up an analyst can read at a glance.
  It is derived from the same tables the SOC dashboard uses, so the two can
  never disagree.

Posture is deliberately a *derived view*, never a stored score. A stored score
goes stale the moment anything changes; a derived one is always true.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.core.trust_config import TrustModelConfig, get_trust_config
from app.models.observations import ActionModel, SecurityEventModel
from app.models.platform_incident import PlatformIncidentModel
from app.models.session import SessionModel

OPEN_STATUSES = ("OPEN", "INVESTIGATING")
CLOSED_STATUSES = ("CONTAINED", "RESOLVED", "FALSE_POSITIVE")

# Posture grades. A tenant with no incidents and healthy trust is EXCELLENT;
# anything actively contained drags it down fast, because that is the honest
# reading of the situation.
POSTURE_GRADES = (
    (90, "EXCELLENT"),
    (75, "GOOD"),
    (60, "FAIR"),
    (40, "POOR"),
    (0, "CRITICAL"),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass
class PostureReport:
    """Tenant-wide security posture, derived on demand."""

    score: float
    grade: str
    components: Dict[str, float]
    active_sessions: int
    contained_sessions: int
    suspicious_sessions: int
    average_tci: Optional[float]
    open_incidents: int
    critical_incidents: int
    blocked_actions: int
    step_up_requests: int
    step_up_failures: int
    allowed_actions: int
    recent_security_events: int
    generated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "grade": self.grade,
            "components": {k: round(v, 2) for k, v in self.components.items()},
            "active_sessions": self.active_sessions,
            "contained_sessions": self.contained_sessions,
            "suspicious_sessions": self.suspicious_sessions,
            "average_tci": round(self.average_tci, 2) if self.average_tci is not None else None,
            "open_incidents": self.open_incidents,
            "critical_incidents": self.critical_incidents,
            "blocked_actions": self.blocked_actions,
            "step_up_requests": self.step_up_requests,
            "step_up_failures": self.step_up_failures,
            "allowed_actions": self.allowed_actions,
            "recent_security_events": self.recent_security_events,
            "generated_at": self.generated_at.isoformat(),
        }


class IncidentService:
    """Incident lifecycle for one tenant."""

    def __init__(self, db: AsyncSession, tenant_id: str, config: Optional[TrustModelConfig] = None):
        self.db = db
        self.tenant_id = tenant_id
        self.config = config or get_trust_config()

    # ------------------------------------------------------------------ queries
    async def list_incidents(
        self,
        *,
        status: Optional[str] = None,
        session_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[PlatformIncidentModel]:
        stmt: Select = select(PlatformIncidentModel).where(
            PlatformIncidentModel.customer_tenant_id == self.tenant_id
        )
        if status:
            stmt = stmt.where(PlatformIncidentModel.status == status.upper())
        if session_id:
            stmt = stmt.where(PlatformIncidentModel.session_id == session_id)
        if severity:
            stmt = stmt.where(PlatformIncidentModel.severity == severity.upper())
        stmt = stmt.order_by(PlatformIncidentModel.opened_at.desc()).limit(limit)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get(self, incident_id: str) -> Optional[PlatformIncidentModel]:
        result = await self.db.execute(
            select(PlatformIncidentModel).where(
                PlatformIncidentModel.customer_tenant_id == self.tenant_id,
                PlatformIncidentModel.id == incident_id,
            )
        )
        return result.scalar_one_or_none()

    async def open_incidents_for_session(self, session_id: str) -> List[PlatformIncidentModel]:
        result = await self.db.execute(
            select(PlatformIncidentModel).where(
                PlatformIncidentModel.customer_tenant_id == self.tenant_id,
                PlatformIncidentModel.session_id == session_id,
                PlatformIncidentModel.status.in_(OPEN_STATUSES),
            )
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------ lifecycle
    async def update_status(
        self,
        incident_id: str,
        status: str,
        *,
        note: Optional[str] = None,
        closed_by: Optional[str] = None,
    ) -> Optional[PlatformIncidentModel]:
        """Moves an incident through its lifecycle.

        Closing an incident is a deliberate operator act. It unblocks trust
        recovery and baseline promotion for the affected user, which is exactly
        why it must be explicit and recorded rather than automatic.
        """
        incident = await self.get(incident_id)
        if incident is None:
            return None

        normalized = status.upper()
        if normalized not in OPEN_STATUSES + CLOSED_STATUSES:
            raise ValueError(
                f"unknown incident status {status!r}; "
                f"expected one of {OPEN_STATUSES + CLOSED_STATUSES}"
            )

        incident.status = normalized
        incident.updated_at = _now()
        if note:
            incident.description = f"{incident.description or ''}\n[{normalized}] {note}".strip()
        if normalized in CLOSED_STATUSES:
            incident.closed_at = _now()
        else:
            incident.closed_at = None

        # Annotate who closed it, without inventing a new column.
        actions = list(incident.containment_actions or [])
        if closed_by or note:
            suffix = f": {note}" if note else ""
            actions.append(f"{normalized} by {closed_by or 'operator'}{suffix}")
        incident.containment_actions = actions

        await self.db.flush()
        logger.info("Incident %s → %s", incident_id, normalized)
        return incident

    @staticmethod
    def to_dict(incident: PlatformIncidentModel) -> Dict[str, Any]:
        return {
            "id": incident.id,
            "session_id": incident.session_id,
            "user_id": incident.user_id,
            "device_id": incident.device_id,
            "severity": incident.severity,
            "title": incident.title,
            "description": incident.description,
            "status": incident.status,
            "tci_at_detection": incident.tci_at_detection,
            "trust_state_at_detection": incident.trust_state_at_detection,
            "evidence": list(incident.evidence_ids or []),
            "containment_actions": list(incident.containment_actions or []),
            "receipt_ids": list(incident.receipt_ids or []),
            "opened_at": incident.opened_at,
            "updated_at": incident.updated_at,
            "closed_at": incident.closed_at,
            "is_open": incident.status in OPEN_STATUSES,
        }


class SecurityPostureService:
    """Derives tenant-wide posture from the live tables."""

    def __init__(self, db: AsyncSession, tenant_id: str, config: Optional[TrustModelConfig] = None):
        self.db = db
        self.tenant_id = tenant_id
        self.config = config or get_trust_config()

    async def report(self, *, window_hours: int = 24) -> PostureReport:
        now = _now()
        since = now - timedelta(hours=window_hours)

        sessions = await self._session_stats()
        incidents = await self._incident_stats()
        actions = await self._action_stats()
        events = await self._event_count(since)

        components = {
            # Trust health: average TCI across active sessions. No sessions is
            # neutral-good, not zero — an idle tenant is not an unsafe one.
            "trust_health": (
                sessions["average_tci"] if sessions["average_tci"] is not None else 85.0
            ),
            # Containment: every contained session is a real cost.
            "containment": self._containment_component(sessions),
            # Incident pressure: open incidents, weighted by severity.
            "incident_pressure": self._incident_component(incidents),
            # Enforcement activity: a high block ratio means either an attack in
            # progress or an over-tight policy. Either way an analyst should look.
            "enforcement": self._enforcement_component(actions),
        }

        # Weighted composite. Trust health dominates because it is the thing the
        # product actually measures; the rest are corroboration.
        score = (
            components["trust_health"] * 0.45
            + components["containment"] * 0.25
            + components["incident_pressure"] * 0.20
            + components["enforcement"] * 0.10
        )
        score = max(0.0, min(100.0, score))

        return PostureReport(
            score=score,
            grade=self._grade(score),
            components=components,
            active_sessions=sessions["active"],
            contained_sessions=sessions["contained"],
            suspicious_sessions=sessions["suspicious"],
            average_tci=sessions["average_tci"],
            open_incidents=incidents["open"],
            critical_incidents=incidents["critical"],
            blocked_actions=actions["blocked"],
            step_up_requests=actions["step_up"],
            step_up_failures=actions["step_up_failures"],
            allowed_actions=actions["allowed"],
            recent_security_events=events,
            generated_at=now,
        )

    # ------------------------------------------------------------------ internals
    async def _session_stats(self) -> Dict[str, Any]:
        base = SessionModel.customer_tenant_id == self.tenant_id
        active_result = await self.db.execute(
            select(
                func.count(SessionModel.id),
                func.avg(SessionModel.tci),
            ).where(base, SessionModel.status == "ACTIVE")
        )
        active, average_tci = active_result.one()

        suspicious_result = await self.db.execute(
            select(func.count(SessionModel.id)).where(
                base,
                SessionModel.status == "ACTIVE",
                SessionModel.trust_state.in_(("SUSPICIOUS", "CRITICAL", "BLOCKED")),
            )
        )
        contained_result = await self.db.execute(
            select(func.count(SessionModel.id)).where(base, SessionModel.is_contained.is_(True))
        )

        return {
            "active": int(active or 0),
            "average_tci": float(average_tci) if average_tci is not None else None,
            "suspicious": int(suspicious_result.scalar_one() or 0),
            "contained": int(contained_result.scalar_one() or 0),
        }

    async def _incident_stats(self) -> Dict[str, int]:
        base = PlatformIncidentModel.customer_tenant_id == self.tenant_id
        open_result = await self.db.execute(
            select(func.count(PlatformIncidentModel.id)).where(
                base, PlatformIncidentModel.status.in_(OPEN_STATUSES)
            )
        )
        critical_result = await self.db.execute(
            select(func.count(PlatformIncidentModel.id)).where(
                base,
                PlatformIncidentModel.status.in_(OPEN_STATUSES),
                PlatformIncidentModel.severity.in_(("CRITICAL", "HIGH")),
            )
        )
        return {
            "open": int(open_result.scalar_one() or 0),
            "critical": int(critical_result.scalar_one() or 0),
        }

    async def _action_stats(self) -> Dict[str, int]:
        base = ActionModel.customer_tenant_id == self.tenant_id

        async def count(decisions: tuple) -> int:
            result = await self.db.execute(
                select(func.count(ActionModel.id)).where(base, ActionModel.decision.in_(decisions))
            )
            return int(result.scalar_one() or 0)

        step_up_failures_result = await self.db.execute(
            select(func.count(ActionModel.id)).where(base, ActionModel.step_up_result == "FAILED")
        )

        return {
            "allowed": await count(("ALLOW",)),
            "blocked": await count(("BLOCK", "REVOKE", "CONTAIN")),
            "step_up": await count(("STEP_UP",)),
            "step_up_failures": int(step_up_failures_result.scalar_one() or 0),
        }

    async def _event_count(self, since: datetime) -> int:
        result = await self.db.execute(
            select(func.count(SecurityEventModel.id)).where(
                SecurityEventModel.customer_tenant_id == self.tenant_id,
                SecurityEventModel.severity >= 0.35,
                SecurityEventModel.observed_at >= since,
            )
        )
        return int(result.scalar_one() or 0)

    @staticmethod
    def _containment_component(sessions: Dict[str, Any]) -> float:
        """100 with no containment, falling steeply as sessions are contained."""
        if sessions["active"] == 0 and sessions["contained"] == 0:
            return 100.0
        total = max(1, sessions["active"] + sessions["contained"])
        ratio = sessions["contained"] / total
        return max(0.0, 100.0 - ratio * 200.0)

    @staticmethod
    def _incident_component(incidents: Dict[str, int]) -> float:
        """Open incidents subtract from posture; critical ones subtract more."""
        penalty = incidents["open"] * 8 + incidents["critical"] * 12
        return max(0.0, 100.0 - penalty)

    @staticmethod
    def _enforcement_component(actions: Dict[str, int]) -> float:
        """A high block ratio lowers posture — it means something is wrong."""
        total = actions["allowed"] + actions["blocked"] + actions["step_up"]
        if total == 0:
            return 100.0
        block_ratio = actions["blocked"] / total
        failure_ratio = (
            actions["step_up_failures"] / max(1, actions["step_up"]) if actions["step_up"] else 0.0
        )
        return max(0.0, 100.0 - block_ratio * 90.0 - failure_ratio * 30.0)

    @staticmethod
    def _grade(score: float) -> str:
        for threshold, grade in POSTURE_GRADES:
            if score >= threshold:
                return grade
        return "CRITICAL"


__all__ = [
    "IncidentService",
    "SecurityPostureService",
    "PostureReport",
    "OPEN_STATUSES",
    "CLOSED_STATUSES",
]
