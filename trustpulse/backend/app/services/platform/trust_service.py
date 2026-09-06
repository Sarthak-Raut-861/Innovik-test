"""TRUSTPULSE — Trust API and SOC read-model service.

Thin orchestration layer between the HTTP API and the trust engine. It never
computes trust itself, so there is exactly one implementation of the model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import SessionNotFoundException
from app.core.trust_config import TrustModelConfig, get_trust_config
from app.models.observations import TrustStateModel
from app.models.session import SessionModel
from app.repositories.platform import PlatformRepository
from app.schemas.platform import (
    NetworkContext,
    SocOverview,
    SocSessionDetail,
    SocSessionSummary,
    TelemetryRequest,
    TelemetryResponse,
    TrustEvaluateRequest,
)
from app.schemas.trust import EvidenceRecord, FactorScoreSchema, TrustResult
from app.services.trust_engine.engine import TrustEngine

# Evidence types that indicate the session itself may be compromised.
COMPROMISE_INDICATING = {
    "BEHAVIOR_DEVIATION",
    "BASELINE_DEVIATION",
    "DEVICE_CHANGE",
    "NETWORK_CHANGE",
    "SESSION_ANOMALY",
    "PRIVILEGE_ESCALATION",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class TrustService:
    def __init__(
        self,
        db: AsyncSession,
        tenant_id: str,
        config: Optional[TrustModelConfig] = None,
    ) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.config = config or get_trust_config()
        self.repo = PlatformRepository(db, tenant_id)
        self.engine = TrustEngine(db, tenant_id, config=self.config)

    # ---------------------------------------------------------------- telemetry
    async def ingest_telemetry(self, request: TelemetryRequest) -> TelemetryResponse:
        session = await self._require_session(request.session_id)
        if session.status not in ("ACTIVE", "PAUSED"):
            # Telemetry for a revoked/contained session is recorded but cannot
            # improve trust; the engine scores it accordingly.
            pass

        observation = self._normalize_observation(request)
        self._apply_network(session, request.network)

        evaluation = await self.engine.evaluate(
            session,
            observation=observation or None,
            trigger="TELEMETRY",
            source=request.source,
            sample_metadata=request.sample_metadata,
        )
        await self.db.flush()

        return TelemetryResponse(
            accepted=True,
            features_received=len(evaluation.features),
            anomaly_score=round(evaluation.anomaly.anomaly_score, 4),
            trust=evaluation.result,
            learned={
                "shadow_learned": evaluation.learned_shadow,
                "shadow_rejected": evaluation.shadow_rejected,
                "promotion": evaluation.promotion,
                "core_observations": evaluation.core_observations,
                "shadow_observations": evaluation.shadow_observations,
            },
        )

    # -------------------------------------------------------------------- trust
    async def evaluate(self, request: TrustEvaluateRequest) -> TrustResult:
        session = await self._require_session(request.session_id)
        self._apply_network(session, request.network)
        evaluation = await self.engine.evaluate(
            session,
            observation=request.features,
            trigger=request.trigger or "MANUAL",
            source="SIMULATION" if (request.trigger or "").upper() == "SIMULATION" else "SDK",
        )
        await self.db.flush()
        return evaluation.result

    async def get_trust(self, session_id: str) -> TrustResult:
        """Returns the current trust view without recomputing it."""
        session = await self._require_session(session_id)
        rows = await self.repo.recent_trust_states(session.id, limit=1)
        if not rows:
            evaluation = await self.engine.evaluate(session, trigger="READ")
            await self.db.flush()
            return evaluation.result
        return self._trust_from_row(session, rows[0])

    async def get_history(self, session_id: str, limit: int = 200) -> Dict[str, Any]:
        session = await self._require_session(session_id)
        rows = list(reversed(await self.repo.recent_trust_states(session.id, limit=limit)))
        points = [
            {
                "observed_at": _aware(row.observed_at).isoformat()
                if _aware(row.observed_at)
                else None,
                "tci": row.tci,
                "state": row.state,
                "confidence": row.confidence,
                "trend": row.trend,
                "trigger": row.trigger,
                "state_changed": row.state_changed,
            }
            for row in rows
        ]
        timeline: List[Dict[str, Any]] = []
        for row in rows:
            if row.state_changed:
                timeline.append(
                    {
                        "observed_at": (
                            _aware(row.observed_at).isoformat() if _aware(row.observed_at) else None
                        ),
                        "from": row.previous_state,
                        "to": row.state,
                        "tci": row.tci,
                        "trigger": row.trigger,
                    }
                )
        return {"session_id": session.session_id, "points": points, "state_timeline": timeline}

    # ---------------------------------------------------------------------- SOC
    async def soc_overview(self) -> SocOverview:
        stats = await self.repo.soc_overview()
        return SocOverview(trust_model_version=self.config.schema_version, **stats)

    async def soc_sessions(self, limit: int = 50) -> List[SocSessionSummary]:
        sessions = await self.repo.list_sessions(limit=limit)
        summaries: List[SocSessionSummary] = []
        for session in sessions:
            user = await self.repo.get_user(session.user_ref_id) if session.user_ref_id else None
            device = (
                await self.repo.get_device(session.device_ref_id) if session.device_ref_id else None
            )
            action = await self.repo.latest_action(session.id)
            summaries.append(
                SocSessionSummary(
                    session_id=session.session_id,
                    user=user.username if user else session.subject_id,
                    user_id=user.external_user_id if user else session.subject_id,
                    device=(device.label or device.device_fingerprint[:12]) if device else None,
                    tci=session.tci,
                    trust_state=session.trust_state,
                    trend=session.tci_trend,
                    confidence=session.tci_confidence,
                    last_action=action.action if action else None,
                    action_risk=action.action_risk if action else None,
                    decision=action.decision if action else None,
                    last_seen_at=session.last_seen_at,
                    status=session.status,
                    is_contained=bool(session.is_contained),
                )
            )
        return summaries

    async def soc_session_detail(self, session_id: str) -> SocSessionDetail:
        session = await self._require_session(session_id)
        user = await self.repo.get_user(session.user_ref_id) if session.user_ref_id else None
        device = (
            await self.repo.get_device(session.device_ref_id) if session.device_ref_id else None
        )
        action = await self.repo.latest_action(session.id)
        rows = list(reversed(await self.repo.recent_trust_states(session.id, limit=200)))
        events = await self.repo.security_events_for_session(session.id, limit=100)
        actions = await self.repo.actions_for_session(session.id, limit=100)

        core_row = (
            await self.repo.get_trusted_baseline(session.user_ref_id, session.device_ref_id)
            if session.user_ref_id
            else None
        )
        shadow_row = (
            await self.repo.get_shadow_baseline(session.user_ref_id, session.device_ref_id)
            if session.user_ref_id
            else None
        )

        summary = SocSessionSummary(
            session_id=session.session_id,
            user=user.username if user else session.subject_id,
            user_id=user.external_user_id if user else session.subject_id,
            device=(device.label or device.device_fingerprint[:12]) if device else None,
            tci=session.tci,
            trust_state=session.trust_state,
            trend=session.tci_trend,
            confidence=session.tci_confidence,
            last_action=action.action if action else None,
            action_risk=action.action_risk if action else None,
            decision=action.decision if action else None,
            last_seen_at=session.last_seen_at,
            status=session.status,
            is_contained=bool(session.is_contained),
        )

        trust = self._trust_from_row(session, rows[-1]) if rows else None

        return SocSessionDetail(
            session=summary,
            trust=trust,
            tci_history=[
                {
                    "observed_at": (
                        _aware(row.observed_at).isoformat() if _aware(row.observed_at) else None
                    ),
                    "tci": row.tci,
                    "state": row.state,
                    "confidence": row.confidence,
                    "trend": row.trend,
                    "trigger": row.trigger,
                    "state_changed": row.state_changed,
                }
                for row in rows
            ],
            evidence=[
                EvidenceRecord(
                    type=row.event_type,
                    severity=float(row.severity or 0.0),
                    description=row.description,
                    source=row.source,
                    observed_at=_aware(row.observed_at),
                    metadata=dict(row.meta or {}),
                )
                for row in reversed(events)
            ],
            actions=[
                {
                    "id": row.id,
                    "action": row.action,
                    "resource": row.resource,
                    "action_risk": row.action_risk,
                    "decision": row.decision,
                    "decision_reason": row.decision_reason,
                    "tci_at_decision": row.tci_at_decision,
                    "trust_state_at_decision": row.trust_state_at_decision,
                    "receipt_id": row.receipt_id,
                    "step_up_result": row.step_up_result,
                    "requested_at": (
                        _aware(row.requested_at).isoformat() if _aware(row.requested_at) else None
                    ),
                }
                for row in actions
            ],
            baselines={
                "core": {
                    "observations": core_row.observation_count if core_row else 0,
                    "version": core_row.version if core_row else 0,
                    "features": len((core_row.baseline or {}).get("means", {})) if core_row else 0,
                    "promotions_from_shadow": core_row.promotions_from_shadow if core_row else 0,
                    "rejected_observations": core_row.rejected_observations if core_row else 0,
                },
                "shadow": {
                    "observations": shadow_row.observation_count if shadow_row else 0,
                    "version": shadow_row.version if shadow_row else 0,
                    "features": len((shadow_row.baseline or {}).get("means", {}))
                    if shadow_row
                    else 0,
                    "rejected_observations": shadow_row.rejected_observations if shadow_row else 0,
                    "last_promotion_reasons": (
                        shadow_row.last_promotion_reasons if shadow_row else None
                    ),
                },
            },
        )

    # ---------------------------------------------------------------- internals
    async def _require_session(self, session_id: str) -> SessionModel:
        session = await self.repo.get_session_by_session_id(session_id)
        if session is None:
            raise SessionNotFoundException(session_id)
        return session

    @staticmethod
    def _normalize_observation(request: TelemetryRequest) -> Dict[str, float]:
        """Accepts either grouped SDK features or pre-normalized canonical values."""
        if request.flat_features:
            return {str(k): float(v) for k, v in request.flat_features.items()}
        return dict(request.features or {})

    @staticmethod
    def _apply_network(session: SessionModel, network: Optional[NetworkContext]) -> None:
        if network is None:
            return
        if network.country:
            session.network_country = network.country
        if network.asn:
            session.network_asn = network.asn
        session.is_vpn = bool(network.is_vpn)
        session.is_proxy_or_tor = bool(network.is_proxy_or_tor)
        if network.client_ip:
            from app.core.credentials import hash_identifier

            session.ip_hash = hash_identifier(network.client_ip)

    def _trust_from_row(self, session: SessionModel, row: TrustStateModel) -> TrustResult:
        payload = row.factors or {}
        factors = [
            FactorScoreSchema(
                name=item.get("name", "unknown"),
                score=float(item.get("score", 0.0)),
                configured_weight=float(self.config.weights.get(item.get("name", ""), 0.0)),
                effective_weight=float(
                    (payload.get("effective_weights") or {}).get(item.get("name", ""), 0.0)
                ),
                available=bool(item.get("available", True)),
                contribution=round(
                    float(item.get("score", 0.0))
                    * float(
                        (payload.get("effective_weights") or {}).get(item.get("name", ""), 0.0)
                    ),
                    2,
                ),
                reasons=list(item.get("reasons") or []),
            )
            for item in (payload.get("items") or [])
        ]
        evidence: List[EvidenceRecord] = []
        for item in row.evidence or []:
            if not isinstance(item, dict):
                continue
            observed = item.get("observed_at")
            try:
                observed_at = (
                    datetime.fromisoformat(observed) if isinstance(observed, str) else None
                )
            except ValueError:
                observed_at = None
            evidence.append(
                EvidenceRecord(
                    type=str(item.get("type", "SESSION_ANOMALY")),
                    severity=float(item.get("severity", 0.0) or 0.0),
                    description=str(item.get("description", "")),
                    source=str(item.get("source", "TRUST_ENGINE")),
                    observed_at=observed_at,
                    metadata={
                        k: v for k, v in (item.get("metadata") or {}).items() if k != "observed_at"
                    },
                )
            )
        return TrustResult(
            session_id=session.session_id,
            tci=float(row.tci),
            confidence=row.confidence,
            trend=row.trend,
            state=row.state,
            previous_state=row.previous_state,
            state_changed=bool(row.state_changed),
            raw_band=row.raw_band,
            hysteresis_applied=bool(row.hysteresis_applied),
            factors=factors,
            evidence=evidence,
            warnings=list(row.warnings or []),
            evaluations=int(session.trust_evaluations or 0),
            evaluated_at=_aware(row.observed_at),
            trigger=row.trigger,
        )

    @staticmethod
    def compromise_signals(evidence: List[EvidenceRecord]) -> List[EvidenceRecord]:
        """Filters evidence down to compromise-indicating signals (used by policy)."""
        return [record for record in evidence if record.type in COMPROMISE_INDICATING]


__all__ = ["TrustService", "COMPROMISE_INDICATING"]
