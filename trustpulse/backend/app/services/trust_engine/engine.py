"""TRUSTPULSE — Trust Engine.

Pipeline for one evaluation:

    derived telemetry ─▶ feature extraction ─▶ anomaly detection (evidence)
                      ─▶ six factor scorers ─▶ weighted TCI fusion
                      ─▶ hysteresis state machine ─▶ persisted trust state
                      ─▶ baseline learning (gated)

The engine produces a **trust assessment**. It never authorizes anything: the
authorization decision belongs to the policy engine and the PEP (Phase 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from trustpulse_ml.anomaly_detection.detector import (
    AnomalyResult,
    IsolationForestAnomalyDetector,
    StatisticalAnomalyDetector,
    describe_deviation,
    fuse_results,
)
from trustpulse_ml.baseline.adaptive_shadow import AdaptiveShadow
from trustpulse_ml.baseline.trusted_core import Baseline, TrustedCore, baseline_distance
from trustpulse_ml.feature_extraction.features import (
    RawDataRejectedError,
    extract_feature_vector,
    transform,
)
from trustpulse_ml.trust_fusion.fusion import FactorScore, FusionResult, fuse_factors

from app.core.logging import logger
from app.core.trust_config import TrustModelConfig, get_trust_config
from app.models.observations import BehaviorFeatureModel, SecurityEventModel, TrustStateModel
from app.models.session import SessionModel
from app.repositories.platform import PlatformRepository
from app.schemas.trust import EvidenceRecord, FactorScoreSchema, TrustResult
from app.services.trust_engine.factors import (
    evidence_from_factors,
    score_behavior,
    score_device,
    score_history,
    score_identity,
    score_network,
    score_session,
)
from app.services.trust_engine.state_machine import StateTransition, TrustStateMachine

# Evidence at or above this severity is persisted as a security event.
EVENT_SEVERITY_THRESHOLD = 0.35
# Avoid writing the same evidence type repeatedly for one session.
EVENT_DEDUPE_WINDOW_SECONDS = 120

# Optional ensemble detectors, cached per (tenant, user, device). They are pure
# evidence: if they cannot be fitted they contribute nothing.
_FOREST_CACHE: Dict[Tuple[str, str, Optional[str]], IsolationForestAnomalyDetector] = {}
_FOREST_MIN_SAMPLES = 30


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


@dataclass
class TrustEvaluation:
    """Everything one evaluation produced."""

    result: TrustResult
    transition: StateTransition
    anomaly: AnomalyResult
    fusion: FusionResult
    learned_shadow: bool = False
    shadow_rejected: bool = False
    promotion: Dict[str, Any] = field(default_factory=dict)
    core_observations: int = 0
    shadow_observations: int = 0
    features: Dict[str, float] = field(default_factory=dict)
    persisted_events: List[str] = field(default_factory=list)


class TrustEngine:
    """Continuous session trust evaluation."""

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
        self.state_machine = TrustStateMachine(self.config)
        self.core_learner = TrustedCore(
            alpha=float(self.config.get("behavior", "trusted_core_alpha", default=0.05))
        )
        self.shadow_learner = AdaptiveShadow(
            alpha=float(self.config.get("behavior", "shadow_alpha", default=0.25)),
            min_observations=int(
                self.config.get("behavior", "shadow_promotion_min_observations", default=8)
            ),
            max_promotion_distance=float(
                self.config.get("behavior", "shadow_max_promotion_distance", default=1.2)
            ),
        )
        self.detector = StatisticalAnomalyDetector()

    # ------------------------------------------------------------------ public
    async def evaluate(
        self,
        session: SessionModel,
        *,
        observation: Optional[Dict[str, Any]] = None,
        trigger: str = "TELEMETRY",
        source: str = "SDK",
        sample_metadata: Optional[Dict[str, Any]] = None,
        persist: bool = True,
    ) -> TrustEvaluation:
        """Recompute trust for ``session``. Optionally ingest a new observation."""
        now = _now()
        device = (
            await self.repo.get_device(session.device_ref_id) if session.device_ref_id else None
        )
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
        core = Baseline.from_dict(core_row.baseline if core_row else None)
        shadow = Baseline.from_dict(shadow_row.baseline if shadow_row else None)

        # ------------------------------------------------- 1. feature extraction
        features, features_compared, anomaly = await self._observe(
            session=session,
            observation=observation,
            core=core,
            now=now,
            source=source,
            sample_metadata=sample_metadata,
            persist=persist,
        )
        features_compared = anomaly.features_compared or features_compared

        # ------------------------------------------------------- 2. factor scores
        recent_states = await self.repo.recent_trust_states(session.id, limit=25)
        recent_states = list(reversed(recent_states))  # oldest -> newest
        suspicious_events = await self.repo.count_suspicious_events(session.id)
        past_incidents = (
            await self.repo.count_incidents_for_user(session.user_ref_id)
            if session.user_ref_id
            else 0
        )
        rolling_tci = (
            await self.repo.rolling_tci_for_user(session.user_ref_id) if session.user_ref_id else []
        )
        drift = (
            baseline_distance(core, shadow)
            if not core.is_empty() and not shadow.is_empty()
            else None
        )
        consecutive_anomalies = self._consecutive_anomalies(
            await self.repo.recent_anomaly_scores(session.id, limit=20),
            anomaly.anomaly_score if features else None,
        )

        factors: List[FactorScore] = [
            score_identity(
                auth_method=session.auth_method,
                mfa_used=session.mfa_used,
                session_created_at=session.created_at,
                config=self.config,
            ),
            score_device(
                device=device,
                fingerprint_matches=(
                    None
                    if device is None or not session.device_id
                    else device.device_fingerprint == session.device_id
                ),
                session_device_fingerprint=session.device_id,
                config=self.config,
            ),
            score_behavior(
                anomaly_score=None if not features else anomaly.anomaly_score,
                anomaly_reasons=anomaly.reasons,
                core_observations=core.observation_count,
                shadow_observations=shadow.observation_count,
                features_compared=features_compared,
                drift_distance=drift,
                consecutive_anomalies=consecutive_anomalies,
                config=self.config,
            ),
            score_network(
                country=session.network_country,
                asn=session.network_asn,
                is_vpn=session.is_vpn,
                is_proxy_or_tor=session.is_proxy_or_tor,
                baseline_country=session.baseline_network_country,
                baseline_asn=session.baseline_network_asn,
                config=self.config,
            ),
            score_session(
                status=session.status,
                is_contained=session.is_contained,
                created_at=session.created_at,
                last_seen_at=session.last_seen_at,
                last_telemetry_at=(
                    max(
                        [
                            _aware(row.observed_at)
                            for row in session.behavior_features
                            if _aware(row.observed_at)
                        ]
                        or [_aware(session.last_seen_at)]
                    )
                ),
                suspicious_event_count=suspicious_events,
                step_up_failures=session.step_up_failures,
                config=self.config,
            ),
            score_history(
                rolling_tci_values=rolling_tci,
                past_incident_count=past_incidents,
                step_up_failure_count=session.step_up_failures,
                config=self.config,
            ),
        ]

        # ------------------------------------------------------------ 3. fusion
        history = [float(row.tci) for row in recent_states if row.tci is not None]
        fusion = fuse_factors(
            factors,
            weights=self.config.weights,
            evidence_features=features_compared,
            high_confidence_min_features=self.config.high_confidence_min_features,
            medium_confidence_min_features=self.config.medium_confidence_min_features,
            history=history,
            scale_max=self.config.tci_scale_max,
        )
        if not any(factor.available for factor in factors):
            fusion.tci = float(self.config.cold_start_tci)

        # ------------------------------------------------------- 4. state machine
        recent_raw_bands = [str(row.raw_band or row.state) for row in recent_states]
        open_incidents = (
            await self.repo.count_open_incidents_for_user(session.user_ref_id)
            if session.user_ref_id
            else 0
        )
        transition = self.state_machine.next_state(
            current_state=session.trust_state,
            tci=fusion.tci,
            previous_tci=session.tci,
            recent_raw_bands=recent_raw_bands,
            is_contained=bool(session.is_contained),
            is_revoked=session.status in ("REVOKED", "TERMINATED"),
            open_incident=open_incidents > 0,
        )

        # ----------------------------------------------------------- 5. evidence
        evidence = evidence_from_factors(fusion.factors, now=now)
        for deviation in anomaly.deviations[:3]:
            if abs(float(deviation.get("z", 0.0))) < 2.0:
                continue
            severity = min(1.0, abs(float(deviation["z"])) / 10.0)
            evidence.append(
                EvidenceRecord(
                    type="BASELINE_DEVIATION",
                    severity=round(severity, 2),
                    description=describe_deviation(deviation),
                    source=anomaly.method,
                    observed_at=now,
                    metadata={
                        "feature": deviation["feature"],
                        "z": round(float(deviation["z"]), 2),
                    },
                )
            )
        if transition.changed:
            evidence.append(
                EvidenceRecord(
                    type="STATE_CHANGE",
                    severity=0.6 if transition.severity >= 2 else 0.3,
                    description=(
                        f"Trust state moved {transition.previous_state} → {transition.state} "
                        f"({transition.reason})"
                    ),
                    source="STATE_MACHINE",
                    observed_at=now,
                    metadata=transition.detail,
                )
            )

        result = TrustResult(
            session_id=session.session_id,
            tci=round(fusion.tci, 1),
            confidence=fusion.confidence,
            trend=fusion.trend,
            state=transition.state,
            previous_state=transition.previous_state,
            state_changed=transition.changed,
            raw_band=transition.raw_band,
            hysteresis_applied=transition.hysteresis_applied,
            factors=[
                FactorScoreSchema(
                    name=factor.name,
                    score=round(factor.score, 2),
                    configured_weight=round(factor.weight, 4),
                    effective_weight=round(fusion.effective_weights.get(factor.name, 0.0), 4),
                    available=factor.available,
                    contribution=round(
                        factor.score * fusion.effective_weights.get(factor.name, 0.0), 2
                    ),
                    reasons=factor.reasons,
                    detail=factor.detail,
                )
                for factor in fusion.factors
            ],
            evidence=evidence,
            warnings=fusion.warnings,
            evaluations=int(session.trust_evaluations or 0) + 1,
            evaluated_at=now,
            trigger=trigger,
        )

        # --------------------------------------------------------- 6. persistence
        persisted_events: List[str] = []
        if persist:
            persisted_events = await self._persist_events(session, evidence, now)
            await self.repo.add_trust_state(
                TrustStateModel(
                    customer_tenant_id=self.tenant_id,
                    session_id=session.id,
                    user_id=session.user_ref_id,
                    tci=round(fusion.tci, 2),
                    previous_tci=session.tci,
                    state=transition.state,
                    previous_state=transition.previous_state,
                    state_changed=transition.changed,
                    raw_band=transition.raw_band,
                    hysteresis_applied=transition.hysteresis_applied,
                    confidence=fusion.confidence,
                    trend=fusion.trend,
                    factors={
                        "items": [
                            {
                                "name": f.name,
                                "score": round(f.score, 2),
                                "available": f.available,
                                "reasons": f.reasons,
                            }
                            for f in fusion.factors
                        ],
                        "effective_weights": {
                            k: round(v, 4) for k, v in fusion.effective_weights.items()
                        },
                        "anomaly_score": round(anomaly.anomaly_score, 4),
                        "transition": transition.to_dict(),
                    },
                    evidence=[record.to_dict() for record in evidence],
                    warnings=fusion.warnings,
                    trigger=trigger,
                    observed_at=now,
                )
            )
            session.previous_tci = session.tci
            session.tci = round(fusion.tci, 2)
            session.tci_confidence = fusion.confidence
            session.tci_trend = fusion.trend
            if transition.state != session.trust_state:
                session.trust_state_since = now
            session.trust_state = transition.state
            session.trust_evaluations = int(session.trust_evaluations or 0) + 1
            session.last_trust_evaluation_at = now
            session.last_seen_at = now
            await self.db.flush()

        # -------------------------------------------------- 7. baseline learning
        learned_shadow = False
        shadow_rejected = False
        promotion: Dict[str, Any] = {}
        if persist and features and session.user_ref_id:
            learned_shadow, shadow, shadow_rejected = await self._learn(
                session=session,
                core=core,
                shadow=shadow,
                features=features,
                trust_state=transition.state,
                open_incident=open_incidents > 0,
            )
            if learned_shadow or shadow_rejected:
                await self.repo.upsert_shadow_baseline(
                    session.user_ref_id,
                    session.device_ref_id,
                    shadow.to_dict(),
                    observation_count=shadow.observation_count,
                    version=shadow.version,
                    rejected_observations=shadow.rejected_observations,
                )
            promotion = await self._maybe_promote(
                session=session,
                core=core,
                shadow=shadow,
                trust_state=transition.state,
                open_incident=open_incidents > 0,
            )
            if promotion.get("promoted"):
                core = Baseline.from_dict(promotion["core"])
                await self.repo.upsert_trusted_baseline(
                    session.user_ref_id,
                    session.device_ref_id,
                    core.to_dict(),
                    observation_count=core.observation_count,
                    version=core.version,
                    rejected_observations=core.rejected_observations,
                    promotions_from_shadow=(core_row.promotions_from_shadow if core_row else 0) + 1,
                    last_promotion_at=now,
                    last_observation_at=now,
                )
            elif core.observation_count == 0 and transition.state == "TRUSTED":
                # Bootstrap: a brand-new trusted session seeds the core directly so
                # the demo does not need a separate enrolment step.
                core = self.core_learner.update(core, transform(features))
                await self.repo.upsert_trusted_baseline(
                    session.user_ref_id,
                    session.device_ref_id,
                    core.to_dict(),
                    observation_count=core.observation_count,
                    version=core.version,
                    rejected_observations=core.rejected_observations,
                    last_observation_at=now,
                )

        return TrustEvaluation(
            result=result,
            transition=transition,
            anomaly=anomaly,
            fusion=fusion,
            learned_shadow=learned_shadow,
            shadow_rejected=shadow_rejected,
            promotion=promotion,
            core_observations=core.observation_count,
            shadow_observations=shadow.observation_count,
            features=features,
            persisted_events=persisted_events,
        )

    # ---------------------------------------------------------------- internals
    @staticmethod
    def _consecutive_anomalies(
        recent_scores_desc: List[float], current_score: Optional[float], threshold: float = 0.5
    ) -> int:
        """Counts the current observation plus trailing anomalous observations.

        Sustained deviation is stronger evidence than a single spike, so the
        behavior factor keeps eroding while the deviation persists.
        """
        sequence = ([current_score] if current_score is not None else []) + list(recent_scores_desc)
        count = 0
        for score in sequence:
            if float(score) >= threshold:
                count += 1
            else:
                break
        return count

    async def _observe(
        self,
        *,
        session: SessionModel,
        observation: Optional[Dict[str, Any]],
        core: Baseline,
        now: datetime,
        source: str,
        sample_metadata: Optional[Dict[str, Any]],
        persist: bool,
    ) -> Tuple[Dict[str, float], int, AnomalyResult]:
        """Extract features and compare them against the Trusted Core."""
        features: Dict[str, float] = {}
        features_compared = 0

        if observation is not None:
            try:
                features = extract_feature_vector(observation)
            except RawDataRejectedError as exc:
                logger.warning("Rejected raw telemetry for session %s: %s", session.session_id, exc)
                raise

        if not features:
            latest = await self.repo.latest_behavior_feature(session.id)
            if latest is not None:
                features = {k: float(v) for k, v in (latest.features or {}).items()}
                features_compared = int(latest.features_compared or 0)
                anomaly = AnomalyResult(
                    anomaly_score=float(latest.anomaly_score or 0.0),
                    is_anomaly=bool(
                        [r for r in (latest.anomaly_reasons or []) if r != "COLD_START_NO_BASELINE"]
                    ),
                    reasons=list(latest.anomaly_reasons or []),
                    deviations=list(latest.deviations or []),
                    features_compared=features_compared,
                    method=latest.detector_method or "statistical",
                )
                return features, features_compared, anomaly
            return (
                {},
                0,
                AnomalyResult(
                    anomaly_score=0.0,
                    is_anomaly=False,
                    reasons=["NO_BEHAVIORAL_EVIDENCE"],
                    method="none",
                ),
            )

        statistical = self.detector.evaluate(features, core if not core.is_empty() else None)
        forest = await self._forest_evidence(session, features)
        anomaly = fuse_results([statistical, forest], weights=[0.8, 0.2])
        features_compared = statistical.features_compared

        if persist:
            await self.repo.add_behavior_feature(
                BehaviorFeatureModel(
                    customer_tenant_id=self.tenant_id,
                    session_id=session.id,
                    user_id=session.user_ref_id,
                    device_id=session.device_ref_id,
                    features=features,
                    sample_metadata=sample_metadata,
                    anomaly_score=round(anomaly.anomaly_score, 4),
                    anomaly_reasons=anomaly.reasons,
                    deviations=anomaly.deviations,
                    features_compared=features_compared,
                    detector_method=anomaly.method,
                    source=source,
                    observed_at=now,
                )
            )
            # Keep the in-memory relationship cache consistent for this request.
            session.behavior_features = list(session.behavior_features)
        return features, features_compared, anomaly

    async def _forest_evidence(
        self, session: SessionModel, features: Dict[str, float]
    ) -> Optional[AnomalyResult]:
        """Optional IsolationForest evidence. Never blocks when unfitted."""
        if not session.user_ref_id:
            return None
        key = (self.tenant_id, session.user_ref_id, session.device_ref_id)
        detector = _FOREST_CACHE.get(key)
        if detector is None or not detector.is_fitted:
            history = await self.repo.trusted_feature_history(
                session.user_ref_id, session.device_ref_id, limit=200
            )
            candidate = IsolationForestAnomalyDetector(min_samples=_FOREST_MIN_SAMPLES)
            if not candidate.fit(history):
                return None
            detector = candidate
            _FOREST_CACHE[key] = detector
        return detector.evaluate(features)

    async def _persist_events(
        self, session: SessionModel, evidence: List[EvidenceRecord], now: datetime
    ) -> List[str]:
        """Persists significant evidence, de-duplicated within a short window."""
        recent = await self.repo.security_events_for_session(session.id, limit=20)
        window_start = now - timedelta(seconds=EVENT_DEDUPE_WINDOW_SECONDS)
        recent_types = {
            row.event_type
            for row in recent
            if _aware(row.observed_at) and _aware(row.observed_at) >= window_start
        }
        written: List[str] = []
        for record in evidence:
            if record.severity < EVENT_SEVERITY_THRESHOLD:
                continue
            if record.type in recent_types:
                continue
            await self.repo.add_security_event(
                SecurityEventModel(
                    customer_tenant_id=self.tenant_id,
                    session_id=session.id,
                    user_id=session.user_ref_id,
                    device_id=session.device_ref_id,
                    event_type=record.type,
                    severity=record.severity,
                    description=record.description,
                    source=record.source,
                    meta=record.metadata,
                    observed_at=record.observed_at or now,
                )
            )
            recent_types.add(record.type)
            written.append(record.type)
        return written

    async def _learn(
        self,
        *,
        session: SessionModel,
        core: Baseline,
        shadow: Baseline,
        features: Dict[str, float],
        trust_state: str,
        open_incident: bool,
    ) -> Tuple[bool, Baseline, bool]:
        shadow, learned = self.shadow_learner.update(
            shadow, transform(features), trust_state, open_incident
        )
        return learned, shadow, not learned

    async def _maybe_promote(
        self,
        *,
        session: SessionModel,
        core: Baseline,
        shadow: Baseline,
        trust_state: str,
        open_incident: bool,
    ) -> Dict[str, Any]:
        promoted_core, decision = self.shadow_learner.promote(
            core, shadow, trust_state, open_incident, recent_rejections=0, blend_alpha=0.1
        )
        payload: Dict[str, Any] = decision.to_dict()
        payload["promoted"] = decision.promote
        if decision.promote:
            payload["core"] = promoted_core.to_dict()
        return payload


def reset_forest_cache() -> None:
    """Test helper."""
    _FOREST_CACHE.clear()


__all__ = ["TrustEngine", "TrustEvaluation", "reset_forest_cache"]
