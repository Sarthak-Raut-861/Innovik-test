"""
TrustPulse AI — Behavioral Service.

Maintains trusted/candidate baselines and evaluates behavioral evidence against
the established baseline.

Baseline poisoning protection:
  * New observations first enter the CANDIDATE baseline.
  * The TRUSTED baseline is only promoted after a guarded gate
    (confidence, no incident, no suspicious action, policy allows learning).
"""

from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext
from app.core.logging import logger
from app.engines.behavioral.anomaly import AnomalyEngine
from app.engines.behavioral.baseline import BaselineEngine
from app.engines.behavioral.drift import DriftEngine
from app.engines.behavioral.similarity import SimilarityEngine
from app.models.session import SessionModel
from app.repositories.profiles import ProfileRepository
from app.repositories.telemetry import TelemetryRepository


class BehavioralService:
    def __init__(
        self, db: AsyncSession, tenant_id: str, integration: Optional[IntegrationContext] = None
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.profile_repo = ProfileRepository(db, tenant_id)
        self.telemetry_repo = TelemetryRepository(db, tenant_id)

    async def update_baseline_from_event(
        self,
        session: SessionModel,
        feature_payload: Dict[str, Any],
        session_confidence: int,
        has_active_incident: bool,
        suspicious_action: bool,
        policy_allows_learning: bool = True,
    ) -> Optional[Any]:
        """Updates the candidate and (guarded) trusted baseline for a subject/device."""
        if not session.subject_id:
            return None

        profile = await self.profile_repo.get_or_create(session.subject_id, session.device_id)
        features = SimilarityEngine.extract_feature_vector(feature_payload)
        if not features:
            return profile

        candidate = BaselineEngine.update_rolling_baseline(profile.candidate_baseline, features)
        count = int(candidate.get("observation_count", 0))

        can_promote = BaselineEngine.can_promote_to_trusted(
            session_confidence=session_confidence,
            has_active_incident=has_active_incident,
            has_suspicious_action=suspicious_action,
            policy_allows_learning=policy_allows_learning,
            observation_count=count,
        )

        if can_promote:
            new_trusted, previous = BaselineEngine.promote_candidate(
                profile.trusted_baseline, candidate
            )
            await self.profile_repo.update_baselines(
                profile=profile,
                trusted_baseline=new_trusted,
                trusted_baseline_previous=previous,
                candidate_baseline=candidate,
                confidence=min(1.0, session_confidence / 100.0),
                observation_count=count,
            )
            logger.info(
                f"Promoted trusted baseline v{profile.baseline_version} "
                f"for subject {session.subject_id}"
            )
        else:
            await self.profile_repo.update_baselines(
                profile=profile,
                candidate_baseline=candidate,
                observation_count=count,
            )
        return profile

    async def get_behavioral_evidence(
        self,
        session: SessionModel,
    ) -> Dict[str, Any]:
        """Computes behavioral evidence for risk evaluation."""
        trusted_baseline = None
        candidate_baseline = None
        is_cold_start = True

        if session.subject_id:
            profile = await self.profile_repo.get_by_subject_device(
                session.subject_id, session.device_id
            )
            if profile and profile.trusted_baseline:
                trusted_baseline = profile.trusted_baseline
                candidate_baseline = profile.candidate_baseline
                is_cold_start = False

        recent_events = await self.telemetry_repo.get_session_events(session.session_id, limit=20)
        observed_features: Dict[str, Any] = {}
        if recent_events:
            observed_features = recent_events[0].feature_payload or {}

        try:
            anomaly_score, is_anomaly, anomaly_reasons = AnomalyEngine.evaluate_features(
                observed_features=observed_features,
                trusted_baseline=trusted_baseline,
            )
        except Exception as exc:
            # Engine failure is NOT security clearance. Treat as unknown evidence.
            logger.error(f"Behavioral engine failed: {exc}")
            anomaly_score, is_anomaly, anomaly_reasons = 0.5, True, ["BEHAVIOR_ENGINE_UNAVAILABLE"]

        try:
            drift_magnitude, significant_drift = DriftEngine.evaluate_drift(
                candidate_baseline, trusted_baseline
            )
        except Exception as exc:
            logger.error(f"Drift engine failed: {exc}")
            drift_magnitude, significant_drift = 0.0, False
        if significant_drift:
            anomaly_reasons = list(dict.fromkeys(anomaly_reasons + ["SIGNIFICANT_DRIFT"]))

        event_count = len(recent_events)
        # Session history signal declines with long sessions / unresolved gaps.
        history_signal = 1.0
        if event_count > 500:
            history_signal = 0.8
        if event_count > 2000:
            history_signal = 0.6

        return {
            "observed_features": observed_features,
            "trusted_baseline": trusted_baseline,
            "candidate_baseline": candidate_baseline,
            "is_cold_start": is_cold_start,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "anomaly_reasons": anomaly_reasons,
            "drift_magnitude": drift_magnitude,
            "significant_drift": significant_drift,
            "session_history_signal": history_signal,
            "recent_event_count": event_count,
        }
