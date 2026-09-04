"""
TrustPulse AI - Risk Evaluation Service

Orchestrates session confidence calculation and action risk evaluation,
then delegates to the policy decision engine.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.risk import RiskEvaluationRequest, RiskEvaluationResponse
from app.schemas.action import ActionRiskLevel
from app.repositories.sessions import SessionRepository
from app.repositories.profiles import ProfileRepository
from app.repositories.risks import RiskRepository
from app.repositories.incidents import IncidentRepository
from app.repositories.telemetry import TelemetryRepository
from app.engines.behavioral.anomaly import AnomalyEngine
from app.engines.behavioral.baseline import BaselineEngine
from app.engines.risk.session_confidence import SessionConfidenceEngine
from app.engines.action.action_risk import ActionRiskEngine
from app.engines.policy.decision_engine import PolicyDecisionEngine
from app.core.exceptions import SessionNotFoundException
from app.core.logging import logger


class RiskService:
    def __init__(self, db: AsyncSession, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id
        self.session_repo = SessionRepository(db, tenant_id)
        self.profile_repo = ProfileRepository(db, tenant_id)
        self.risk_repo = RiskRepository(db, tenant_id)
        self.incident_repo = IncidentRepository(db, tenant_id)
        self.telemetry_repo = TelemetryRepository(db, tenant_id)

    async def evaluate(self, request: RiskEvaluationRequest) -> RiskEvaluationResponse:
        """
        Full risk evaluation pipeline:
        1. Session lookup
        2. Profile/baseline retrieval
        3. Recent telemetry fetch
        4. Behavioral anomaly detection
        5. Session confidence calculation
        6. Action risk assessment
        7. Policy decision
        8. Audit persistence
        """
        # --- 1. Session Lookup ---
        sess = await self.session_repo.get_by_session_id(request.session_id)
        if not sess:
            raise SessionNotFoundException(request.session_id)

        # --- 2. Open Incidents Check ---
        open_incidents = await self.incident_repo.get_open_incidents(request.session_id)
        open_incident = len(open_incidents) > 0

        # --- 3. Profile/Baseline Retrieval ---
        trusted_baseline = None
        is_cold_start = True

        if sess.subject_id:
            profile = await self.profile_repo.get_by_subject_device(
                sess.subject_id, sess.device_id
            )
            if profile and profile.trusted_baseline:
                trusted_baseline = profile.trusted_baseline
                is_cold_start = False
        else:
            is_cold_start = True

        # --- 4. Recent Telemetry ---
        recent_events = await self.telemetry_repo.get_session_events(request.session_id, limit=10)
        observed_features = {}
        if recent_events:
            # Use the most recent valid payload
            latest = recent_events[0]
            observed_features = latest.feature_payload or {}

        # --- 5. Behavioral Anomaly Detection ---
        anomaly_score, is_anomaly, anomaly_reasons = AnomalyEngine.evaluate_features(
            observed_features=observed_features,
            trusted_baseline=trusted_baseline,
        )

        # --- 6. Session Confidence ---
        session_confidence, confidence_level, reason_codes = SessionConfidenceEngine.calculate_confidence(
            anomaly_score=anomaly_score,
            is_cold_start=is_cold_start,
            device_matched=True,   # Extended: device fingerprint matching
            network_suspicious=False,  # Extended: network intelligence
            open_incident=open_incident,
        )
        reason_codes = list(set(reason_codes + anomaly_reasons))

        # --- 7. Action Risk ---
        action_risk, action_reason = ActionRiskEngine.evaluate_action_risk(
            action_type=request.action.type,
            amount=request.action.amount,
            currency=request.action.currency,
        )
        if action_reason:
            reason_codes = list(set(reason_codes + [action_reason]))

        # --- 8. Policy Decision ---
        decision, reason_codes = PolicyDecisionEngine.decide(
            session_confidence=session_confidence,
            action_risk=action_risk,
            reason_codes=reason_codes,
            open_incident=open_incident,
        )

        # --- 9. Auto-raise incident on ISOLATE ---
        decision_id = str(uuid.uuid4())
        if decision.value == "ISOLATE" and not open_incident:
            await self.incident_repo.create_incident(
                session_id=request.session_id,
                severity="CRITICAL",
                trigger_reason=", ".join(reason_codes),
                decision_id=decision_id,
            )
            # Also terminate session
            await self.session_repo.update_status(request.session_id, "ISOLATED")
            logger.warn(f"Session {request.session_id} ISOLATED: {reason_codes}")

        # --- 10. Persist Decision ---
        action_rec = await self.risk_repo.record_action_request(
            session_id=request.session_id,
            action_type=request.action.type,
            risk_level=action_risk.value,
            amount=request.action.amount,
            currency=request.action.currency,
            resource_type=request.action.resource_type,
            resource_id=request.action.resource_id,
        )

        await self.risk_repo.record_decision(
            session_id=request.session_id,
            decision=decision.value,
            reason_codes=reason_codes,
            action_id=str(action_rec.id) if hasattr(action_rec, "id") else None,
            policy_version="v1",
        )

        # --- 11. Update behavioral profile with new telemetry ---
        if sess.subject_id and recent_events and not is_cold_start:
            try:
                profile = await self.profile_repo.get_or_create(
                    subject_id=sess.subject_id,
                    device_id=sess.device_id,
                )
                # Extract flat feature vector for baseline update
                from app.engines.behavioral.similarity import SimilarityEngine
                flat_features = SimilarityEngine.extract_feature_vector(observed_features)

                new_candidate = BaselineEngine.update_rolling_baseline(
                    current_baseline=profile.candidate_baseline,
                    new_features=flat_features,
                )

                # Only promote if session is healthy
                can_promote = BaselineEngine.can_promote_to_trusted(
                    session_confidence=session_confidence,
                    has_active_incident=open_incident,
                    has_suspicious_action=(decision.value in ("BLOCK", "ISOLATE")),
                )

                if can_promote and profile.candidate_baseline:
                    promoted = BaselineEngine.promote_candidate(
                        trusted_baseline=profile.trusted_baseline,
                        candidate_baseline=new_candidate,
                    )
                    await self.profile_repo.update_baselines(
                        profile=profile,
                        trusted_baseline=promoted,
                        confidence=float(session_confidence) / 100.0,
                    )
                else:
                    await self.profile_repo.update_baselines(
                        profile=profile,
                        candidate_baseline=new_candidate,
                    )
            except Exception as e:
                logger.warn(f"Profile update failed (non-critical): {e}")

        return RiskEvaluationResponse(
            decision=decision.value,
            session_confidence=session_confidence,
            confidence_level=confidence_level,
            action_risk=action_risk,
            reason_codes=reason_codes,
            policy_version="v1",
            decision_id=decision_id,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
