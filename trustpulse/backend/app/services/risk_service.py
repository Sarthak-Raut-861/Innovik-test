"""
TrustPulse AI — Risk Evaluation Service.

Fresh, synchronous action evaluation for a live session.

Telemetry→Detection→Risk Evidence→Action Risk→Deterministic Policy→Decision.
The policy engine is the only component that returns ALLOW/STEP_UP/BLOCK/ISOLATE.
"""

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import IntegrationContext
from app.core.config import settings
from app.core.exceptions import (
    RateLimitExceededException,
    SecurityServiceUnavailableException,
    SessionNotFoundException,
)
from app.core.logging import logger
from app.core.metrics import metrics
from app.core.redis import redis_manager
from app.engines.action.action_risk import ActionRiskEngine
from app.engines.policy.policy_engine import PolicyEngine
from app.engines.risk.session_confidence import SessionConfidenceEngine
from app.repositories.incidents import IncidentRepository
from app.repositories.profiles import ProfileRepository
from app.repositories.risks import RiskRepository
from app.repositories.sessions import SessionRepository
from app.schemas.risk import RiskEvaluationRequest, RiskEvaluationResponse
from app.services.audit_service import AuditService
from app.services.behavioral_service import BehavioralService
from app.services.incident_service import IncidentService


class RiskService:
    def __init__(
        self, db: AsyncSession, tenant_id: str, integration: Optional[IntegrationContext] = None
    ):
        self.db = db
        self.tenant_id = tenant_id
        self.integration = integration
        self.session_repo = SessionRepository(db, tenant_id)
        self.profile_repo = ProfileRepository(db, tenant_id)
        self.risk_repo = RiskRepository(db, tenant_id)
        self.incident_repo = IncidentRepository(db, tenant_id)
        self.incident_svc = IncidentService(db, tenant_id, integration)
        self.behavioral = BehavioralService(db, tenant_id, integration)
        self.audit = AuditService(db, tenant_id, integration)

    async def evaluate(self, request: RiskEvaluationRequest) -> RiskEvaluationResponse:
        allowed = await redis_manager.check_rate_limit(
            self.tenant_id,
            settings.RATE_LIMIT_RISK_PER_MINUTE,
            scope="tenant",
        )
        if not allowed:
            raise RateLimitExceededException(scope="risk")

        try:
            return await self._evaluate_inner(request)
        except (SessionNotFoundException, RateLimitExceededException):
            raise
        except Exception as exc:
            logger.error(f"Risk evaluation failed: {exc}", exc_info=True)
            metrics.incr("risk_evaluation_errors")
            raise SecurityServiceUnavailableException(
                "risk-engine",
                (
                    "Risk evaluation could not be completed safely; "
                    "sensitive actions require customer fail-safe handling."
                ),
            ) from None

    async def _evaluate_inner(self, request: RiskEvaluationRequest) -> RiskEvaluationResponse:
        sess = await self.session_repo.get_by_session_id(request.session_id)
        if not sess:
            raise SessionNotFoundException(request.session_id)
        if sess.status in ("TERMINATED", "ISOLATED"):
            return await self._isolated_response(sess, "SESSION_TERMINATED")

        open_incidents = await self.incident_repo.get_open_incidents(request.session_id)
        has_open_incident = len(open_incidents) > 0

        behavior = await self.behavioral.get_behavioral_evidence(sess)

        device_matched, device_evidence_available = await self._device_evidence(sess, behavior)
        network_suspicious, network_evidence_available = self._network_evidence()

        reason_codes = list(behavior["anomaly_reasons"])
        if behavior["significant_drift"]:
            reason_codes = list(dict.fromkeys(reason_codes + ["SIGNIFICANT_DRIFT"]))

        session_confidence, confidence_level, conf_reasons = (
            SessionConfidenceEngine.calculate_confidence(
                anomaly_score=behavior["anomaly_score"],
                is_cold_start=behavior["is_cold_start"],
                device_matched=device_matched,
                device_evidence_available=device_evidence_available,
                network_suspicious=network_suspicious,
                network_evidence_available=network_evidence_available,
                session_history_signal=behavior["session_history_signal"],
                open_incident=has_open_incident,
            )
        )
        reason_codes = list(dict.fromkeys(reason_codes + conf_reasons))

        action_risk, action_reason = ActionRiskEngine.evaluate_action_risk(
            action_type=request.action.type,
            amount=request.action.amount,
            currency=request.action.currency,
        )
        if action_reason:
            reason_codes = list(dict.fromkeys(reason_codes + [action_reason]))
        if action_risk.value == "CRITICAL":
            reason_codes = list(dict.fromkeys(reason_codes + ["ACTION_RISK_CRITICAL"]))

        # Hysteresis: enforce cooldowns to prevent allow/block/allow flapping.
        previous_state = await redis_manager.get_decision_state(self.tenant_id, request.session_id)

        decision, rule_id, reason_codes = PolicyEngine.decide(
            session_confidence=session_confidence,
            action_risk=action_risk,
            reason_codes=reason_codes,
            open_incident=has_open_incident,
            policy_version=settings.POLICY_VERSION,
        )

        decision, rule_id, reason_codes = self._apply_hysteresis(
            previous_state, decision, rule_id, reason_codes
        )

        await self._persist_and_react(
            request,
            sess,
            action_risk.value,
            session_confidence,
            confidence_level,
            decision.value,
            rule_id,
            reason_codes,
            behavior,
        )

        decision_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=settings.HYSTERESIS_COOLDOWN_SECONDS
        )
        metrics.incr("risk_evaluations")
        metrics.incr(f"decision_{decision.value}")

        await self.audit.log(
            event_type=self._event_for_decision(decision.value),
            resource_type="ACTION",
            resource_id=request.action.type,
            metadata={
                "session_id": request.session_id,
                "decision": decision.value,
                "session_confidence": session_confidence,
                "action_risk": action_risk.value,
                "reason_codes": reason_codes,
                "policy_version": settings.POLICY_VERSION,
                "rule_id": rule_id,
            },
        )

        return RiskEvaluationResponse(
            decision=decision.value,
            session_confidence=session_confidence,
            confidence_level=confidence_level,
            action_risk=action_risk,
            reason_codes=reason_codes,
            policy_version=settings.POLICY_VERSION,
            policy_rule_id=rule_id,
            decision_id=decision_id,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
            decision_expires_at=expires_at.isoformat(),
        )

    async def _persist_and_react(
        self,
        request: RiskEvaluationRequest,
        sess,
        action_risk: str,
        session_confidence: int,
        confidence_level: str,
        decision: str,
        rule_id: str,
        reason_codes: List[str],
        behavior: Dict,
    ) -> None:
        action_rec = await self.risk_repo.record_action_request(
            session_id=request.session_id,
            action_type=request.action.type,
            risk_level=action_risk,
            amount=request.action.amount,
            currency=request.action.currency,
            resource_type=request.action.resource_type,
            resource_id=request.action.resource_id,
        )
        await self.risk_repo.record_assessment(
            session_id=request.session_id,
            behavior_signal=max(0.0, 1.0 - float(behavior["anomaly_score"])),
            device_signal=0.6 if not behavior["is_cold_start"] else 0.5,
            network_signal=0.85,
            session_history_signal=float(behavior["session_history_signal"]),
            session_confidence=session_confidence,
            confidence_level=confidence_level,
        )
        await self.risk_repo.record_decision(
            session_id=request.session_id,
            decision=decision,
            reason_codes=reason_codes,
            action_id=action_rec.action_id,
            policy_version=settings.POLICY_VERSION,
            policy_rule_id=rule_id,
        )
        await redis_manager.set_decision_state(
            self.tenant_id, request.session_id, decision, session_confidence
        )

        if decision == "ISOLATE":
            await self.incident_svc.create_incident(
                session_id=request.session_id,
                severity="CRITICAL",
                trigger_reason=", ".join(reason_codes) or "ISOLATE decision",
                decision_id=None,
            )
            await self.session_repo.update_status(request.session_id, "ISOLATED")
            logger.warning(f"Session {request.session_id} ISOLATED: {reason_codes}")

        elif decision == "BLOCK":
            await self.session_repo.update_status(request.session_id, "ACTIVE")

    async def _device_evidence(self, sess, behavior: Dict) -> Tuple[bool, bool]:
        if not sess.device_id:
            return False, False
        if sess.subject_id:
            profile = await self.profile_repo.get_by_subject_device(sess.subject_id, sess.device_id)
            if profile:
                return profile.device_id == sess.device_id, True
        return False, True

    @staticmethod
    def _network_evidence() -> Tuple[bool, bool]:
        # No threat-intelligence integration in Phase 2; unknown is not suspicious.
        return False, False

    @staticmethod
    def _apply_hysteresis(
        previous_state: Optional[Dict],
        decision,
        rule_id: str,
        reason_codes: List[str],
    ):
        """Prevents flapping around security states."""
        if not previous_state or "decision" not in previous_state:
            return decision, rule_id, reason_codes

        previous = previous_state["decision"]
        at = float(previous_state.get("at", 0.0))
        elapsed = time.time() - at
        cooldown = settings.HYSTERESIS_COOLDOWN_SECONDS

        if (
            previous in ("BLOCK", "ISOLATE")
            and decision.value in ("ALLOW", "STEP_UP")
            and elapsed < cooldown
        ):
            reason_codes = list(dict.fromkeys(reason_codes + ["HYSTERESIS_HOLD"]))
            from app.engines.policy.policy_types import SecurityDecisionEnum

            return SecurityDecisionEnum(previous), "hysteresis-hold", reason_codes

        if (
            previous == "STEP_UP"
            and decision.value == "ALLOW"
            and elapsed < settings.HYSTERESIS_ESCALATION_COOLDOWN_SECONDS
        ):
            reason_codes = list(dict.fromkeys(reason_codes + ["HYSTERESIS_HOLD"]))
            from app.engines.policy.policy_types import SecurityDecisionEnum

            return SecurityDecisionEnum.STEP_UP, "hysteresis-hold", reason_codes

        return decision, rule_id, reason_codes

    async def _isolated_response(self, sess, reason: str) -> RiskEvaluationResponse:
        return RiskEvaluationResponse(
            decision="ISOLATE",
            session_confidence=0,
            confidence_level="LOW",
            action_risk=ActionRiskEngine.evaluate_action_risk("VIEW_PROFILE")[0],
            reason_codes=["SESSION_ISOLATED", reason],
            policy_version=settings.POLICY_VERSION,
            policy_rule_id="incident-isolate",
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )

    @staticmethod
    def _event_for_decision(decision: str) -> str:
        if decision == "ALLOW":
            return "RISK_EVALUATED"
        if decision == "STEP_UP":
            return "STEP_UP_REQUIRED"
        if decision == "BLOCK":
            return "SESSION_BLOCKED"
        return "SESSION_ISOLATED"
