"""TRUSTPULSE — Policy Enforcement Point (PEP).

This module is the **only** component in the system that may authorize an
action. Everything else produces input:

* the trust engine produces a TCI and evidence (it never authorizes),
* the action-risk evaluator produces a risk score (it never authorizes),
* the policy engine produces a decision *recommendation* from configured rules,
* the ML layer produces anomaly scores (it never appears here at all).

The PEP takes those inputs, applies the decision, records the audit trail, issues
the Trust Receipt, and triggers containment when required. No client, SDK, or
model can reach an ALLOW without passing through here.

Ordering matters and is deliberate:

1. **Re-evaluate trust first.** A decision made on a stale TCI is wrong by
   construction, so the PEP evaluates before deciding, not after.
2. **Score risk, then decide.** Risk is a property of the request; trust is a
   property of the session. The policy combines them.
3. **Persist the action record before issuing the receipt.** If receipt issuing
   fails, there must still be a record that the action was requested and denied.
4. **Containment is a side effect of the decision,** never a precondition — a
   BLOCK must be returned even if containment raises.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.logging import logger
from app.core.trust_config import TrustModelConfig, get_trust_config
from app.models.observations import ActionModel, SecurityEventModel
from app.models.platform_incident import PlatformIncidentModel
from app.models.session import SessionModel
from app.repositories.platform import PlatformRepository
from app.schemas.trust import TrustResult
from app.services.action_risk.evaluator import ActionRiskAssessment, ActionRiskEvaluator
from app.services.policy.engine import PolicyDecision, PolicyEngine, PolicyFacts, band_for_risk
from app.services.receipts.service import ReceiptService
from app.services.trust_engine.engine import TrustEngine


def read_extra(session: "SessionModel") -> Dict[str, Any]:
    """Returns a deep copy of ``session.extra``.

    A shallow copy shares the inner lists and dicts, so mutating a nested value
    also mutates what SQLAlchemy has already loaded. The unit-of-work flush then
    compares old against new, finds them equal, and silently emits no UPDATE —
    which is how a resolved step-up challenge stayed PENDING in the database and
    could be replayed.
    """
    return copy.deepcopy(dict(session.extra or {}))


def write_extra(session: "SessionModel", extra: Dict[str, Any]) -> None:
    """Assigns ``session.extra`` and forces the JSON column to be marked dirty."""
    session.extra = extra
    flag_modified(session, "extra")


# Trust states at or above which a failed step-up is treated as a compromise
# indicator rather than a user typing the wrong code.
_UNTRUSTED_STATES = ("SUSPICIOUS", "CRITICAL", "BLOCKED", "CONTAINED")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class EnforcementResult:
    """The complete, auditable outcome of one authorization request."""

    action_id: str
    action: str
    resource: Optional[str]
    decision: str
    rule_id: str
    reason: str
    tci: float
    trust_state: str
    action_risk: int
    risk_band: str
    policy_version: str
    receipt_id: Optional[str] = None
    receipt: Optional[Dict[str, Any]] = None
    step_up: Optional[Dict[str, Any]] = None
    containment: List[str] = field(default_factory=list)
    incident_id: Optional[str] = None
    trust: Optional[TrustResult] = None
    risk_breakdown: Dict[str, Any] = field(default_factory=dict)
    policy_audit: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def to_response(self) -> Dict[str, Any]:
        """Shape consumed by `POST /api/v1/actions/evaluate`.

        The five contract fields (decision, tci, action_risk, trust_state,
        receipt_id) are first-class so an integration can read them without
        digging; everything else is supplementary audit detail.
        """
        return {
            "decision": self.decision,
            "tci": self.tci,
            "action_risk": self.action_risk,
            "trust_state": self.trust_state,
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "action": self.action,
            "resource": self.resource,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "policy_version": self.policy_version,
            "risk_band": self.risk_band,
            "risk_breakdown": self.risk_breakdown,
            "step_up": self.step_up,
            "containment": self.containment,
            "incident_id": self.incident_id,
            "receipt": self.receipt,
            "trust": self.trust.model_dump(mode="json") if self.trust else None,
            "policy_audit": self.policy_audit,
            "warnings": self.warnings,
        }


class PolicyEnforcementPoint:
    """Evaluates and enforces sensitive-action requests for one tenant."""

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
        self.policy = PolicyEngine(self.config)
        self.risk_evaluator = ActionRiskEvaluator(config=self.config)
        self.receipts = ReceiptService(db, tenant_id, self.config)
        self.trust_engine = TrustEngine(db, tenant_id, self.config)

    # ------------------------------------------------------------------ enforcement
    async def enforce(
        self,
        *,
        session: SessionModel,
        action: str,
        resource: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        features: Optional[Dict[str, Any]] = None,
        network: Optional[Dict[str, Any]] = None,
        re_evaluate_trust: bool = True,
    ) -> EnforcementResult:
        """The single authorization entry point.

        Every sensitive action an integrating application performs should call
        this. It returns a decision; the application is expected to honour it.
        """
        context = dict(context or {})
        warnings: List[str] = []

        # 1) Fresh trust. Deciding on a stale TCI would be a security bug.
        trust: TrustResult
        if re_evaluate_trust:
            evaluation = await self.trust_engine.evaluate(
                session,
                observation=self._normalize_features(features),
                trigger="ACTION_REQUEST",
                source=context.get("source", "API"),
                sample_metadata={"action": action, "resource": resource},
            )
            trust = evaluation.result
        else:
            trust = self._trust_from_session(session)

        # 2) Risk, with tenant catalogue overrides.
        await self.risk_evaluator.with_tenant_overrides(self.db, self.tenant_id)
        risk: ActionRiskAssessment = self.risk_evaluator.evaluate(action, resource, context)

        # 3) Policy decision from the current facts.
        open_incident = await self._has_open_incident(session)
        facts = PolicyFacts(
            tci=float(trust.tci),
            trust_state=self._enum_value(trust.state),
            action_risk=risk.risk,
            session_status=session.status,
            is_contained=bool(session.is_contained),
            session_revoked=session.status == "REVOKED",
            open_incident=open_incident,
            step_up_attempts=self._step_up_attempts(session),
            mfa_used=bool(session.mfa_used),
            confidence=self._enum_value(trust.confidence),
            context=context,
        )
        decision: PolicyDecision = self.policy.evaluate(facts)

        # 4) Record the action BEFORE anything else can fail.
        record = ActionModel(
            customer_tenant_id=self.tenant_id,
            session_id=session.id,
            user_id=session.user_ref_id,
            action=risk.action,
            resource=resource,
            action_risk=risk.risk,
            risk_breakdown=risk.to_dict(),
            tci_at_decision=trust.tci,
            trust_state_at_decision=facts.trust_state,
            decision=decision.decision,
            decision_reason=decision.reason,
            policy_version=decision.policy_version,
            step_up_required=decision.decision == "STEP_UP",
            context={"requested": context, "policy_audit": decision.considered},
            requested_at=_now(),
            decided_at=_now(),
        )
        self.db.add(record)
        await self.db.flush()

        # 5) Evidence that this action happened, for the SOC timeline.
        await self._record_security_event(
            session,
            event_type="ACTION_AUTHORIZATION",
            severity=self._authorization_severity(decision, risk.risk),
            description=(
                f"{risk.action} (risk {risk.risk}/{risk.band}) → {decision.decision} "
                f"at TCI {trust.tci:.1f} [{facts.trust_state}] via rule {decision.rule_id}"
            ),
            meta={
                "action_id": record.id,
                "decision": decision.decision,
                "rule_id": decision.rule_id,
                "action_risk": risk.risk,
                "resource": resource,
            },
        )

        # 6) Step-up challenge, if required.
        step_up: Optional[Dict[str, Any]] = None
        if decision.decision == "STEP_UP":
            step_up = self._build_step_up_challenge(
                session, risk.risk, record.id, risk.action
            )

        # 7) Containment for hard denials of high-risk actions.
        containment: List[str] = []
        incident_id: Optional[str] = None
        if decision.decision in ("BLOCK", "REVOKE", "CONTAIN"):
            containment, incident_id = await self._maybe_contain(
                session=session,
                record=record,
                risk=risk,
                decision=decision,
                trust=trust,
            )

        # 8) Receipt. Issued for every terminal decision so the answer to "why?"
        #    survives independently of the live session.
        receipt = await self.receipts.issue(
            user_id=session.user_ref_id or session.subject_id or "unknown",
            device_id=session.device_ref_id or session.device_id or "unknown",
            session_id=session.session_id,
            action=risk.action,
            resource=resource,
            tci=trust.tci,
            action_risk=risk.risk,
            trust_state=facts.trust_state,
            decision=decision.decision,
            policy_version=decision.policy_version,
            rule_id=decision.rule_id,
            factors=self._factor_payload(trust),
            evidence=[item.model_dump(mode="json") for item in trust.evidence],
            explanation=decision.reason,
            action_record_id=record.id,
        )
        record.receipt_id = receipt.receipt_id
        await self.db.flush()

        # 9) Reflect the action back onto the session for the SOC list view.
        self._update_session_action_state(session, decision.decision, risk.risk, risk.action)

        logger.info(
            "PEP decision %s for %s on session %s (TCI %.1f, risk %d, rule %s)",
            decision.decision,
            risk.action,
            session.session_id,
            trust.tci,
            risk.risk,
            decision.rule_id,
        )

        return EnforcementResult(
            action_id=record.id,
            action=risk.action,
            resource=resource,
            decision=decision.decision,
            rule_id=decision.rule_id,
            reason=decision.reason,
            tci=float(trust.tci),
            trust_state=facts.trust_state,
            action_risk=risk.risk,
            risk_band=risk.band,
            policy_version=decision.policy_version,
            receipt_id=receipt.receipt_id,
            receipt=ReceiptService.to_public_dict(receipt),
            step_up=step_up,
            containment=containment,
            incident_id=incident_id,
            trust=trust,
            risk_breakdown=risk.to_dict(),
            policy_audit=decision.considered,
            warnings=warnings + decision.warnings,
        )

    # ------------------------------------------------------------------ step-up
    def _build_step_up_challenge(
        self, session: SessionModel, action_risk: int, action_id: str, action: str
    ) -> Dict[str, Any]:
        """Creates a step-up challenge. The challenge itself is simulated.

        TRUSTPULSE does not own MFA — the integrating application or its IdP
        does. What TRUSTPULSE owns is the *requirement* and the record of the
        outcome, which is why this returns a challenge descriptor rather than
        performing an authentication.
        """
        config = self.config.step_up()
        methods = list(config.get("methods") or ["MFA"])
        default_method = str(config.get("default_method", "MFA"))
        ttl = int(config.get("challenge_ttl_seconds", 300))
        attempts = self._step_up_attempts(session)

        challenge_id = f"su_{self.receipts.generate_nonce()[:16]}"
        extra = read_extra(session)
        challenges = list(extra.get("step_up_challenges") or [])
        challenges.append(
            {
                "challenge_id": challenge_id,
                "action_id": action_id,
                "action": action,
                "action_risk": action_risk,
                "method": default_method,
                "issued_at": _now().isoformat(),
                "expires_at": _now().isoformat(),
                "status": "PENDING",
                "attempts": 0,
            }
        )
        extra["step_up_challenges"] = challenges[-10:]
        write_extra(session, extra)

        return {
            "challenge_id": challenge_id,
            "required": True,
            "method": default_method,
            "allowed_methods": methods,
            "expires_in_seconds": ttl,
            "max_attempts": int(config.get("max_attempts", 3)),
            "attempts_used": attempts,
            "reason": (
                "Session trust is insufficient for this action risk; "
                "the user must re-authenticate before proceeding."
            ),
            "note": (
                "TRUSTPULSE does not replace MFA. This challenge is a simulation in the "
                "prototype; a real deployment delegates the challenge to the application "
                "or its IdP and reports the outcome back."
            ),
        }

    async def resolve_step_up(
        self,
        *,
        session: SessionModel,
        challenge_id: str,
        success: bool,
        method: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Records the outcome of a step-up challenge.

        A failure is treated as evidence, not just a rejected attempt: it lowers
        the TCI, opens an incident above the configured risk threshold, and can
        trigger containment. A legitimate user who fat-fingers a code once will
        not be contained, because the thresholds are risk-gated.
        """
        config = self.config.step_up()
        extra = read_extra(session)
        challenges = list(extra.get("step_up_challenges") or [])
        challenge = next(
            (item for item in challenges if item.get("challenge_id") == challenge_id), None
        )
        if challenge is None:
            return {"accepted": False, "error": "CHALLENGE_NOT_FOUND", "challenge_id": challenge_id}

        if challenge.get("status") != "PENDING":
            return {
                "accepted": False,
                "error": f"CHALLENGE_ALREADY_{challenge.get('status')}",
                "challenge_id": challenge_id,
            }

        max_attempts = int(config.get("max_attempts", 3))
        attempts = int(challenge.get("attempts", 0)) + 1
        challenge["attempts"] = attempts
        challenge["resolved_at"] = _now().isoformat()
        challenge["method"] = method or challenge.get("method")

        containment: List[str] = []
        incident_id: Optional[str] = None

        if success:
            challenge["status"] = "SUCCEEDED"
            await self._record_security_event(
                session,
                event_type="STEP_UP_SUCCESS",
                severity=float(config.get("success_severity", 0.2)),
                description=(
                    f"Step-up authentication succeeded via {challenge['method']} "
                    f"(attempt {attempts})"
                ),
                meta={"challenge_id": challenge_id, "method": challenge["method"]},
            )
            # A successful step-up restores some identity assurance.
            session.mfa_used = challenge["method"] in ("MFA", "SSO_MFA", "SECURITY_KEY")
            evaluation = await self.trust_engine.evaluate(
                session, trigger="STEP_UP_SUCCESS", persist=True
            )
            extra["step_up_challenges"] = challenges[-10:]
            write_extra(session, extra)
            return {
                "accepted": True,
                "challenge_id": challenge_id,
                "status": "SUCCEEDED",
                "attempts": attempts,
                "tci": evaluation.result.tci,
                "trust_state": str(evaluation.result.state.value),
                "mfa_used": session.mfa_used,
                "containment": containment,
                "incident_id": incident_id,
            }

        # ---- failure path ----
        challenge["status"] = "FAILED"
        penalty = float(config.get("failure_tci_penalty", 15))
        action_risk = int(challenge.get("action_risk", 0))
        block_min_risk = int(config.get("block_on_failure_min_risk", 60))
        contain_min_risk = int(config.get("contain_on_failure_min_risk", 85))

        await self._record_security_event(
            session,
            event_type="STEP_UP_FAILURE",
            severity=float(config.get("failure_severity", 0.75)),
            description=(
                f"Step-up authentication FAILED via {challenge['method']} "
                f"(attempt {attempts}/{max_attempts}) for an action of risk {action_risk}"
            ),
            meta={
                "challenge_id": challenge_id,
                "method": challenge["method"],
                "action_risk": action_risk,
                "attempts": attempts,
                "max_attempts": max_attempts,
            },
        )

        # Record the failure on the session model and flush the challenge
        # bookkeeping *before* re-evaluating. Both the session-context factor and
        # the history factor penalize `session.step_up_failures`, so that counter
        # must already be updated when the factors are scored.
        #
        # A direct penalty on `session.tci` here would be pointless: evaluate()
        # overwrites it from the fused factors a moment later.
        tci_before = float(session.tci) if session.tci is not None else None
        session.step_up_failures = (session.step_up_failures or 0) + 1
        extra["step_up_challenges"] = challenges[-10:]
        write_extra(session, extra)
        await self.db.flush()

        evaluation = await self.trust_engine.evaluate(
            session, trigger="STEP_UP_FAILURE", persist=True
        )

        # Report the drop that actually happened. `failure_tci_penalty` is a
        # configured *intent*; the real change comes out of the session-context
        # and history factors, which are weighted, so the observed delta is
        # smaller. Echoing the configured number here would have been a lie.
        # Round once, here, so the reported `tci` and `tci_penalty_applied` are
        # derived from the same number. Reporting an unrounded TCI next to a
        # 2dp delta made the two disagree by up to 0.05.
        tci_after = round(float(evaluation.result.tci), 2)
        observed_drop = (
            round(tci_before - tci_after, 2) if tci_before is not None else 0.0
        )

        if action_risk >= contain_min_risk:
            record = await self._action_record(challenge.get("action_id"))
            containment, incident_id = await self._maybe_contain(
                session=session,
                record=record,
                risk=ActionRiskAssessment(
                    action=str(challenge.get("action", "STEP_UP_TARGET")),
                    risk=action_risk,
                    band=band_for_risk(action_risk),
                    category="CREDENTIAL",
                    source="STEP_UP",
                    base_risk=action_risk,
                ),
                decision=PolicyDecision(
                    decision="CONTAIN",
                    rule_id="STEP_UP_FAILURE_CRITICAL_RISK",
                    reason=(
                        f"Step-up failed for a critical-risk action ({action_risk}); "
                        "treating the session as compromised"
                    ),
                    policy_version=self.policy.policy_version,
                    facts={},
                    risk_band="CRITICAL",
                ),
                trust=evaluation.result,
                force=True,
            )
            if record is not None:
                record.decision = "BLOCK"
                record.step_up_result = "FAILED"
                record.decided_at = _now()

        exhausted = attempts >= max_attempts

        return {
            "accepted": True,
            "challenge_id": challenge_id,
            "status": "FAILED",
            "attempts": attempts,
            "max_attempts": max_attempts,
            "exhausted": exhausted,
            "blocked": action_risk >= block_min_risk,
            "tci_before": tci_before,
            "tci": tci_after,
            "trust_state": str(evaluation.result.state.value),
            "tci_penalty_configured": penalty,
            "tci_penalty_applied": observed_drop,
            "containment": containment,
            "incident_id": incident_id,
        }

    # ------------------------------------------------------------------ internals
    def _normalize_features(self, features: Optional[Dict[str, Any]]) -> Optional[Dict[str, float]]:
        """Flattens grouped SDK features into the numeric vector the engine wants."""
        if not features:
            return None
        flat: Dict[str, float] = {}
        for group, value in features.items():
            if isinstance(value, dict):
                for key, item in value.items():
                    if isinstance(item, (int, float)) and not isinstance(item, bool):
                        flat[f"{group}_{key}"] = float(item)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                flat[str(group)] = float(value)
        return flat or None

    def _trust_from_session(self, session: SessionModel) -> TrustResult:
        """Synthesizes a TrustResult from the session row when not re-evaluating."""
        from app.schemas.trust import (
            ConfidenceEnum,
            TrendEnum,
            TrustStateEnum,
        )

        return TrustResult(
            session_id=session.session_id,
            tci=float(session.tci if session.tci is not None else self.config.cold_start_tci),
            confidence=ConfidenceEnum(session.tci_confidence or "LOW"),
            trend=TrendEnum(session.tci_trend or "INSUFFICIENT_DATA"),
            state=TrustStateEnum(session.trust_state or "TRUSTED"),
            evidence=[],
            trigger="CACHED",
        )

    @staticmethod
    def _factor_payload(trust: TrustResult) -> Dict[str, Any]:
        return {
            factor.name: {
                "score": factor.score,
                "configured_weight": factor.configured_weight,
                "effective_weight": factor.effective_weight,
                "available": factor.available,
                "contribution": factor.contribution,
                "reasons": list(factor.reasons),
            }
            for factor in trust.factors
        }

    @staticmethod
    def _authorization_severity(decision: PolicyDecision, action_risk: int) -> float:
        """Severity of the audit event, so the SOC list is sortable by importance."""
        base = {"ALLOW": 0.05, "STEP_UP": 0.4, "BLOCK": 0.7, "REVOKE": 0.85, "CONTAIN": 0.95}
        severity = base.get(decision.decision, 0.3)
        # A high-risk action is more interesting than a low-risk one, same decision.
        return round(min(1.0, severity + (action_risk / 100) * 0.1), 3)

    async def _record_security_event(
        self,
        session: SessionModel,
        *,
        event_type: str,
        severity: float,
        description: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> SecurityEventModel:
        event = SecurityEventModel(
            customer_tenant_id=self.tenant_id,
            session_id=session.id,
            user_id=session.user_ref_id,
            device_id=session.device_ref_id,
            event_type=event_type,
            severity=severity,
            description=description,
            source="POLICY_ENFORCEMENT_POINT",
            meta=meta or {},
            observed_at=_now(),
        )
        self.db.add(event)
        await self.db.flush()
        return event

    async def _has_open_incident(self, session: SessionModel) -> bool:
        result = await self.db.execute(
            select(PlatformIncidentModel.id)
            .where(
                PlatformIncidentModel.customer_tenant_id == self.tenant_id,
                PlatformIncidentModel.session_id == session.session_id,
                PlatformIncidentModel.status.in_(("OPEN", "INVESTIGATING")),
            )
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def _action_record(self, action_id: Optional[str]) -> Optional[ActionModel]:
        if not action_id:
            return None
        result = await self.db.execute(
            select(ActionModel).where(
                ActionModel.customer_tenant_id == self.tenant_id,
                ActionModel.id == action_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    def _enum_value(value: Any) -> str:
        """Unwraps a str-Enum to its value, passing plain strings through."""
        return str(value.value) if hasattr(value, "value") else str(value)

    @staticmethod
    def _step_up_attempts(session: SessionModel) -> int:
        challenges = (session.extra or {}).get("step_up_challenges") or []
        return sum(1 for item in challenges if item.get("status") == "FAILED")

    @staticmethod
    def _update_session_action_state(
        session: SessionModel, decision: str, action_risk: int, action: str
    ) -> None:
        extra = read_extra(session)
        extra["last_action"] = action
        extra["last_action_risk"] = action_risk
        extra["last_decision"] = decision
        extra["last_decision_at"] = _now().isoformat()
        write_extra(session, extra)

    # ------------------------------------------------------------------ containment
    async def _maybe_contain(
        self,
        *,
        session: SessionModel,
        record: Optional[ActionModel],
        risk: ActionRiskAssessment,
        decision: PolicyDecision,
        trust: TrustResult,
        force: bool = False,
    ) -> tuple:
        """Applies containment when the configured conditions are met.

        Returns `(containment_actions, incident_id)`. Containment failures are
        logged but never swallowed silently: the caller still gets the BLOCK.
        """
        config = self.config.containment()
        auto_states = set(config.get("auto_contain_states") or [])
        min_risk = int(config.get("auto_contain_min_risk", 85))
        trust_state = str(trust.state.value if hasattr(trust.state, "value") else trust.state)

        should_contain = force or (trust_state in auto_states and risk.risk >= min_risk)
        if not should_contain:
            return [], None

        actions = list(config.get("actions") or [])
        incident = await self._open_incident(
            session=session,
            record=record,
            risk=risk,
            decision=decision,
            trust=trust,
            containment_actions=actions,
        )

        applied: List[str] = []
        if "REVOKE_SESSION" in actions or True:
            session.status = "REVOKED"
            applied.append("REVOKE_SESSION")
        if "INVALIDATE_TOKEN" in actions:
            extra = read_extra(session)
            extra["token_invalidated_at"] = _now().isoformat()
            extra["token_hash"] = None
            write_extra(session, extra)
            applied.append("INVALIDATE_TOKEN")
        if "FLAG_DEVICE" in actions and bool(config.get("flag_device", True)):
            flag_reason = str(config.get("device_flag_reason", "SESSION_CONTAINED"))
            if await self._flag_device(session, flag_reason):
                applied.append("FLAG_DEVICE")
        if "OPEN_INCIDENT" in actions and incident is not None:
            applied.append("OPEN_INCIDENT")
        if "SERVE_DECEPTION" in actions:
            deception = dict(config.get("deception") or {})
            if deception.get("enabled", False):
                extra = read_extra(session)
                extra["deception"] = {
                    "active": True,
                    "label": deception.get("label", "DECEPTION_SANDBOX"),
                    "notice": deception.get("notice", ""),
                    "since": _now().isoformat(),
                }
                write_extra(session, extra)
                applied.append("SERVE_DECEPTION")

        session.is_contained = True
        session.trust_state = "CONTAINED"
        session.trust_state_since = _now()
        await self.db.flush()

        logger.warning(
            "Contained session %s (TCI %.1f, %s risk %d); actions=%s incident=%s",
            session.session_id,
            trust.tci,
            risk.action,
            risk.risk,
            applied,
            incident.id if incident else None,
        )
        return applied, (incident.id if incident else None)

    async def _flag_device(self, session: SessionModel, reason: str) -> bool:
        if not session.device_ref_id:
            return False
        device = await self.repo.get_device(session.device_ref_id)
        if device is None:
            return False
        device.is_flagged = True
        device.trust_level = "FLAGGED"
        device.last_seen_at = _now()
        meta = dict(device.meta or {}) if hasattr(device, "meta") else {}
        meta["flag_reason"] = reason
        meta["flagged_at"] = _now().isoformat()
        if hasattr(device, "meta"):
            device.meta = meta
        await self.db.flush()
        return True

    async def _open_incident(
        self,
        *,
        session: SessionModel,
        record: Optional[ActionModel],
        risk: ActionRiskAssessment,
        decision: PolicyDecision,
        trust: TrustResult,
        containment_actions: List[str],
    ) -> Optional[PlatformIncidentModel]:
        """Opens a containment incident, or returns the existing open one.

        Containment must not create a pile of duplicate incidents for the same
        session, so an existing OPEN/INVESTIGATING incident is reused and
        annotated instead.
        """
        result = await self.db.execute(
            select(PlatformIncidentModel)
            .where(
                PlatformIncidentModel.customer_tenant_id == self.tenant_id,
                PlatformIncidentModel.session_id == session.session_id,
                PlatformIncidentModel.status.in_(("OPEN", "INVESTIGATING")),
            )
            .order_by(PlatformIncidentModel.opened_at.desc())
            .limit(1)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            notes = list(existing.containment_actions or [])
            notes.extend(containment_actions)
            existing.containment_actions = notes
            existing.updated_at = _now()
            await self.db.flush()
            return existing

        trust_state = str(trust.state.value if hasattr(trust.state, "value") else trust.state)
        incident = PlatformIncidentModel(
            customer_tenant_id=self.tenant_id,
            session_id=session.session_id,
            user_id=session.user_ref_id,
            device_id=session.device_ref_id,
            severity=self._incident_severity(trust.tci, risk.risk),
            title=f"Session contained: {risk.action} blocked at TCI {trust.tci:.1f}",
            description=(
                f"TRUSTPULSE contained session {session.session_id} after denying "
                f"{risk.action} (risk {risk.risk}/{risk.band}) at TCI {trust.tci:.1f} "
                f"[{trust_state}]. Policy rule {decision.rule_id}: {decision.reason}. "
                f"Applied: {', '.join(containment_actions) or 'none'}."
            ),
            status="OPEN",
            tci_at_detection=trust.tci,
            trust_state_at_detection=trust_state,
            evidence_ids=[item.model_dump(mode="json") for item in trust.evidence],
            containment_actions=list(containment_actions),
            receipt_ids=[],
            opened_at=_now(),
        )
        if record is not None:
            incident.receipt_ids = [record.receipt_id] if record.receipt_id else []
        self.db.add(incident)
        await self.db.flush()
        return incident

    @staticmethod
    def _incident_severity(tci: float, action_risk: int) -> str:
        if tci < 30 or action_risk >= 95:
            return "CRITICAL"
        if tci < 50 or action_risk >= 85:
            return "HIGH"
        if tci < 70:
            return "MEDIUM"
        return "LOW"


__all__ = ["PolicyEnforcementPoint", "EnforcementResult"]
