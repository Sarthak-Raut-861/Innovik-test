"""TRUSTPULSE — Policy engine.

Turns (session trust, action risk) into a decision. This is the *reasoning*
half of authorization; the Policy Enforcement Point (`services/enforcement`) is
the half that actually enforces it and is the only component allowed to do so.

Design constraints:

* **Deterministic.** Same inputs → same decision, every time. No model calls, no
  randomness, no wall-clock dependence beyond explicit TTLs.
* **Data-driven.** The rules live in `shared/constants/trust_model.json` under
  `authorization.rules` and are evaluated in order; the first match wins. An
  operator can re-tune enforcement without touching this file.
* **Total.** Validation at config load guarantees the final rule is a catch-all,
  so every request gets a decision. A policy that can silently fall through
  would be a fail-open security bug.
* **Explainable.** Every decision names the rule that produced it and carries
  the rule's human-readable reason, because "why was I blocked?" must be
  answerable by the SOC and by the end user.

The AI/ML layer never appears here. Anomaly scores influence the *TCI*, and the
TCI influences this decision — but no model output is ever consulted directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.trust_config import TrustModelConfig, get_trust_config

VALID_DECISIONS = ("ALLOW", "STEP_UP", "BLOCK", "REVOKE", "CONTAIN")

# Severity ordering, used for the "most restrictive wins" tie-break.
DECISION_SEVERITY = {
    "ALLOW": 0,
    "STEP_UP": 1,
    "BLOCK": 2,
    "REVOKE": 3,
    "CONTAIN": 4,
}


@dataclass(frozen=True)
class PolicyFacts:
    """Everything the policy may look at.

    Deliberately flat and immutable: the policy must not reach into the session
    or the trust engine, or it becomes impossible to reason about — or to test —
    in isolation.
    """

    tci: float
    trust_state: str
    action_risk: int
    session_status: str = "ACTIVE"
    is_contained: bool = False
    session_revoked: bool = False
    open_incident: bool = False
    step_up_attempts: int = 0
    mfa_used: bool = False
    confidence: str = "LOW"
    context: Dict[str, Any] = field(default_factory=dict)

    def describe(self) -> Dict[str, Any]:
        return {
            "tci": round(self.tci, 2),
            "trust_state": self.trust_state,
            "action_risk": self.action_risk,
            "session_status": self.session_status,
            "is_contained": self.is_contained,
            "session_revoked": self.session_revoked,
            "open_incident": self.open_incident,
            "step_up_attempts": self.step_up_attempts,
            "mfa_used": self.mfa_used,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class PolicyDecision:
    """The decision, plus the audit trail explaining it."""

    decision: str
    rule_id: str
    reason: str
    policy_version: str
    facts: Dict[str, Any]
    risk_band: str
    considered: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def blocked(self) -> bool:
        return self.decision in ("BLOCK", "REVOKE", "CONTAIN")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "risk_band": self.risk_band,
            "facts": self.facts,
            "considered": self.considered,
            "warnings": self.warnings,
        }


def band_for_risk(risk: int) -> str:
    """Risk band labels. Mirrors `RISK_BANDS` in the action-risk catalogue."""
    if risk >= 85:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    return "LOW"


class PolicyEngine:
    """Evaluates the configured policy rules against a set of facts."""

    def __init__(self, config: Optional[TrustModelConfig] = None) -> None:
        self.config = config or get_trust_config()
        self._rules = self.config.policy_rules()
        if not self._rules:
            # Fail closed rather than fail open if the policy is somehow empty.
            raise ValueError("authorization policy has no rules; refusing to authorize anything")

    @property
    def policy_version(self) -> str:
        return self.config.policy_version

    def rules(self) -> List[Dict[str, Any]]:
        return [dict(rule) for rule in self._rules]

    def evaluate(self, facts: PolicyFacts) -> PolicyDecision:
        """Returns the first matching rule's decision.

        The TCI floor is applied as a hard guard *before* rule evaluation so that
        a mis-ordered or over-permissive rule set cannot authorise a session whose
        trust has collapsed. It is defence in depth on top of the rules, not a
        substitute for them.
        """
        warnings: List[str] = []
        considered: List[Dict[str, Any]] = []

        floor_decision = self._apply_tci_floor(facts, warnings)
        if floor_decision is not None:
            considered.append({"rule_id": "TCI_FLOOR_GUARD", "matched": True})
            return floor_decision

        for rule in self._rules:
            matched, why_not = self._match(rule, facts)
            considered.append(
                {
                    "rule_id": rule.get("id"),
                    "decision": rule.get("decision"),
                    "matched": matched,
                    **({} if matched else {"skipped": why_not}),
                }
            )
            if matched:
                return PolicyDecision(
                    decision=str(rule.get("decision")),
                    rule_id=str(rule.get("id")),
                    reason=str(rule.get("reason", "")),
                    policy_version=self.policy_version,
                    facts=facts.describe(),
                    risk_band=band_for_risk(facts.action_risk),
                    considered=considered,
                    warnings=warnings,
                )

        # Unreachable for a validated config (the catch-all is mandatory), but
        # fail closed if someone disables validation.
        warnings.append("POLICY_HAS_NO_MATCHING_RULE")
        return PolicyDecision(
            decision="BLOCK",
            rule_id="NO_MATCHING_RULE",
            reason="No policy rule matched; failing closed",
            policy_version=self.policy_version,
            facts=facts.describe(),
            risk_band=band_for_risk(facts.action_risk),
            considered=considered,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ internals
    def _apply_tci_floor(self, facts: PolicyFacts, warnings: List[str]) -> Optional[PolicyDecision]:
        """Hard floor guard, independent of the rule list."""
        floor = self.config.tci_block_floor
        min_risk = self.config.tci_block_floor_min_risk
        if facts.tci > floor or facts.action_risk < min_risk:
            return None
        warnings.append("TCI_BELOW_AUTHORIZATION_FLOOR")
        return PolicyDecision(
            decision="BLOCK",
            rule_id="TCI_FLOOR_GUARD",
            reason=(
                f"TCI {facts.tci:.1f} is at or below the authorization floor "
                f"({floor:.0f}) for action risk {facts.action_risk}"
            ),
            policy_version=self.policy_version,
            facts=facts.describe(),
            risk_band=band_for_risk(facts.action_risk),
            considered=[],
            warnings=warnings,
        )

    def _match(self, rule: Dict[str, Any], facts: PolicyFacts) -> tuple:
        """Tests one rule. Returns (matched, reason_not_matched)."""
        requires = rule.get("requires") or {}
        if not requires:
            return True, ""

        for key, expected in requires.items():
            ok, detail = self._test_predicate(key, expected, facts)
            if not ok:
                return False, detail
        return True, ""

    @staticmethod
    def _test_predicate(key: str, expected: Any, facts: PolicyFacts) -> tuple:
        if key == "trust_state_in":
            states = {str(s) for s in (expected or [])}
            if facts.trust_state in states:
                return True, ""
            return False, f"trust_state {facts.trust_state} not in {sorted(states)}"

        if key == "trust_state_not_in":
            states = {str(s) for s in (expected or [])}
            if facts.trust_state not in states:
                return True, ""
            return False, f"trust_state {facts.trust_state} is in {sorted(states)}"

        if key == "min_action_risk":
            if facts.action_risk >= float(expected):
                return True, ""
            return False, f"action_risk {facts.action_risk} < {expected}"

        if key == "max_action_risk":
            if facts.action_risk <= float(expected):
                return True, ""
            return False, f"action_risk {facts.action_risk} > {expected}"

        if key == "min_tci":
            if facts.tci >= float(expected):
                return True, ""
            return False, f"tci {facts.tci:.1f} < {expected}"

        if key == "max_tci":
            if facts.tci <= float(expected):
                return True, ""
            return False, f"tci {facts.tci:.1f} > {expected}"

        if key == "session_status":
            if facts.session_status == str(expected):
                return True, ""
            return False, f"session_status {facts.session_status} != {expected}"

        if key == "session_status_not":
            if facts.session_status != str(expected):
                return True, ""
            return False, f"session_status is {expected}"

        if key == "contained":
            if bool(facts.is_contained) is bool(expected):
                return True, ""
            return False, f"is_contained={facts.is_contained} != {expected}"

        if key == "session_revoked":
            if bool(facts.session_revoked) is bool(expected):
                return True, ""
            return False, f"session_revoked={facts.session_revoked} != {expected}"

        if key == "open_incident":
            if bool(facts.open_incident) is bool(expected):
                return True, ""
            return False, f"open_incident={facts.open_incident} != {expected}"

        if key == "mfa_used":
            if bool(facts.mfa_used) is bool(expected):
                return True, ""
            return False, f"mfa_used={facts.mfa_used} != {expected}"

        if key == "min_step_up_attempts":
            if facts.step_up_attempts >= int(expected):
                return True, ""
            return False, f"step_up_attempts {facts.step_up_attempts} < {expected}"

        if key == "confidence_in":
            levels = {str(item) for item in (expected or [])}
            if facts.confidence in levels:
                return True, ""
            return False, f"confidence {facts.confidence} not in {sorted(levels)}"

        if key == "context_equals":
            for context_key, context_value in (expected or {}).items():
                if facts.context.get(context_key) != context_value:
                    return False, f"context[{context_key}] != {context_value!r}"
            return True, ""

        # An unknown predicate must not silently pass — that would let a typo in
        # the config weaken enforcement.
        return False, f"unknown predicate {key!r}"


__all__ = [
    "PolicyEngine",
    "PolicyFacts",
    "PolicyDecision",
    "band_for_risk",
    "VALID_DECISIONS",
    "DECISION_SEVERITY",
]
