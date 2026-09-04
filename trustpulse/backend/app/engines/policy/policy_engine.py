"""
TrustPulse AI — Deterministic Policy Engine.

The policy engine is the ONLY component allowed to map security evidence to a
final SecurityDecision. Behavioral/risk engines produce evidence, never decisions.

The built-in v1 policy is deliberately conservative:

  * LOW action risk is never blocked on its own.
  * MEDIUM risk requires at least GUARDED confidence; otherwise STEP_UP.
  * HIGH risk requires MODERATE confidence; otherwise STEP_UP or BLOCK.
  * CRITICAL risk requires HIGH confidence; otherwise STEP_UP or BLOCK.
  * ISOLATE requires an open incident OR critically low confidence PLUS multiple
    independent compromise signals. Missing behavioral evidence alone is never
    treated as malicious and never triggers ISOLATE.
"""

from typing import Iterable, List, Set, Tuple

from app.core.config import settings
from app.engines.policy.policy_types import PolicyDefinition, PolicyRule, SecurityDecisionEnum
from app.schemas.action import ActionRiskLevel

# Codes that each represent a distinct source of evidence. Two or more of these
# indicate correlated independent evidence of compromise.
INDEPENDENT_SIGNAL_CODES: Set[str] = {
    "BEHAVIOR_ANOMALY",
    "TYPING_DWELL_ANOMALY",
    "MOUSE_KINEMATICS_ANOMALY",
    "CLICK_CADENCE_ANOMALY",
    "NEW_DEVICE",
    "NEW_OR_CHANGED_DEVICE",
    "SUSPICIOUS_NETWORK",
    "SIGNIFICANT_DRIFT",
    "REPLAY_DETECTED",
    "MISSING_INTEGRITY",
    "ACTION_RISK_CRITICAL",
    "LARGE_AMOUNT_ESCALATION",
    "UNKNOWN_SESSION_DEVICE",
    "SEQUENCE_ANOMALY",
}


class PolicyEngine:
    """Evaluates evidence against a versioned, auditable policy."""

    @staticmethod
    def v1_policy() -> PolicyDefinition:
        high = settings.HIGH_CONFIDENCE_THRESHOLD  # 80
        moderate = settings.MODERATE_CONFIDENCE_THRESHOLD  # 60
        guarded = settings.GUARDED_CONFIDENCE_THRESHOLD  # 30
        return PolicyDefinition(
            version=settings.POLICY_VERSION,
            rules=[
                PolicyRule(
                    rule_id="incident-isolate",
                    description="Any active security incident isolates the session.",
                    action_risk=ActionRiskLevel.CRITICAL,
                    min_confidence=0,
                    decision=SecurityDecisionEnum.ISOLATE,
                    requires_open_incident=True,
                    priority=100,
                ),
                PolicyRule(
                    rule_id="low-allow",
                    description="Low-risk actions are allowed.",
                    action_risk=ActionRiskLevel.LOW,
                    min_confidence=0,
                    decision=SecurityDecisionEnum.ALLOW,
                    priority=1,
                ),
                PolicyRule(
                    rule_id="medium-allow",
                    description="Medium-risk actions require guarded confidence.",
                    action_risk=ActionRiskLevel.MEDIUM,
                    min_confidence=guarded,
                    decision=SecurityDecisionEnum.ALLOW,
                    priority=2,
                ),
                PolicyRule(
                    rule_id="medium-step-up",
                    description="Medium-risk actions with low confidence require step-up.",
                    action_risk=ActionRiskLevel.MEDIUM,
                    min_confidence=0,
                    decision=SecurityDecisionEnum.STEP_UP,
                    priority=3,
                ),
                PolicyRule(
                    rule_id="high-allow",
                    description="High-risk actions require moderate confidence.",
                    action_risk=ActionRiskLevel.HIGH,
                    min_confidence=moderate,
                    decision=SecurityDecisionEnum.ALLOW,
                    priority=2,
                ),
                PolicyRule(
                    rule_id="high-step-up",
                    description="High-risk actions with guarded confidence require step-up.",
                    action_risk=ActionRiskLevel.HIGH,
                    min_confidence=guarded,
                    decision=SecurityDecisionEnum.STEP_UP,
                    priority=3,
                ),
                PolicyRule(
                    rule_id="high-block",
                    description="High-risk actions with low confidence are blocked.",
                    action_risk=ActionRiskLevel.HIGH,
                    min_confidence=0,
                    decision=SecurityDecisionEnum.BLOCK,
                    priority=4,
                ),
                PolicyRule(
                    rule_id="critical-allow",
                    description="Critical-risk actions require high confidence.",
                    action_risk=ActionRiskLevel.CRITICAL,
                    min_confidence=high,
                    decision=SecurityDecisionEnum.ALLOW,
                    priority=2,
                ),
                PolicyRule(
                    rule_id="critical-step-up",
                    description="Critical-risk actions with moderate confidence require step-up.",
                    action_risk=ActionRiskLevel.CRITICAL,
                    min_confidence=moderate,
                    decision=SecurityDecisionEnum.STEP_UP,
                    priority=3,
                ),
                PolicyRule(
                    rule_id="critical-block",
                    description=(
                        "Critical-risk actions with guarded or low confidence are "
                        "blocked unless multiple independent compromise signals are present."
                    ),
                    action_risk=ActionRiskLevel.CRITICAL,
                    min_confidence=0,
                    decision=SecurityDecisionEnum.BLOCK,
                    priority=4,
                ),
                PolicyRule(
                    rule_id="critical-isolate",
                    description=(
                        "Critical-risk actions with critically low confidence and "
                        "multiple independent compromise signals isolate the session."
                    ),
                    action_risk=ActionRiskLevel.CRITICAL,
                    min_confidence=0,
                    decision=SecurityDecisionEnum.ISOLATE,
                    priority=5,
                ),
            ],
        )

    @staticmethod
    def get_policy(version: str = "v1") -> PolicyDefinition:
        # Phase 2 exposes a single audited built-in policy. New versions can be
        # switched server-side without code changes to callers.
        if version not in ("v1", ""):
            return PolicyEngine.v1_policy()
        return PolicyEngine.v1_policy()

    @staticmethod
    def decide(
        session_confidence: int,
        action_risk: ActionRiskLevel,
        reason_codes: List[str],
        open_incident: bool = False,
        policy_version: str = "v1",
    ) -> Tuple[SecurityDecisionEnum, str, List[str]]:
        """Returns (decision, rule_id, enriched_reason_codes)."""
        session_confidence = max(0, min(100, int(session_confidence)))
        policy = PolicyEngine.get_policy(policy_version or settings.POLICY_VERSION)
        reason_codes = list(dict.fromkeys(reason_codes or []))

        if open_incident:
            reason_codes = list(dict.fromkeys(reason_codes + ["ACTIVE_SECURITY_INCIDENT"]))
            return SecurityDecisionEnum.ISOLATE, "incident-isolate", reason_codes

        candidates = [
            rule
            for rule in policy.rules
            if rule.action_risk == action_risk and not rule.requires_open_incident
        ]
        candidates.sort(key=lambda r: (r.priority, -r.min_confidence))

        # Isolation has highest priority and must be evaluated before permissive
        # matching rules such as CRITICAL+low-confidence BLOCK.
        for rule in candidates:
            if rule.decision == SecurityDecisionEnum.ISOLATE:
                if (
                    session_confidence <= settings.LOW_CONFIDENCE_MAX
                    and PolicyEngine.count_independent_signals(reason_codes) >= 2
                ):
                    reason_codes = list(dict.fromkeys(reason_codes + ["SESSION_ISOLATED"]))
                    return rule.decision, rule.rule_id, reason_codes
                continue

        for rule in candidates:
            if rule.decision == SecurityDecisionEnum.ISOLATE:
                continue
            if session_confidence >= rule.min_confidence:
                if rule.decision == SecurityDecisionEnum.ALLOW:
                    return rule.decision, rule.rule_id, reason_codes
                reason_codes = list(dict.fromkeys(reason_codes + ["CONFIDENCE_TOO_LOW_FOR_ACTION"]))
                return rule.decision, rule.rule_id, reason_codes

        # Fallback should never be reached with a valid policy.
        return (
            SecurityDecisionEnum.BLOCK,
            "fallback-block",
            list(
                dict.fromkeys(
                    reason_codes + ["UNKNOWN_RISK_LEVEL", "CONFIDENCE_TOO_LOW_FOR_ACTION"]
                )
            ),
        )

    @staticmethod
    def count_independent_signals(reason_codes: Iterable[str], minimum_code: bool = False) -> int:
        """Counts distinct independent signal families from reason codes."""
        present = {code for code in reason_codes if code in INDEPENDENT_SIGNAL_CODES}
        # Avoid double counting overlapping families (e.g. generic + specific behavioral).
        families: Set[str] = set()
        for code in present:
            if code in {
                "TYPING_DWELL_ANOMALY",
                "MOUSE_KINEMATICS_ANOMALY",
                "CLICK_CADENCE_ANOMALY",
            }:
                families.add("BEHAVIOR")
            elif code == "BEHAVIOR_ANOMALY":
                families.add("BEHAVIOR")
            elif code in {"NEW_DEVICE", "NEW_OR_CHANGED_DEVICE", "UNKNOWN_SESSION_DEVICE"}:
                families.add("DEVICE")
            elif code == "SUSPICIOUS_NETWORK":
                families.add("NETWORK")
            elif code == "SIGNIFICANT_DRIFT":
                families.add("DRIFT")
            elif code == "REPLAY_DETECTED":
                families.add("REPLAY")
            elif code == "MISSING_INTEGRITY":
                families.add("INTEGRITY")
            elif code == "SEQUENCE_ANOMALY":
                families.add("SEQUENCE")
            elif code in {"ACTION_RISK_CRITICAL", "LARGE_AMOUNT_ESCALATION"}:
                families.add("ACTION")
            else:
                families.add(code)
        return len(families)
