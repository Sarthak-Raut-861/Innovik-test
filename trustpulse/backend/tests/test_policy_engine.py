"""TRUSTPULSE — Phase 2 policy engine and action risk tests.

These are pure-logic tests: no database, no HTTP. They pin the authorization
semantics so a config or code change cannot silently weaken enforcement.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from app.core.trust_config import TrustConfigError, TrustModelConfig
from app.services.action_risk.evaluator import ActionRiskEvaluator
from app.services.policy.engine import (
    PolicyDecision,
    PolicyEngine,
    PolicyFacts,
    band_for_risk,
)

CONFIG_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "shared" / "constants" / "trust_model.json"
)


def _raw_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _config(raw: dict | None = None) -> TrustModelConfig:
    from app.core.trust_config import _validate

    payload = raw if raw is not None else _raw_config()
    _validate(payload)
    return TrustModelConfig(raw=payload, source="test")


# ------------------------------------------------------------------ risk bands
class TestRiskBands:
    @pytest.mark.parametrize(
        "risk,band",
        [
            (0, "LOW"),
            (29, "LOW"),
            (30, "MEDIUM"),
            (59, "MEDIUM"),
            (60, "HIGH"),
            (84, "HIGH"),
            (85, "CRITICAL"),
            (100, "CRITICAL"),
        ],
    )
    def test_band_boundaries(self, risk: int, band: str) -> None:
        assert band_for_risk(risk) == band


# ------------------------------------------------------------------ risk scoring
class TestActionRisk:
    def setup_method(self) -> None:
        self.evaluator = ActionRiskEvaluator(config=_config())

    @pytest.mark.parametrize(
        "action,expected",
        [
            ("VIEW_DASHBOARD", 10),
            ("VIEW_PROFILE", 15),
            ("VIEW_RESOURCE", 20),
            ("CHANGE_PROFILE", 30),
            ("EXPORT_DATA", 60),
            ("CHANGE_PASSWORD", 85),
            ("CREATE_API_KEY", 90),
            ("DELETE_RESOURCE", 95),
            ("CHANGE_SECURITY_SETTINGS", 95),
            ("MODIFY_ACCESS_POLICY", 97),
            ("CREATE_ADMIN", 98),
        ],
    )
    def test_catalogue_values(self, action: str, expected: int) -> None:
        assert self.evaluator.evaluate(action).risk == expected

    def test_undeclared_action_is_medium_never_low(self) -> None:
        """An unknown action must not silently become safe."""
        assessment = self.evaluator.evaluate("TOTALLY_UNKNOWN_THING")
        assert assessment.risk == 50
        assert assessment.band == "MEDIUM"
        assert assessment.source == "INFERRED"

    @pytest.mark.parametrize(
        "action,expected_risk",
        [
            ("LIST_PROJECTS", 20),
            ("DELETE_VOLUME", 95),
            ("EXPORT_AUDIT_LOG", 60),
            ("GRANT_ROLE", 97),
            ("ROTATE_SIGNING_KEY", 88),
        ],
    )
    def test_inferred_categories(self, action: str, expected_risk: int) -> None:
        assert self.evaluator.evaluate(action).risk == expected_risk

    def test_amount_escalates_at_high_tier(self) -> None:
        assessment = self.evaluator.evaluate("EXPORT_DATA", context={"amount": 25000})
        assert assessment.risk == 80
        assert assessment.escalated
        assert assessment.adjustments[0]["type"] == "AMOUNT_ESCALATION"

    def test_amount_escalates_at_critical_tier(self) -> None:
        assessment = self.evaluator.evaluate("EXPORT_DATA", context={"amount": 100000})
        assert assessment.risk == 98

    def test_small_amount_does_not_escalate(self) -> None:
        assessment = self.evaluator.evaluate("EXPORT_DATA", context={"amount": 1000})
        assert assessment.risk == 60
        assert not assessment.escalated

    def test_privileged_context_adds_bonus(self) -> None:
        base = self.evaluator.evaluate("CHANGE_PROFILE").risk
        escalated = self.evaluator.evaluate("CHANGE_PROFILE", context={"privileged": True})
        assert escalated.risk == base + 8
        assert escalated.adjustments[0]["type"] == "PRIVILEGE_ESCALATION"

    def test_production_resource_adds_bonus(self) -> None:
        base = self.evaluator.evaluate("CHANGE_PROFILE").risk
        escalated = self.evaluator.evaluate("CHANGE_PROFILE", resource="project/production/db")
        assert escalated.risk == base + 6

    def test_risk_is_clamped_to_100(self) -> None:
        """Stacking every escalation must not exceed the scale."""
        assessment = self.evaluator.evaluate(
            "MODIFY_ACCESS_POLICY",
            resource="production",
            context={"amount": 500000, "privileged": True, "production": True},
        )
        assert assessment.risk == 100

    def test_risk_ignores_irrelevant_context(self) -> None:
        """Context that is not a risk signal must not move the score."""
        base = self.evaluator.evaluate("VIEW_DASHBOARD").risk
        noisy = self.evaluator.evaluate(
            "VIEW_DASHBOARD", context={"user_agent": "curl", "notes": "hello"}
        ).risk
        assert base == noisy

    def test_string_amount_is_parsed(self) -> None:
        assessment = self.evaluator.evaluate("EXPORT_DATA", context={"amount": "100,000"})
        assert assessment.risk == 98

    def test_boolean_is_not_treated_as_an_amount(self) -> None:
        assessment = self.evaluator.evaluate("EXPORT_DATA", context={"amount": True})
        assert assessment.risk == 60

    def test_dimensions_are_reported(self) -> None:
        assessment = self.evaluator.evaluate("CREATE_ADMIN")
        assert assessment.dimensions["privilege"] == 1.0
        assert assessment.dimensions["sensitivity"] == 0.95
        assert assessment.category == "PRIVILEGE_ESCALATION"


# ------------------------------------------------------------------ policy rules
class TestPolicyEngine:
    def setup_method(self) -> None:
        self.engine = PolicyEngine(_config())

    def evaluate(self, **kwargs) -> PolicyDecision:
        facts = {"tci": 95.0, "trust_state": "TRUSTED", "action_risk": 10}
        facts.update(kwargs)
        return self.engine.evaluate(PolicyFacts(**facts))

    def test_trusted_session_allows_low_risk(self) -> None:
        decision = self.evaluate()
        assert decision.decision == "ALLOW"
        assert decision.rule_id == "DEFAULT_ALLOW"
        assert decision.allowed
        assert not decision.blocked

    def test_trusted_session_steps_up_for_very_high_risk(self) -> None:
        decision = self.evaluate(action_risk=98)
        assert decision.decision == "STEP_UP"
        assert decision.rule_id == "HEALTHY_STATE_VERY_HIGH_RISK"

    def test_trusted_session_allows_high_risk(self) -> None:
        """A healthy session should not be challenged for ordinary high-risk work."""
        decision = self.evaluate(action_risk=90)
        assert decision.decision == "ALLOW"

    def test_degraded_steps_up_for_critical_risk(self) -> None:
        decision = self.evaluate(tci=75, trust_state="DEGRADED", action_risk=90)
        assert decision.decision == "STEP_UP"
        assert decision.rule_id == "DEGRADED_STATE_CRITICAL_RISK"

    def test_suspicious_steps_up_for_high_risk(self) -> None:
        decision = self.evaluate(tci=60, trust_state="SUSPICIOUS", action_risk=90)
        assert decision.decision == "STEP_UP"
        assert decision.rule_id == "SUSPICIOUS_STATE_HIGH_RISK"

    def test_suspicious_allows_low_risk(self) -> None:
        """Suspicious does not mean useless — reading a dashboard is still fine."""
        decision = self.evaluate(tci=60, trust_state="SUSPICIOUS", action_risk=10)
        assert decision.decision == "ALLOW"

    def test_critical_blocks_high_risk(self) -> None:
        decision = self.evaluate(tci=35, trust_state="CRITICAL", action_risk=90)
        assert decision.decision == "BLOCK"
        assert decision.blocked

    def test_contained_state_blocks_everything(self) -> None:
        for risk in (10, 50, 98):
            decision = self.evaluate(
                tci=95, trust_state="CONTAINED", action_risk=risk, is_contained=True
            )
            assert decision.decision == "BLOCK", f"risk {risk} was not blocked"
            assert decision.rule_id in ("SESSION_CONTAINED", "TCI_FLOOR_GUARD")

    def test_revoked_session_blocks(self) -> None:
        decision = self.evaluate(session_status="REVOKED")
        assert decision.decision == "BLOCK"
        assert decision.rule_id == "SESSION_NOT_ACTIVE"

    def test_terminated_session_blocks(self) -> None:
        decision = self.evaluate(session_status="TERMINATED")
        assert decision.decision == "BLOCK"

    def test_tci_floor_blocks_regardless_of_state(self) -> None:
        """The floor guard fires even if the state has not caught up.

        Hysteresis can legitimately hold a state one band high; the floor stops
        that from authorizing a high-risk action on a collapsed score.
        """
        decision = self.evaluate(tci=40, trust_state="DEGRADED", action_risk=60)
        assert decision.decision == "BLOCK"
        assert decision.rule_id == "TCI_FLOOR_GUARD"
        assert "TCI_BELOW_AUTHORIZATION_FLOOR" in decision.warnings

    def test_tci_floor_does_not_block_low_risk(self) -> None:
        """A low score should not lock a user out of read-only access."""
        decision = self.evaluate(tci=40, trust_state="CRITICAL", action_risk=10)
        assert decision.decision == "ALLOW"

    def test_first_matching_rule_wins(self) -> None:
        """A contained session must be blocked, not stepped up."""
        decision = self.evaluate(
            tci=60, trust_state="SUSPICIOUS", action_risk=90, is_contained=True
        )
        assert decision.decision == "BLOCK"
        assert decision.rule_id == "SESSION_CONTAINED"

    def test_decision_is_deterministic(self) -> None:
        first = self.evaluate(tci=60, trust_state="SUSPICIOUS", action_risk=90)
        second = self.evaluate(tci=60, trust_state="SUSPICIOUS", action_risk=90)
        assert first.decision == second.decision
        assert first.rule_id == second.rule_id
        assert first.reason == second.reason

    def test_decision_is_explainable(self) -> None:
        decision = self.evaluate(tci=60, trust_state="SUSPICIOUS", action_risk=90)
        assert decision.reason
        assert decision.policy_version
        assert decision.risk_band == "CRITICAL"
        # The audit trail must show which rules were considered and why they missed.
        assert len(decision.considered) >= 1
        assert any(entry["matched"] for entry in decision.considered)

    def test_facts_are_recorded(self) -> None:
        decision = self.evaluate(tci=61.234, trust_state="SUSPICIOUS", action_risk=90)
        assert decision.facts["tci"] == 61.23
        assert decision.facts["trust_state"] == "SUSPICIOUS"
        assert decision.facts["action_risk"] == 90


# ------------------------------------------------------------------ policy validation
class TestPolicyValidation:
    """A malformed policy must fail at load, never fail open at runtime."""

    def test_missing_rules_rejected(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"] = []
        with pytest.raises(TrustConfigError, match="non-empty"):
            _config(raw)

    def test_non_catch_all_final_rule_rejected(self) -> None:
        """Without a catch-all the policy is not total and could fall through."""
        raw = _raw_config()
        raw["authorization"]["rules"][-1]["requires"] = {"min_action_risk": 10}
        with pytest.raises(TrustConfigError, match="catch-all"):
            _config(raw)

    def test_unknown_decision_rejected(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"][0]["decision"] = "MAYBE"
        with pytest.raises(TrustConfigError, match="MAYBE"):
            _config(raw)

    def test_duplicate_rule_id_rejected(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"][1]["id"] = raw["authorization"]["rules"][0]["id"]
        with pytest.raises(TrustConfigError, match="duplicate"):
            _config(raw)

    def test_missing_reason_rejected(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"][0]["reason"] = ""
        with pytest.raises(TrustConfigError, match="human-readable"):
            _config(raw)

    def test_unknown_trust_state_in_rule_rejected(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"][4]["requires"]["trust_state_in"] = ["SUSPICIOUSS"]
        with pytest.raises(TrustConfigError, match="SUSPICIOUSS"):
            _config(raw)

    def test_unknown_terminal_state_rejected(self) -> None:
        raw = _raw_config()
        raw["authorization"]["terminal_trust_states"] = ["NOPE"]
        with pytest.raises(TrustConfigError, match="NOPE"):
            _config(raw)

    def test_contained_is_a_valid_terminal_state(self) -> None:
        """CONTAINED is not a TCI band but is a legitimate policy input."""
        raw = _raw_config()
        assert "CONTAINED" in raw["authorization"]["terminal_trust_states"]
        config = _config(raw)  # must not raise
        assert "CONTAINED" in config.terminal_trust_states

    def test_receipt_ttl_cannot_exceed_max(self) -> None:
        raw = _raw_config()
        raw["authorization"]["receipts"]["ttl_seconds"] = 99999
        with pytest.raises(TrustConfigError, match="max_ttl_seconds"):
            _config(raw)

    def test_unknown_predicate_never_matches(self) -> None:
        """A typo in a predicate must not silently make the rule always-true."""
        raw = _raw_config()
        raw["authorization"]["rules"][0]["requires"] = {"trust_statee_in": ["TRUSTED"]}
        engine = PolicyEngine(_config(raw))
        decision = engine.evaluate(PolicyFacts(tci=95, trust_state="TRUSTED", action_risk=10))
        # The malformed rule is skipped; the catch-all still decides.
        assert decision.rule_id != raw["authorization"]["rules"][0]["id"]
        skipped = [
            e for e in decision.considered if e["rule_id"] == raw["authorization"]["rules"][0]["id"]
        ]
        assert skipped and not skipped[0]["matched"]
        assert "unknown predicate" in skipped[0]["skipped"]

    def test_empty_policy_refuses_to_authorize(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"] = []
        # Bypass validation to prove the engine itself fails closed.
        config = TrustModelConfig(raw=raw, source="test")
        with pytest.raises(ValueError, match="refusing to authorize"):
            PolicyEngine(config)


# ------------------------------------------------------------------ predicates
class TestPolicyPredicates:
    def setup_method(self) -> None:
        self.engine = PolicyEngine(_config())

    def test_open_incident_predicate(self) -> None:
        """An open incident is a policy input even though no default rule uses it.

        Pinned here so a tenant can add such a rule and rely on the predicate.
        """
        raw = _raw_config()
        raw["authorization"]["rules"].insert(
            0,
            {
                "id": "OPEN_INCIDENT_BLOCKS",
                "decision": "BLOCK",
                "requires": {"open_incident": True, "min_action_risk": 30},
                "reason": "An open incident is under investigation",
            },
        )
        engine = PolicyEngine(_config(raw))
        blocked = engine.evaluate(
            PolicyFacts(tci=95, trust_state="TRUSTED", action_risk=50, open_incident=True)
        )
        allowed = engine.evaluate(
            PolicyFacts(tci=95, trust_state="TRUSTED", action_risk=50, open_incident=False)
        )
        assert blocked.decision == "BLOCK"
        assert allowed.decision == "ALLOW"

    def test_step_up_attempts_predicate(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"].insert(
            0,
            {
                "id": "TOO_MANY_STEP_UP_FAILURES",
                "decision": "BLOCK",
                "requires": {"min_step_up_attempts": 3},
                "reason": "Repeated step-up failures",
            },
        )
        engine = PolicyEngine(_config(raw))
        decision = engine.evaluate(
            PolicyFacts(tci=95, trust_state="TRUSTED", action_risk=10, step_up_attempts=3)
        )
        assert decision.decision == "BLOCK"

    def test_context_predicate(self) -> None:
        raw = _raw_config()
        raw["authorization"]["rules"].insert(
            0,
            {
                "id": "BLOCK_CROSS_TENANT",
                "decision": "BLOCK",
                "requires": {"context_equals": {"cross_tenant": True}},
                "reason": "Cross-tenant access is not permitted",
            },
        )
        engine = PolicyEngine(_config(raw))
        blocked = engine.evaluate(
            PolicyFacts(
                tci=95, trust_state="TRUSTED", action_risk=10, context={"cross_tenant": True}
            )
        )
        allowed = engine.evaluate(
            PolicyFacts(tci=95, trust_state="TRUSTED", action_risk=10, context={})
        )
        assert blocked.decision == "BLOCK"
        assert allowed.decision == "ALLOW"

    def test_policy_rules_are_copies_not_references(self) -> None:
        """Mutating a returned rule must not change the live policy."""
        rules = self.engine.rules()
        rules[0]["decision"] = "ALLOW"
        assert self.engine.rules()[0]["decision"] != "ALLOW" or (
            self.engine.rules()[0]["id"] != rules[0]["id"]
        )


class TestPolicyConfigIsData:
    def test_rules_live_in_the_shared_config(self) -> None:
        """Enforcement must be tunable without a code change."""
        raw = _raw_config()
        assert "authorization" in raw
        assert len(raw["authorization"]["rules"]) >= 5
        assert raw["authorization"]["rules"][-1]["requires"] == {}

    def test_policy_can_be_retuned_without_code(self) -> None:
        raw = _raw_config()
        # Tighten: require step-up for anything above risk 20 in a healthy session.
        raw["authorization"]["rules"].insert(
            -1,
            {
                "id": "STRICT_MODE",
                "decision": "STEP_UP",
                "requires": {"trust_state_in": ["TRUSTED"], "min_action_risk": 20},
                "reason": "Strict mode",
            },
        )
        engine = PolicyEngine(_config(raw))
        assert (
            engine.evaluate(PolicyFacts(tci=95, trust_state="TRUSTED", action_risk=30)).decision
            == "STEP_UP"
        )
