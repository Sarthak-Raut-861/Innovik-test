"""Contract tests: shared/constants/trust_model.json ↔ shared/schemas/trust.ts.

`shared/schemas/trust.ts` is the canonical TypeScript contract, cited by both
`docs/API_REFERENCE.md` and `docs/ARCHITECTURE.md`. It is a hand-maintained
mirror of the JSON config and the backend Pydantic schemas, so these tests fail
the build if it drifts rather than letting a consumer code against stale values.

The mirror is parsed with narrow regexes rather than a TS parser on purpose: the
assertions are about a handful of literal tables, and pulling in a TypeScript
toolchain for the backend suite would be a poor trade.
"""

from __future__ import annotations

import json
import pathlib
import re
from pathlib import Path

import pytest

from app.core.trust_config import get_trust_config

# parents[2] == trustpulse/  (tests -> backend -> trustpulse)
REPO_ROOT = Path(__file__).resolve().parents[2]
TS_CONTRACT = REPO_ROOT / "shared" / "schemas" / "trust.ts"
JSON_CONFIG = REPO_ROOT / "shared" / "constants" / "trust_model.json"


def _load_ts() -> str:
    if not TS_CONTRACT.is_file():
        pytest.skip(f"shared contract not present at {TS_CONTRACT}")
    return TS_CONTRACT.read_text(encoding="utf-8")


EVIDENCE_START = "export type EvidenceType"
EVIDENCE_END = "export interface EvidenceRecord"


def _evidence_union_section() -> str:
    """The `export type EvidenceType` union, as text."""
    return _section(_load_ts(), EVIDENCE_START, EVIDENCE_END)


def _section(text: str, start: str, end: str) -> str:
    """Returns the text between two markers, failing loudly if either is absent."""
    assert start in text, f"marker not found in trust.ts: {start}"
    begin = text.index(start)
    assert end in text[begin:], f"end marker not found after {start}: {end}"
    return text[begin : begin + text[begin:].index(end)]


class TestContractFilePresent:
    def test_shared_contract_exists(self) -> None:
        assert TS_CONTRACT.is_file(), "shared/schemas/trust.ts is missing"

    def test_json_config_exists(self) -> None:
        assert JSON_CONFIG.is_file(), "shared/constants/trust_model.json is missing"


class TestWeightsMatch:
    def test_default_weights_mirror_json(self) -> None:
        """DEFAULT_WEIGHTS in TS must equal tci.weights in JSON."""
        config = json.loads(JSON_CONFIG.read_text(encoding="utf-8"))
        expected = config["tci"]["weights"]

        section = _section(_load_ts(), "DEFAULT_WEIGHTS", "/** Action risk bands")
        found = {
            name: float(value)
            for name, value in re.findall(r"(\w+): ([0-9.]+)", section)
        }

        assert set(found) == set(expected), (
            f"weight names differ: TS-only={set(found) - set(expected)} "
            f"JSON-only={set(expected) - set(found)}"
        )
        for name, value in expected.items():
            assert found[name] == pytest.approx(value), (
                f"weight {name}: TS={found[name]} JSON={value}"
            )

    def test_weights_match_the_loaded_backend_config(self) -> None:
        """The TS mirror must also match what the backend actually serves."""
        config = get_trust_config()
        section = _section(_load_ts(), "DEFAULT_WEIGHTS", "/** Action risk bands")
        found = {
            name: float(value)
            for name, value in re.findall(r"(\w+): ([0-9.]+)", section)
        }
        for name, value in config.weights.items():
            assert found.get(name) == pytest.approx(value), (
                f"backend weight {name}={value} not mirrored in trust.ts ({found.get(name)})"
            )


class TestStateBandsMatch:
    def test_default_state_bands_mirror_json(self) -> None:
        config = json.loads(JSON_CONFIG.read_text(encoding="utf-8"))
        expected = {b["state"]: b["min"] for b in config["trust_states"]["bands"]}

        section = _section(_load_ts(), "DEFAULT_STATE_BANDS", "DEFAULT_WEIGHTS")
        found = {
            state: int(floor)
            for state, floor in re.findall(r"state: '(\w+)', min: (\d+)", section)
        }

        assert found == expected, f"state bands differ: TS={found} JSON={expected}"

    def test_bands_match_the_loaded_backend_config(self) -> None:
        """Band floors must agree with the config the backend serves."""
        config = get_trust_config()
        section = _section(_load_ts(), "DEFAULT_STATE_BANDS", "DEFAULT_WEIGHTS")
        found = {
            state: int(floor)
            for state, floor in re.findall(r"state: '(\w+)', min: (\d+)", section)
        }
        for band in config.state_bands():
            state, floor = band["state"], band["min"]
            assert found.get(state) == floor, (
                f"band {state}: backend={floor} TS={found.get(state)}"
            )


class TestEvidenceTypesMatch:
    def test_evidence_union_mirrors_json(self) -> None:
        """The EvidenceType union must match evidence_types exactly.

        FACTOR_UNAVAILABLE is deliberately absent — it is a warning prefix, not
        an evidence type, and must not be added back.
        """
        config = json.loads(JSON_CONFIG.read_text(encoding="utf-8"))
        expected = set(config["evidence_types"])

        section = _evidence_union_section()
        found = set(re.findall(r"'([A-Z_]+)'", section))

        assert found == expected, (
            f"evidence vocabulary drift: TS-only={sorted(found - expected)} "
            f"JSON-only={sorted(expected - found)}"
        )

    def test_factor_unavailable_is_not_an_evidence_type(self) -> None:
        section = _evidence_union_section()
        assert "FACTOR_UNAVAILABLE" not in section, (
            "FACTOR_UNAVAILABLE is a warning prefix, not an evidence type"
        )

    def test_evidence_union_matches_the_loaded_backend_config(self) -> None:
        config = get_trust_config()
        section = _evidence_union_section()
        found = set(re.findall(r"'([A-Z_]+)'", section))
        assert found == set(config.evidence_types()), (
            f"TS evidence vocabulary does not match the backend: "
            f"TS-only={sorted(found - set(config.evidence_types()))} "
            f"backend-only={sorted(set(config.evidence_types()) - found)}"
        )

    def test_state_change_is_an_evidence_type(self) -> None:
        """Guard the opposite mistake: STATE_CHANGE is real evidence."""
        config = json.loads(JSON_CONFIG.read_text(encoding="utf-8"))
        assert "STATE_CHANGE" in config["evidence_types"]


class TestRiskBandsMatch:
    def test_risk_bands_mirror_the_catalogue(self) -> None:
        """RISK_BANDS must match backend/app/services/action_risk/catalogue.py."""
        from app.services.action_risk.catalogue import RISK_BANDS

        expected = {int(threshold): label for threshold, label in RISK_BANDS}

        section = _section(_load_ts(), "export const RISK_BANDS", "export function riskBandFor")
        found = {
            int(threshold): label
            for threshold, label in re.findall(r"min_risk: (\d+), band: '(\w+)'", section)
        }

        assert found == expected, f"risk bands differ: TS={found} catalogue={expected}"


class TestAuthorizationContract:
    """Phase 2: the TS mirror must track the shipped authorization config.

    These diff `shared/schemas/trust.ts` against the live backend objects, not
    against the JSON file, so a change that lands in one place but not the other
    fails here rather than at an integrator's build.
    """

    def test_decisions_match_the_policy_engine(self) -> None:
        from app.services.policy.engine import VALID_DECISIONS

        section = _section(
            _load_ts(), "export type Decision =", "export interface EnforcementDecision"
        )
        found = set(re.findall(r"'([A-Z_]+)'", section))
        assert found == set(VALID_DECISIONS), (
            f"Decision union drifted: TS={sorted(found)} engine={sorted(VALID_DECISIONS)}"
        )

    def test_enforcement_decision_mirrors_the_response_model(self) -> None:
        """The TS mirror must match `ActionDecisionResponse` field for field.

        This diffs the hand-written TypeScript against the live Pydantic model
        rather than against a hand-copied list, so a field added to the API
        without updating the contract fails here.
        """
        from app.schemas.authorization import ActionDecisionResponse

        ts = _load_ts()
        begin = ts.index("export interface EnforcementDecision")
        end = ts.index("export interface ActionRiskAssessment")
        section = ts[begin:end]
        declared = set(re.findall(r"^  (\w+)\??:", section, re.MULTILINE))

        model_fields = set(ActionDecisionResponse.model_fields)
        missing = model_fields - declared
        assert not missing, f"trust.ts omits response fields: {sorted(missing)}"

        extra = declared - model_fields
        assert not extra, f"trust.ts declares fields the API never returns: {sorted(extra)}"

    def test_step_up_challenge_mirrors_the_schema(self) -> None:
        from app.schemas.authorization import StepUpChallenge

        section = _section(
            _load_ts(), "export interface StepUpChallenge", "export interface ConsideredRule"
        )
        declared = set(re.findall(r"^  (\w+)\??:", section, re.MULTILINE))
        model_fields = set(StepUpChallenge.model_fields)
        assert model_fields - declared == set(), (
            f"trust.ts omits challenge fields: {sorted(model_fields - declared)}"
        )
        assert declared - model_fields == set(), (
            f"trust.ts declares unknown challenge fields: {sorted(declared - model_fields)}"
        )

    def test_step_up_resolution_reports_the_observed_penalty(self) -> None:
        """Regression: this used to echo the configured number as if applied."""
        from app.schemas.authorization import StepUpResolveResponse

        section = _section(
            _load_ts(), "export interface StepUpResolution", "export type ContainmentAction"
        )
        declared = set(re.findall(r"^  (\w+)\??:", section, re.MULTILINE))
        model_fields = set(StepUpResolveResponse.model_fields)
        assert model_fields - declared == set(), (
            f"trust.ts omits resolution fields: {sorted(model_fields - declared)}"
        )
        for field in ("tci_before", "tci_penalty_configured", "tci_penalty_applied"):
            assert field in declared, f"StepUpResolution is missing {field}"

    def test_containment_actions_match_the_config(self) -> None:
        config = get_trust_config()
        expected = set(config.containment()["actions"])

        section = _section(
            _load_ts(), "export type ContainmentAction =", "export interface ContainmentResult"
        )
        found = set(re.findall(r"'([A-Z_]+)'", section))
        assert found == expected, (
            f"containment actions differ: TS={sorted(found)} config={sorted(expected)}"
        )

    def test_containment_actions_match_the_service(self) -> None:
        """The service must not implement actions the contract never mentions."""
        from app.services.enforcement.pep import PolicyEnforcementPoint

        section = _section(
            _load_ts(), "export type ContainmentAction =", "export interface ContainmentResult"
        )
        declared = set(re.findall(r"'([A-Z_]+)'", section))

        source = pathlib.Path(PolicyEnforcementPoint.__module__.replace(".", "/"))
        source = REPO_ROOT / "backend" / "app" / "services" / "enforcement" / f"{source.name}.py"
        handled = set(
            re.findall(r'elif action == "([A-Z_]+)"|if action == "([A-Z_]+)"', source.read_text())
        )
        handled = {a or b for a, b in handled}
        assert handled <= declared, f"PEP handles undeclared actions: {sorted(handled - declared)}"

    def test_incident_status_matches_the_service(self) -> None:
        from app.services.incidents.service import CLOSED_STATUSES, OPEN_STATUSES

        section = _section(
            _load_ts(), "export type IncidentStatus =", "export interface IncidentRecord"
        )
        found = set(re.findall(r"'([A-Z_]+)'", section))
        expected = set(OPEN_STATUSES) | set(CLOSED_STATUSES)
        assert found == expected, (
            f"incident statuses differ: TS={sorted(found)} service={sorted(expected)}"
        )

    def test_policy_rule_predicates_are_all_supported(self) -> None:
        """Every predicate the TS contract offers must be one the engine reads.

        An unknown predicate is skipped rather than matched, so advertising one
        the engine ignores would let a rule look enforced while doing nothing.
        """
        ts = _load_ts()
        begin = ts.index("export interface PolicyRule")
        section = ts[begin : begin + 2000]
        advertised = set(re.findall(r"^    (\w+)\?:", section, re.MULTILINE))
        advertised -= {"id", "decision", "reason", "requires"}

        source = (
            REPO_ROOT / "backend/app/services/policy/engine.py"
        ).read_text()
        # _test_predicate dispatches with `if key == "<name>"`.
        supported = set(re.findall(r'if key == "(\w+)"', source))
        assert supported, "no predicates found — the dispatch pattern changed"
        unsupported = advertised - supported
        assert not unsupported, (
            f"trust.ts advertises predicates PolicyEngine never reads: {sorted(unsupported)}"
        )


class TestPrivacyContract:
    def test_forbidden_keys_mirror_the_ml_guard(self) -> None:
        """The TS forbidden-key list must match the server-side guard.

        The browser check is defense in depth; the server is authoritative. If
        the two lists diverge the SDK could transmit something the API rejects,
        or (worse) the SDK could pass through raw data.
        """
        from trustpulse_ml.feature_extraction.features import FORBIDDEN_KEY_PATTERNS

        section = _section(
            _load_ts(), "export const FORBIDDEN_TELEMETRY_KEYS", "];"
        )
        # Underscores matter: the server guards both `inputvalue` and `input_value`.
        found = set(re.findall(r"'([a-z_]+)'", section))
        expected = set(FORBIDDEN_KEY_PATTERNS)

        assert found == expected, (
            f"privacy vocabulary drift: TS-only={sorted(found - expected)} "
            f"server-only={sorted(expected - found)}"
        )

    def test_tci_bounds_mirror_the_json_scale(self) -> None:
        config = json.loads(JSON_CONFIG.read_text(encoding="utf-8"))
        text = _load_ts()
        assert f"export const TCI_MIN = {config['tci']['scale_min']};" in text
        assert f"export const TCI_MAX = {config['tci']['scale_max']};" in text


class TestStateSeverityOrdering:
    def test_severity_ordering_is_consistent(self) -> None:
        """STATE_SEVERITY must be a total order over the documented states."""
        section = _section(_load_ts(), "export const STATE_SEVERITY", "};")
        found = {state: int(rank) for state, rank in re.findall(r"(\w+): (\d+)", section)}

        expected_states = ["TRUSTED", "DEGRADED", "SUSPICIOUS", "CRITICAL", "BLOCKED", "CONTAINED"]
        assert set(found) == set(expected_states), f"states differ: {sorted(found)}"

        ranks = [found[state] for state in expected_states]
        assert ranks == sorted(ranks), f"severity must increase with {expected_states}: {ranks}"
        assert len(set(ranks)) == len(ranks), "severity ranks must be unique"

    def test_every_state_has_a_colour(self) -> None:
        section = _section(_load_ts(), "export const STATE_COLOR", "};")
        found = set(re.findall(r"(\w+): '#", section))
        expected = {"TRUSTED", "DEGRADED", "SUSPICIOUS", "CRITICAL", "BLOCKED", "CONTAINED"}
        assert found == expected, f"missing colours for {sorted(expected - found)}"
