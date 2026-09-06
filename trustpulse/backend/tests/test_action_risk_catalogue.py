"""TRUSTPULSE — Action risk catalogue (numeric 0-100, configurable)."""

from __future__ import annotations

import pytest

from app.core.trust_config import load_trust_config
from app.services.action_risk.catalogue import ActionRiskCatalogue, band_for_risk

SPEC_VALUES = {
    "VIEW_DASHBOARD": 10,
    "VIEW_PROFILE": 15,
    "VIEW_RESOURCE": 20,
    "CHANGE_PROFILE": 30,
    "EXPORT_DATA": 60,
    "CHANGE_PASSWORD": 85,
    "CREATE_API_KEY": 90,
    "DELETE_RESOURCE": 95,
    "CHANGE_SECURITY_SETTINGS": 95,
    "MODIFY_ACCESS_POLICY": 97,
    "CREATE_ADMIN": 98,
}


def test_catalogue_matches_the_specified_prototype_values():
    catalogue = ActionRiskCatalogue()
    for action, expected in SPEC_VALUES.items():
        assert catalogue.risk(action) == expected, action


def test_risk_lookup_is_case_insensitive():
    catalogue = ActionRiskCatalogue()
    assert catalogue.risk("create_api_key") == catalogue.risk("CREATE_API_KEY")
    assert catalogue.risk("  View_Dashboard ") == 10


def test_every_profile_carries_the_full_risk_dimensions():
    catalogue = ActionRiskCatalogue()
    for action, profile in catalogue.catalogue().items():
        assert 0 <= profile["risk"] <= 100, action
        for dimension in ("sensitivity", "privilege", "resource_exposure", "impact"):
            assert 0.0 <= float(profile[dimension]) <= 1.0, f"{action}.{dimension}"
        assert profile["category"], action


def test_privilege_escalation_outranks_read_actions():
    catalogue = ActionRiskCatalogue()
    assert catalogue.risk("CREATE_ADMIN") > catalogue.risk("VIEW_DASHBOARD")
    assert catalogue.risk("MODIFY_ACCESS_POLICY") > catalogue.risk("EXPORT_DATA")
    assert catalogue.risk("CHANGE_SECURITY_SETTINGS") > catalogue.risk("CHANGE_PROFILE")


def test_unknown_actions_are_never_treated_as_safe():
    catalogue = ActionRiskCatalogue()
    assert catalogue.risk("SOMETHING_UNDECLARED") == 50
    profile = catalogue.profile("SOMETHING_UNDECLARED")
    assert profile["source"] == "INFERRED"


@pytest.mark.parametrize(
    "action,expected_band",
    [
        ("VIEW_DASHBOARD", "LOW"),
        ("CHANGE_PROFILE", "MEDIUM"),
        ("EXPORT_DATA", "HIGH"),
        ("CREATE_API_KEY", "CRITICAL"),
        ("CREATE_ADMIN", "CRITICAL"),
    ],
)
def test_risk_bands(action, expected_band):
    catalogue = ActionRiskCatalogue()
    assert catalogue.band(action) == expected_band


def test_inferred_categories_are_sensible():
    catalogue = ActionRiskCatalogue()
    assert catalogue.profile("LIST_PROJECTS")["category"] == "READ"
    assert catalogue.profile("DELETE_VOLUME")["category"] == "DESTRUCTIVE"
    assert catalogue.profile("EXPORT_AUDIT_LOG")["category"] == "EXFILTRATION"
    assert catalogue.profile("GRANT_ROLE")["category"] == "PRIVILEGE_ESCALATION"
    assert catalogue.profile("ROTATE_SIGNING_KEY")["category"] == "CREDENTIAL"


def test_action_risk_is_configurable_by_environment(monkeypatch):
    monkeypatch.setenv("ACTION_RISK_CREATE_API_KEY", "42")
    monkeypatch.setenv("ACTION_RISK_VIEW_DASHBOARD", "5")
    catalogue = ActionRiskCatalogue(config=load_trust_config())
    assert catalogue.risk("CREATE_API_KEY") == 42
    assert catalogue.risk("VIEW_DASHBOARD") == 5
    assert catalogue.band("CREATE_API_KEY") == "MEDIUM"


def test_action_risk_overrides_are_clamped_to_the_scale(monkeypatch):
    monkeypatch.setenv("ACTION_RISK_EXPORT_DATA", "500")
    catalogue = ActionRiskCatalogue(config=load_trust_config())
    assert catalogue.risk("EXPORT_DATA") == 100


def test_catalogue_is_sorted_by_descending_risk():
    risks = [profile["risk"] for profile in ActionRiskCatalogue().catalogue().values()]
    assert risks == sorted(risks, reverse=True)


def test_band_boundaries():
    assert band_for_risk(0) == "LOW"
    assert band_for_risk(29) == "LOW"
    assert band_for_risk(30) == "MEDIUM"
    assert band_for_risk(59) == "MEDIUM"
    assert band_for_risk(60) == "HIGH"
    assert band_for_risk(84) == "HIGH"
    assert band_for_risk(85) == "CRITICAL"
    assert band_for_risk(100) == "CRITICAL"
