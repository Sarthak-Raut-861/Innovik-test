"""TRUSTPULSE — Action risk evaluation.

Risk describes the **action**, never the user. A `CREATE_API_KEY` is equally
dangerous whoever asks for it; who is asking is handled separately, by the trust
engine and the policy.

The catalogue supplies a base 0-100 score per action. This module layers
*request context* on top of that base:

* a large transfer amount escalates risk,
* acting with elevated privilege escalates risk,
* targeting a production resource escalates risk.

Every escalation is additive and clamped to 0-100, and every adjustment is
reported in `adjustments` so an analyst can see exactly why a score moved off
the catalogue value.

All thresholds come from `shared/constants/trust_model.json`
(`action_risk` + `authorization`). Nothing here is hard-coded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.trust_config import TrustModelConfig, get_trust_config
from app.services.action_risk.catalogue import ActionRiskCatalogue, band_for_risk


@dataclass
class ActionRiskAssessment:
    """A fully-explained action risk score."""

    action: str
    risk: int
    band: str
    category: str
    source: str
    base_risk: int
    dimensions: Dict[str, float] = field(default_factory=dict)
    adjustments: List[Dict[str, Any]] = field(default_factory=list)
    profile: Dict[str, Any] = field(default_factory=dict)

    @property
    def escalated(self) -> bool:
        return self.risk != self.base_risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "risk": self.risk,
            "band": self.band,
            "category": self.category,
            "source": self.source,
            "base_risk": self.base_risk,
            "escalated": self.escalated,
            "dimensions": self.dimensions,
            "adjustments": self.adjustments,
        }


# Context keys that are pure risk signals. Anything else in `context` is passed
# through to the audit record but never influences the score.
AMOUNT_KEYS = ("amount", "value", "total", "amount_usd")
PRIVILEGE_KEYS = ("privileged", "elevated", "sudo", "as_admin", "impersonating")
PRODUCTION_KEYS = ("production", "is_production", "prod", "live")


class ActionRiskEvaluator:
    """Scores an action request using the catalogue plus request context."""

    def __init__(
        self,
        catalogue: Optional[ActionRiskCatalogue] = None,
        config: Optional[TrustModelConfig] = None,
    ) -> None:
        self.config = config or get_trust_config()
        self.catalogue = catalogue or ActionRiskCatalogue(config=self.config)

    async def with_tenant_overrides(self, db: Any, tenant_id: str) -> "ActionRiskEvaluator":
        """Loads per-tenant catalogue overrides from the database."""
        self.catalogue = ActionRiskCatalogue(config=self.config, db=db, tenant_id=tenant_id)
        await self.catalogue.load_overrides()
        return self

    def evaluate(
        self,
        action: str,
        resource: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ActionRiskAssessment:
        context = dict(context or {})
        profile = self.catalogue.profile(action)
        base_risk = int(profile.get("risk", 50))

        dimensions = {
            "sensitivity": float(profile.get("sensitivity", 0.5)),
            "privilege": float(profile.get("privilege", 0.5)),
            "resource_exposure": float(profile.get("resource_exposure", 0.5)),
            "impact": float(profile.get("impact", 0.5)),
        }

        risk = float(base_risk)
        adjustments: List[Dict[str, Any]] = []

        amount_adjustment = self._amount_adjustment(context)
        if amount_adjustment is not None:
            new_risk, note = amount_adjustment
            if new_risk > risk:
                adjustments.append(
                    {"type": "AMOUNT_ESCALATION", "from": risk, "to": new_risk, "detail": note}
                )
                risk = new_risk

        privilege_bonus, privilege_reason = self._privilege_adjustment(context)
        if privilege_bonus:
            adjustments.append(
                {
                    "type": "PRIVILEGE_ESCALATION",
                    "from": risk,
                    "to": risk + privilege_bonus,
                    "detail": privilege_reason,
                }
            )
            risk += privilege_bonus

        production_bonus, production_reason = self._production_adjustment(context, resource)
        if production_bonus:
            adjustments.append(
                {
                    "type": "PRODUCTION_RESOURCE",
                    "from": risk,
                    "to": risk + production_bonus,
                    "detail": production_reason,
                }
            )
            risk += production_bonus

        final_risk = max(0, min(100, int(round(risk))))

        return ActionRiskAssessment(
            action=str(profile.get("action", action or "UNKNOWN")),
            risk=final_risk,
            band=band_for_risk(final_risk),
            category=str(profile.get("category", "WRITE")),
            source=str(profile.get("source", "BUILTIN")),
            base_risk=base_risk,
            dimensions=dimensions,
            adjustments=adjustments,
            profile=profile,
        )

    # ------------------------------------------------------------------ adjustments
    def _amount_adjustment(self, context: Dict[str, Any]) -> Optional[tuple]:
        """Large-value operations escalate to the configured amount tiers."""
        amount = self._first_number(context, AMOUNT_KEYS)
        if amount is None:
            return None

        tiers = self.config.get("action_risk", "amount_escalation") or {}
        critical_amount = float(tiers.get("critical_amount", 100000))
        high_amount = float(tiers.get("high_amount", 25000))
        critical_risk = float(tiers.get("critical_amount_risk", 98))
        high_risk = float(tiers.get("high_amount_risk", 80))

        if amount >= critical_amount:
            return critical_risk, f"amount {amount:,.2f} >= critical tier {critical_amount:,.0f}"
        if amount >= high_amount:
            return high_risk, f"amount {amount:,.2f} >= high tier {high_amount:,.0f}"
        return None

    def _privilege_adjustment(self, context: Dict[str, Any]) -> tuple:
        """Acting with elevated privilege adds a flat bonus."""
        if not self._any_true(context, PRIVILEGE_KEYS):
            return 0, ""
        bonus = float(self.config.get("action_risk", "privilege_escalation_bonus", default=8))
        return bonus, "request declared elevated privilege"

    def _production_adjustment(self, context: Dict[str, Any], resource: Optional[str]) -> tuple:
        """Production targets add a flat bonus."""
        declared = self._any_true(context, PRODUCTION_KEYS)
        inferred = bool(resource) and "production" in str(resource).lower()
        if not (declared or inferred):
            return 0, ""
        bonus = float(self.config.get("action_risk", "production_resource_bonus", default=6))
        reason = (
            "production resource declared" if declared else "resource path indicates production"
        )
        return bonus, reason

    @staticmethod
    def _first_number(context: Dict[str, Any], keys: tuple) -> Optional[float]:
        for key in keys:
            if key in context:
                value = context[key]
                if isinstance(value, bool):
                    continue
                if isinstance(value, (int, float)):
                    return float(value)
                try:
                    return float(str(value).replace(",", ""))
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _any_true(context: Dict[str, Any], keys: tuple) -> bool:
        for key in keys:
            if key in context and bool(context[key]) is True:
                return True
        return False


__all__ = ["ActionRiskEvaluator", "ActionRiskAssessment", "band_for_risk"]
