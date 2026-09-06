"""TRUSTPULSE — Action risk catalogue.

Risk is a 0-100 score describing **how dangerous the requested action is**,
independent of who is asking. It is combined with session trust by the policy
engine (Phase 2); this module only answers "how risky is this action?".

Profiles come from ``shared/constants/trust_model.json`` and can be overridden
per tenant in the ``action_risk_profiles`` table, so an integrating application
defines its own vocabulary without touching TRUSTPULSE code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.trust_config import TrustModelConfig, get_trust_config
from app.models.observations import ActionRiskProfileModel

RISK_BANDS = (
    (85, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
)

DEFAULT_PROFILE = {
    "risk": 50,
    "sensitivity": 0.5,
    "privilege": 0.5,
    "resource_exposure": 0.5,
    "impact": 0.5,
    "category": "WRITE",
}


def band_for_risk(risk: int) -> str:
    for threshold, label in RISK_BANDS:
        if risk >= threshold:
            return label
    return "LOW"


class ActionRiskCatalogue:
    """Read-only view of the effective action risk catalogue for one tenant."""

    def __init__(
        self,
        config: Optional[TrustModelConfig] = None,
        db: Optional[AsyncSession] = None,
        tenant_id: Optional[str] = None,
    ) -> None:
        self.config = config or get_trust_config()
        self.db = db
        self.tenant_id = tenant_id
        self._overrides: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ loading
    async def load_overrides(self) -> "ActionRiskCatalogue":
        """Merges tenant-specific profiles from the database."""
        self._overrides = {}
        if self.db is None or not self.tenant_id:
            return self
        result = await self.db.execute(
            select(ActionRiskProfileModel).where(
                ActionRiskProfileModel.customer_tenant_id == self.tenant_id,
                ActionRiskProfileModel.enabled.is_(True),
            )
        )
        for row in result.scalars().all():
            self._overrides[row.action.upper()] = {
                "risk": int(row.risk),
                "sensitivity": float(row.sensitivity),
                "privilege": float(row.privilege),
                "resource_exposure": float(row.resource_exposure),
                "impact": float(row.impact),
                "category": row.category,
                "source": row.source,
            }
        return self

    # ------------------------------------------------------------------ queries
    def profile(self, action: str) -> Dict[str, Any]:
        """Effective profile for one action, including its source."""
        key = (action or "").strip().upper()
        if key in self._overrides:
            return {**self._overrides[key], "action": key}
        builtin = self.config.action_profiles().get(key)
        if builtin:
            return {**DEFAULT_PROFILE, **builtin, "action": key, "source": "BUILTIN"}
        inferred = self._infer(key)
        return {**DEFAULT_PROFILE, **inferred, "action": key or "UNKNOWN", "source": "INFERRED"}

    def risk(self, action: str) -> int:
        return int(self.profile(action).get("risk", 50))

    def band(self, action: str) -> str:
        return band_for_risk(self.risk(action))

    def catalogue(self) -> Dict[str, Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for action, profile in self.config.action_profiles().items():
            merged[action] = {**DEFAULT_PROFILE, **profile, "action": action, "source": "BUILTIN"}
        for action, profile in self._overrides.items():
            merged[action] = {**merged.get(action, {}), **profile, "action": action}
        return dict(sorted(merged.items(), key=lambda item: -int(item[1].get("risk", 0))))

    def known_actions(self) -> List[str]:
        return list(self.catalogue().keys())

    @staticmethod
    def _infer(action: str) -> Dict[str, Any]:
        """Fallback classification for actions an application has not declared.

        Unknown actions are treated as MEDIUM risk, never as safe: an undeclared
        action must not silently become a low-risk one.
        """
        key = action.upper()
        if key.startswith(("VIEW_", "GET_", "LIST_", "SEARCH")):
            return {
                "risk": 20,
                "sensitivity": 0.2,
                "privilege": 0.1,
                "resource_exposure": 0.2,
                "impact": 0.05,
                "category": "READ",
            }
        if key.startswith(("DELETE_", "PURGE_", "WIPE_", "DROP_")):
            return {
                "risk": 95,
                "sensitivity": 0.7,
                "privilege": 0.6,
                "resource_exposure": 0.6,
                "impact": 1.0,
                "category": "DESTRUCTIVE",
            }
        if key.startswith(("CREATE_ADMIN", "GRANT_", "PROMOTE_")):
            return {
                "risk": 97,
                "sensitivity": 0.9,
                "privilege": 1.0,
                "resource_exposure": 0.7,
                "impact": 1.0,
                "category": "PRIVILEGE_ESCALATION",
            }
        if key.startswith(("EXPORT_", "DOWNLOAD_")):
            return {
                "risk": 60,
                "sensitivity": 0.7,
                "privilege": 0.3,
                "resource_exposure": 0.8,
                "impact": 0.5,
                "category": "EXFILTRATION",
            }
        if key.startswith(("CHANGE_SECURITY", "MODIFY_ACCESS", "UPDATE_POLICY")):
            return {
                "risk": 95,
                "sensitivity": 0.9,
                "privilege": 0.8,
                "resource_exposure": 0.4,
                "impact": 1.0,
                "category": "SECURITY_CONFIG",
            }
        if key.startswith(("CHANGE_PASSWORD", "CREATE_API_KEY", "ROTATE_")):
            return {
                "risk": 88,
                "sensitivity": 0.85,
                "privilege": 0.7,
                "resource_exposure": 0.5,
                "impact": 0.9,
                "category": "CREDENTIAL",
            }
        return dict(DEFAULT_PROFILE)


__all__ = ["ActionRiskCatalogue", "band_for_risk", "RISK_BANDS"]
