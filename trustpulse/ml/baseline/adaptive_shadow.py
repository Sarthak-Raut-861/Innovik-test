"""Adaptive Shadow baseline + baseline-poisoning protection.

The shadow learns *gradual legitimate drift* quickly (alpha 0.25 by default) so
that a real user whose typing rhythm changes with a new keyboard or after an
injury is not permanently flagged.

Poisoning protection (all four must hold before promotion):

1. ``min_observations`` shadow observations have accumulated;
2. the session supplying them is not SUSPICIOUS / CRITICAL / BLOCKED / CONTAINED;
3. there is no open incident for the user/device;
4. shadow↔core distance is below ``max_promotion_distance`` — a shadow that has
   drifted too far is quarantined and reset instead of promoted.

Observations from suspicious sessions are *counted as rejected*, never learned.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from trustpulse_ml.baseline.trusted_core import Baseline, TrustedCore, baseline_distance

DEFAULT_SHADOW_ALPHA = 0.25

# Trust states whose observations may never train the core.
UNTRUSTED_STATES: Tuple[str, ...] = ("SUSPICIOUS", "CRITICAL", "BLOCKED", "CONTAINED")


@dataclass(frozen=True)
class PromotionDecision:
    """Outcome of the shadow -> core promotion gate."""

    promote: bool
    reasons: List[str]
    distance: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "promote": self.promote,
            "reasons": list(self.reasons),
            "distance": None if self.distance == float("inf") else round(self.distance, 6),
        }


class AdaptiveShadow:
    """Fast-learning shadow baseline with a hardened promotion gate."""

    def __init__(
        self,
        alpha: float = DEFAULT_SHADOW_ALPHA,
        min_observations: int = 8,
        max_promotion_distance: float = 1.2,
    ) -> None:
        self.alpha = max(0.01, min(0.9, alpha))
        self.min_observations = max(1, int(min_observations))
        self.max_promotion_distance = max(0.0, float(max_promotion_distance))
        self._core = TrustedCore()

    # ------------------------------------------------------------------ learning
    def update(
        self,
        shadow: Baseline,
        observation: Dict[str, float],
        trust_state: str,
        open_incident: bool = False,
    ) -> Tuple[Baseline, bool]:
        """Absorb an observation *if the session is trustworthy enough to learn*.

        Returns ``(shadow, learned)``. When the session is untrusted the shadow is
        returned untouched and ``learned`` is False — the core is never reachable
        from a suspicious session, directly or indirectly.
        """
        if open_incident or (trust_state or "").upper() in UNTRUSTED_STATES:
            return self._core.record_rejection(shadow), False
        return self._core.update(shadow, observation, alpha=self.alpha), True

    # ------------------------------------------------------------------ promotion
    def promotion_decision(
        self,
        core: Baseline,
        shadow: Baseline,
        trust_state: str,
        open_incident: bool = False,
        recent_rejections: int = 0,
    ) -> PromotionDecision:
        """Decide whether the shadow may be blended into the Trusted Core."""
        reasons: List[str] = []
        distance = baseline_distance(core, shadow)

        if shadow.is_empty() or shadow.observation_count < self.min_observations:
            reasons.append("SHADOW_INSUFFICIENT_OBSERVATIONS")
        if (trust_state or "").upper() in UNTRUSTED_STATES:
            reasons.append("SESSION_NOT_TRUSTWORTHY")
        if open_incident:
            reasons.append("OPEN_INCIDENT")
        if recent_rejections > 0 and recent_rejections >= shadow.observation_count:
            reasons.append("ALL_OBSERVATIONS_REJECTED")
        if not core.is_empty() and distance > self.max_promotion_distance:
            reasons.append("DRIFT_TOO_LARGE_QUARANTINED")

        return PromotionDecision(promote=not reasons, reasons=reasons, distance=distance)

    def promote(
        self,
        core: Baseline,
        shadow: Baseline,
        trust_state: str,
        open_incident: bool = False,
        recent_rejections: int = 0,
        blend_alpha: float = 0.1,
    ) -> Tuple[Baseline, PromotionDecision]:
        """Blend the shadow into the core when the gate passes.

        A failed gate never mutates the core. When drift is too large the shadow is
        reset (quarantined) so a poisoned shadow cannot keep accumulating.
        """
        decision = self.promotion_decision(
            core, shadow, trust_state, open_incident, recent_rejections
        )
        if not decision.promote:
            if "DRIFT_TOO_LARGE_QUARANTINED" in decision.reasons:
                return core, decision
            return core, decision

        promoted = self._core.update(core, shadow.means, alpha=blend_alpha)
        return promoted, decision

    def reset(self) -> Baseline:
        """Returns an empty shadow (quarantine / rotation)."""
        return Baseline()


def summarize(core: Baseline, shadow: Baseline) -> Dict[str, Optional[object]]:
    """Compact, non-sensitive summary for APIs and the SOC dashboard."""
    return {
        "core_observations": core.observation_count,
        "core_version": core.version,
        "core_features": len(core.means),
        "core_rejected_observations": core.rejected_observations,
        "shadow_observations": shadow.observation_count,
        "shadow_version": shadow.version,
        "shadow_core_distance": (
            None if baseline_distance(core, shadow) == float("inf")
            else round(baseline_distance(core, shadow), 6)
        ),
    }


def drift_report(core: Baseline, shadow: Baseline, top_n: int = 5) -> List[Dict[str, float]]:
    """Largest per-feature drifts between core and shadow (explainability only)."""
    shared: Sequence[str] = sorted(set(core.means) & set(shadow.means))
    deltas: List[Dict[str, float]] = []
    for name in shared:
        delta = shadow.means[name] - core.means[name]
        scale = max(core.stds.get(name, 1.0), 0.05)
        deltas.append({"feature": name, "delta": delta, "sigma": delta / scale})  # type: ignore[arg-type]
    deltas.sort(key=lambda item: abs(item["sigma"]), reverse=True)
    return deltas[:top_n]
