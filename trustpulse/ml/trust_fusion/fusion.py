"""TCI trust fusion.

``TCI = F(I, D, B, N, C, H)``

Each factor is an independent 0-100 sub-score produced by the trust engine. The
fusion step is a weighted mean with two properties that matter for a security
product:

* **Missing factors are excluded, not zeroed.** If the network context is
  unavailable we renormalize the remaining weights instead of punishing the
  session for our own blind spot.
* **Evidence coverage is reported separately from the score.** A high TCI
  computed from one factor is labelled ``LOW`` confidence, so downstream policy
  can refuse to rely on it.

TCI is an engineering trust index. It is NOT a probability and must never be
described as one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

FACTOR_NAMES: Tuple[str, ...] = (
    "identity",
    "device",
    "behavior",
    "network",
    "session",
    "history",
)

DEFAULT_WEIGHTS: Dict[str, float] = {
    "identity": 0.15,
    "device": 0.20,
    "behavior": 0.30,
    "network": 0.15,
    "session": 0.10,
    "history": 0.10,
}


@dataclass
class FactorScore:
    """One TCI factor: a score, its configured weight and why it got that score."""

    name: str
    score: float
    weight: float
    available: bool = True
    reasons: List[str] = field(default_factory=list)
    detail: Dict[str, object] = field(default_factory=dict)

    def clamp(self) -> "FactorScore":
        self.score = max(0.0, min(100.0, float(self.score)))
        self.weight = max(0.0, float(self.weight))
        return self

    def to_dict(self, effective_weight: Optional[float] = None) -> Dict[str, object]:
        return {
            "name": self.name,
            "score": round(self.score, 2),
            "configured_weight": round(self.weight, 4),
            "effective_weight": round(
                self.weight if effective_weight is None else effective_weight, 4
            ),
            "available": self.available,
            "contribution": round(
                self.score * (self.weight if effective_weight is None else effective_weight), 2
            ),
            "reasons": list(self.reasons),
            "detail": dict(self.detail),
        }


@dataclass
class FusionResult:
    """The TCI plus everything needed to explain it."""

    tci: float
    confidence: str  # HIGH | MEDIUM | LOW
    trend: str  # RISING | STABLE | FALLING | INSUFFICIENT_DATA
    available_weight: float
    factors: List[FactorScore]
    effective_weights: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def contributions(self) -> List[Dict[str, object]]:
        return [f.to_dict(self.effective_weights.get(f.name)) for f in self.factors]

    def to_dict(self) -> Dict[str, object]:
        return {
            "tci": round(self.tci, 1),
            "confidence": self.confidence,
            "trend": self.trend,
            "available_weight": round(self.available_weight, 4),
            "factors": self.contributions(),
            "warnings": list(self.warnings),
        }


def validate_weights(weights: Dict[str, float]) -> Dict[str, float]:
    """Clamps weights to >= 0. Unknown factor names are rejected loudly."""
    unknown = [name for name in weights if name not in FACTOR_NAMES]
    if unknown:
        raise ValueError(f"Unknown TCI factor(s): {', '.join(sorted(unknown))}")
    cleaned = {
        name: max(0.0, float(weights.get(name, DEFAULT_WEIGHTS[name]))) for name in FACTOR_NAMES
    }
    total = sum(cleaned.values())
    if total <= 0:
        raise ValueError("TCI weights must not all be zero")
    return cleaned


def fuse_factors(
    factors: Sequence[FactorScore],
    weights: Optional[Dict[str, float]] = None,
    evidence_features: int = 0,
    high_confidence_min_features: int = 8,
    medium_confidence_min_features: int = 4,
    history: Optional[Sequence[float]] = None,
    scale_max: float = 100.0,
    min_weight_coverage: float = 0.35,
) -> FusionResult:
    """Weighted fusion of the six TCI factors."""
    configured = validate_weights(weights or DEFAULT_WEIGHTS)
    supplied = {f.name: f.clamp() for f in factors if f.name in FACTOR_NAMES}

    available = [f for f in supplied.values() if f.available]
    missing = [
        name for name in FACTOR_NAMES if name not in supplied or not supplied[name].available
    ]

    warnings: List[str] = []
    available_weight = sum(configured[name] for name in (f.name for f in available))

    if not available or available_weight <= 0:
        for name in missing:
            warnings.append(f"FACTOR_UNAVAILABLE:{name}")
        return FusionResult(
            tci=0.0,
            confidence="LOW",
            trend=compute_trend(history or []),
            available_weight=0.0,
            factors=list(supplied.values()),
            effective_weights={},
            warnings=warnings + ["NO_FACTOR_EVIDENCE"],
        )

    if available_weight < min_weight_coverage:
        warnings.append("LOW_FACTOR_COVERAGE")

    effective: Dict[str, float] = {f.name: configured[f.name] / available_weight for f in available}
    tci = float(sum(f.score * effective[f.name] for f in available))
    tci = max(0.0, min(scale_max, tci))

    for name in missing:
        warnings.append(f"FACTOR_UNAVAILABLE:{name}")

    confidence = classify_confidence(
        available_weight=available_weight,
        evidence_features=evidence_features,
        high_min_features=high_confidence_min_features,
        medium_min_features=medium_confidence_min_features,
    )

    ordered = [supplied[name] for name in FACTOR_NAMES if name in supplied]
    return FusionResult(
        tci=tci,
        confidence=confidence,
        trend=compute_trend(history or []),
        available_weight=available_weight,
        factors=ordered,
        effective_weights=effective,
        warnings=warnings,
    )


def classify_confidence(
    available_weight: float,
    evidence_features: int,
    high_min_features: int = 8,
    medium_min_features: int = 4,
) -> str:
    """Evidence sufficiency, deliberately separate from the TCI value itself."""
    if available_weight >= 0.85 and evidence_features >= high_min_features:
        return "HIGH"
    if available_weight >= 0.6 and evidence_features >= medium_min_features:
        return "MEDIUM"
    return "LOW"


def compute_trend(history: Sequence[float], window: int = 5, slope_threshold: float = 0.75) -> str:
    """Direction of travel of the TCI over the last ``window`` samples.

    Uses an ordinary least-squares slope so that a single jittery sample does not
    flip the displayed trend.
    """
    values = [float(v) for v in history if v is not None][-window:]
    if len(values) < 3:
        return "INSUFFICIENT_DATA"
    x = np.arange(len(values), dtype=float)
    y = np.asarray(values, dtype=float)
    slope = float(np.polyfit(x, y, 1)[0])
    if slope <= -slope_threshold:
        return "FALLING"
    if slope >= slope_threshold:
        return "RISING"
    return "STABLE"


__all__ = [
    "DEFAULT_WEIGHTS",
    "FACTOR_NAMES",
    "FactorScore",
    "FusionResult",
    "classify_confidence",
    "compute_trend",
    "fuse_factors",
    "validate_weights",
]
