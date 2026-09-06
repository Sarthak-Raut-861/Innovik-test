"""Trust fusion package."""

from trustpulse_ml.trust_fusion.fusion import (
    DEFAULT_WEIGHTS,
    FACTOR_NAMES,
    FactorScore,
    FusionResult,
    classify_confidence,
    compute_trend,
    fuse_factors,
    validate_weights,
)

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
