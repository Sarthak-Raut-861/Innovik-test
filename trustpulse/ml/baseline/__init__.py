"""Baseline package: Trusted Core + Adaptive Shadow."""

from trustpulse_ml.baseline.adaptive_shadow import (
    UNTRUSTED_STATES,
    AdaptiveShadow,
    PromotionDecision,
    drift_report,
    summarize,
)
from trustpulse_ml.baseline.trusted_core import Baseline, TrustedCore, baseline_distance

__all__ = [
    "UNTRUSTED_STATES",
    "AdaptiveShadow",
    "Baseline",
    "PromotionDecision",
    "TrustedCore",
    "baseline_distance",
    "drift_report",
    "summarize",
]
