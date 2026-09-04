"""
TrustPulse AI — Risk & Confidence Calibration Constants.

These are engineering categories, not probabilities. Real-world calibration
tracks false positive rate, false negative rate, precision, recall, and
detection latency.
"""

from app.core.config import settings


class CalibrationConfig:
    # Signal weights (sum to 1.0). These are defaults and can be overridden by server-side policy.
    WEIGHT_BEHAVIOR: float = 0.45
    WEIGHT_DEVICE: float = 0.25
    WEIGHT_NETWORK: float = 0.15
    WEIGHT_SESSION_HISTORY: float = 0.15

    # Confidence categories (as defined by the product spec):
    # 0-30 LOW, 31-60 GUARDED, 61-80 MODERATE, 81-100 HIGH
    THRESHOLD_MODERATE: int = settings.MODERATE_CONFIDENCE_THRESHOLD  # 60
    THRESHOLD_HIGH: int = settings.HIGH_CONFIDENCE_THRESHOLD  # 80
    LOW_MAX: int = settings.LOW_CONFIDENCE_MAX  # 30

    @classmethod
    def classify_level(cls, score: int) -> str:
        score = max(0, min(100, int(score)))
        if score >= cls.THRESHOLD_HIGH:
            return "HIGH"
        if score >= cls.THRESHOLD_MODERATE:
            return "MODERATE"
        if score > cls.LOW_MAX:
            return "GUARDED"
        return "LOW"
