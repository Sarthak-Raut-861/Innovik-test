"""
TrustPulse AI - Risk & Confidence Calibration Constants
"""

from typing import Dict


class CalibrationConfig:
    # Signal Weights (sum to 1.0)
    WEIGHT_BEHAVIOR: float = 0.45
    WEIGHT_DEVICE: float = 0.25
    WEIGHT_NETWORK: float = 0.15
    WEIGHT_SESSION_HISTORY: float = 0.15

    # Confidence Thresholds
    THRESHOLD_HIGH: int = 80
    THRESHOLD_MODERATE: int = 60
    THRESHOLD_GUARDED: int = 30

    @classmethod
    def classify_level(cls, score: int) -> str:
        if score >= cls.THRESHOLD_HIGH:
            return "HIGH"
        elif score >= cls.THRESHOLD_MODERATE:
            return "MODERATE"
        elif score >= cls.THRESHOLD_GUARDED:
            return "GUARDED"
        return "LOW"
