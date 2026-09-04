"""
TrustPulse AI - Multi-Signal Fusion Engine
"""

from typing import Dict, Any, List, Tuple
from app.engines.risk.calibration import CalibrationConfig


class SignalFusionEngine:
    """
    Combines independent security signals (behavioral biometrics, device technical context,
    network consistency, and session progression) into a unified evidence confidence.
    Enforces Core Rule 4: "No single signal is trusted absolutely."
    """

    @staticmethod
    def fuse_signals(
        behavior_signal: float,        # 0.0 (anomalous) to 1.0 (normal)
        device_signal: float,          # 0.0 (mismatched) to 1.0 (consistent)
        network_signal: float = 1.0,   # 0.0 (suspicious) to 1.0 (normal)
        session_history_signal: float = 1.0,
    ) -> Tuple[int, str]:
        """
        Calculates composite confidence score [0 - 100] and confidence level.
        """
        w_b = CalibrationConfig.WEIGHT_BEHAVIOR
        w_d = CalibrationConfig.WEIGHT_DEVICE
        w_n = CalibrationConfig.WEIGHT_NETWORK
        w_h = CalibrationConfig.WEIGHT_SESSION_HISTORY

        composite = (
            (behavior_signal * w_b)
            + (device_signal * w_d)
            + (network_signal * w_n)
            + (session_history_signal * w_h)
        )

        score = int(round(composite * 100))
        score = max(0, min(100, score))
        level = CalibrationConfig.classify_level(score)

        return score, level
