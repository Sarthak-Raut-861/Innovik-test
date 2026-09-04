"""
TrustPulse AI - Session Confidence Engine
"""

from typing import Dict, Any, Optional, List, Tuple
from app.engines.risk.signal_fusion import SignalFusionEngine
from app.core.config import settings


class SessionConfidenceEngine:
    """
    Evaluates continuous session confidence from multi-source signals.
    """

    @staticmethod
    def calculate_confidence(
        anomaly_score: float,
        is_cold_start: bool = False,
        device_matched: bool = True,
        network_suspicious: bool = False,
        open_incident: bool = False,
    ) -> Tuple[int, str, List[str]]:
        """
        Returns (confidence_score [0-100], confidence_level [str], reason_codes [List[str]])
        """
        reason_codes: List[str] = []

        if open_incident:
            reason_codes.append("ACTIVE_SECURITY_INCIDENT")
            return 15, "LOW", reason_codes

        if is_cold_start:
            reason_codes.append("COLD_START_NO_BASELINE")
            # Cold start defaults to guarded confidence (e.g. 40)
            return settings.COLD_START_CONFIDENCE, "GUARDED", reason_codes

        # Behavior signal: 1.0 (normal) to 0.0 (high anomaly)
        behavior_signal = max(0.0, 1.0 - anomaly_score)
        if anomaly_score >= 0.5:
            reason_codes.append("BEHAVIOR_ANOMALY")

        # Device signal
        device_signal = 1.0 if device_matched else 0.4
        if not device_matched:
            reason_codes.append("NEW_OR_CHANGED_DEVICE")

        # Network signal
        network_signal = 0.3 if network_suspicious else 1.0
        if network_suspicious:
            reason_codes.append("SUSPICIOUS_NETWORK")

        score, level = SignalFusionEngine.fuse_signals(
            behavior_signal=behavior_signal,
            device_signal=device_signal,
            network_signal=network_signal,
            session_history_signal=1.0,
        )

        return score, level, reason_codes
