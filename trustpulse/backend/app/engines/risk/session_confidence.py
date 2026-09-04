"""
TrustPulse AI — Session Confidence Engine.

Produces an evidence-based, normalized confidence score (0-100), plus a category
(LOW / GUARDED / MODERATE / HIGH). The score is NOT a probability that a user is
real, and is never used directly by the browser.
"""

from typing import List, Tuple

from app.core.config import settings
from app.engines.risk.calibration import CalibrationConfig
from app.engines.risk.signal_fusion import SignalFusionEngine


class SessionConfidenceEngine:
    @staticmethod
    def calculate_confidence(
        anomaly_score: float,
        is_cold_start: bool = False,
        device_matched: bool = False,
        device_evidence_available: bool = False,
        network_suspicious: bool = False,
        network_evidence_available: bool = False,
        session_history_signal: float = 1.0,
        open_incident: bool = False,
    ) -> Tuple[int, str, List[str]]:
        """Returns (confidence_score, confidence_level, reason_codes)."""
        reason_codes: List[str] = []

        if open_incident:
            reason_codes.append("ACTIVE_SECURITY_INCIDENT")
            return 15, "LOW", reason_codes

        if is_cold_start:
            reason_codes.append("COLD_START_NO_BASELINE")
            # Missing evidence is neither trusted nor malicious. Cold start is LOW
            # confidence and sensitive actions require step-up/block per policy.
            return (
                settings.COLD_START_CONFIDENCE,
                CalibrationConfig.classify_level(settings.COLD_START_CONFIDENCE),
                reason_codes,
            )

        behavior_signal = max(0.0, 1.0 - anomaly_score)
        if anomaly_score >= 0.5:
            reason_codes.append("BEHAVIOR_ANOMALY")

        if device_evidence_available:
            device_signal = 1.0 if device_matched else 0.4
            if not device_matched:
                reason_codes.append("NEW_DEVICE")
        else:
            # Unknown device evidence is not trust and not proof of compromise.
            device_signal = 0.6
            reason_codes.append("NO_DEVICE_EVIDENCE")

        if network_evidence_available:
            network_signal = 0.3 if network_suspicious else 1.0
            if network_suspicious:
                reason_codes.append("SUSPICIOUS_NETWORK")
        else:
            network_signal = 0.85
            reason_codes.append("NO_NETWORK_EVIDENCE")

        score, level = SignalFusionEngine.fuse_signals(
            behavior_signal=behavior_signal,
            device_signal=device_signal,
            network_signal=network_signal,
            session_history_signal=max(0.0, min(1.0, session_history_signal)),
        )
        return score, level, reason_codes
