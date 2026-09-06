"""TRUSTPULSE — Trust state machine with hysteresis.

Why hysteresis: a TCI that oscillates around a band boundary would otherwise flip
the SOC view (and downstream policy) on every single telemetry packet. Two
mechanisms prevent that:

* **Escalation needs evidence.** Moving to a worse state requires either
  decisive evidence — a sharp single-step TCI drop (``decisive_drop``), a jump of
  two or more severity levels (``multi_level_escalation``), or a score landing
  ``decisive_depth`` points below the current state's floor — or the same worse
  band being observed ``escalation_confirmations`` times in a row.
* **Recovery is deliberately slow.** Moving back to a better state requires the
  score to clear the band minimum plus ``recovery_buffer`` for
  ``recovery_confirmations`` consecutive evaluations, no open incident, and the
  current state must not be terminal.

``BLOCKED`` and ``CONTAINED`` never recover automatically — an operator or the
application must explicitly re-establish the session.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from app.core.trust_config import TrustModelConfig
from app.schemas.trust import STATE_SEVERITY, TrustStateEnum


@dataclass
class StateTransition:
    """Result of one state-machine step."""

    state: str
    previous_state: Optional[str]
    raw_band: str
    changed: bool
    hysteresis_applied: bool
    reason: str
    severity: int
    detail: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "state": self.state,
            "previous_state": self.previous_state,
            "raw_band": self.raw_band,
            "changed": self.changed,
            "hysteresis_applied": self.hysteresis_applied,
            "reason": self.reason,
            "severity": self.severity,
            "detail": dict(self.detail),
        }


class TrustStateMachine:
    """Hysteresis-filtered trust state transitions."""

    def __init__(self, config: TrustModelConfig) -> None:
        self.config = config
        hysteresis = config.hysteresis()
        self.escalation_confirmations = int(hysteresis.get("escalation_confirmations", 2))
        self.recovery_buffer = float(hysteresis.get("recovery_buffer", 6))
        self.recovery_confirmations = int(hysteresis.get("recovery_confirmations", 3))
        # A single-step collapse this large is itself decisive evidence and is not
        # held for confirmation — waiting would be a security failure, not caution.
        self.decisive_drop = float(hysteresis.get("decisive_drop", 15))
        # How far below the CURRENT state's floor a score must land to count as
        # decisive on level alone. (It cannot be measured against the target
        # band's floor: being in that band already means tci >= its minimum.)
        self.decisive_depth = float(hysteresis.get("decisive_depth", 10))
        self.multi_level_escalation = int(hysteresis.get("multi_level_escalation", 2))
        self.no_auto_recovery = {
            str(state)
            for state in hysteresis.get("no_auto_recovery_states", ["BLOCKED", "CONTAINED"])
        }
        self.no_recovery_with_incident = bool(
            hysteresis.get("no_recovery_with_open_incident", True)
        )

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def severity(state: Optional[str]) -> int:
        return STATE_SEVERITY.get((state or "TRUSTED").upper(), 0)

    def band_minimum(self, state: str) -> float:
        for band in self.config.state_bands():
            if str(band["state"]).upper() == state.upper():
                return float(band["min"])
        return 0.0

    @staticmethod
    def _consecutive_recent(bands: Sequence[str], predicate) -> int:
        """Counts how many of the most recent raw bands satisfy ``predicate``."""
        count = 0
        for band in reversed(list(bands)):
            if predicate(band):
                count += 1
            else:
                break
        return count

    # ------------------------------------------------------------------ core
    def next_state(
        self,
        *,
        current_state: Optional[str],
        tci: float,
        recent_raw_bands: Sequence[str],
        previous_tci: Optional[float] = None,
        is_contained: bool = False,
        is_revoked: bool = False,
        open_incident: bool = False,
    ) -> StateTransition:
        """Compute the next trust state for one TCI observation.

        ``previous_tci`` enables decisive-drop escalation: a single-step collapse
        is treated as evidence in its own right and is not held for confirmation.
        """
        raw_band = self.config.state_for_tci(tci).upper()
        # ``recent_raw_bands`` excludes the current observation; append it so the
        # confirmation window always includes "now".
        window: List[str] = [str(band).upper() for band in recent_raw_bands] + [raw_band]
        previous = (current_state or TrustStateEnum.TRUSTED.value).upper()

        if is_contained:
            return StateTransition(
                state=TrustStateEnum.CONTAINED.value,
                previous_state=previous,
                raw_band=raw_band,
                changed=previous != TrustStateEnum.CONTAINED.value,
                hysteresis_applied=False,
                reason="SESSION_CONTAINED",
                severity=self.severity(TrustStateEnum.CONTAINED.value),
            )
        if is_revoked and previous != TrustStateEnum.CONTAINED.value:
            return StateTransition(
                state=TrustStateEnum.BLOCKED.value,
                previous_state=previous,
                raw_band=raw_band,
                changed=previous != TrustStateEnum.BLOCKED.value,
                hysteresis_applied=False,
                reason="SESSION_REVOKED",
                severity=self.severity(TrustStateEnum.BLOCKED.value),
            )

        # The very first assessment of a session has no history to smooth, so the
        # raw band is applied directly instead of being "held" against nothing.
        if previous_tci is None and not recent_raw_bands:
            return StateTransition(
                state=raw_band,
                previous_state=previous,
                raw_band=raw_band,
                changed=previous != raw_band,
                hysteresis_applied=False,
                reason="INITIAL_ASSESSMENT",
                severity=self.severity(raw_band),
                detail={"tci": round(tci, 2)},
            )

        target_severity = self.severity(raw_band)
        current_severity = self.severity(previous)

        # ------------------------------------------------------- no change needed
        if target_severity == current_severity:
            return StateTransition(
                state=raw_band,
                previous_state=previous,
                raw_band=raw_band,
                changed=False,
                hysteresis_applied=False,
                reason="STABLE_WITHIN_BAND",
                severity=target_severity,
            )

        # ------------------------------------------------------------- escalation
        if target_severity > current_severity:
            drop = (previous_tci - tci) if previous_tci is not None else 0.0
            decisive_drop = drop >= self.decisive_drop
            multi_level = (target_severity - current_severity) >= self.multi_level_escalation
            decisive_score = tci <= self.band_minimum(previous) - self.decisive_depth
            decisive = decisive_drop or multi_level or decisive_score

            confirmations = self._consecutive_recent(
                window, lambda band: self.severity(band) >= target_severity
            )
            confirmed = confirmations >= max(1, self.escalation_confirmations)

            if decisive or confirmed:
                if decisive_drop:
                    reason = "ESCALATED_ON_SHARP_TCI_DROP"
                elif multi_level:
                    reason = "ESCALATED_ON_MULTI_LEVEL_DROP"
                elif decisive_score:
                    reason = "ESCALATED_ON_LOW_SCORE"
                else:
                    reason = "ESCALATED_AFTER_CONFIRMATION"
                return StateTransition(
                    state=raw_band,
                    previous_state=previous,
                    raw_band=raw_band,
                    changed=True,
                    hysteresis_applied=not decisive,
                    reason=reason,
                    severity=target_severity,
                    detail={
                        "tci": round(tci, 2),
                        "previous_tci": None if previous_tci is None else round(previous_tci, 2),
                        "drop": round(drop, 2),
                        "confirmations": confirmations,
                        "required": self.escalation_confirmations,
                    },
                )

            return StateTransition(
                state=previous,
                previous_state=previous,
                raw_band=raw_band,
                changed=False,
                hysteresis_applied=True,
                reason="ESCALATION_HELD_PENDING_CONFIRMATION",
                severity=current_severity,
                detail={
                    "tci": round(tci, 2),
                    "previous_tci": None if previous_tci is None else round(previous_tci, 2),
                    "drop": round(drop, 2),
                    "confirmations": confirmations,
                    "required": self.escalation_confirmations,
                    "decisive_drop_required": self.decisive_drop,
                    "decisive_score_threshold": round(
                        self.band_minimum(previous) - self.decisive_depth, 2
                    ),
                },
            )

        # ------------------------------------------------------------- recovery
        if previous in self.no_auto_recovery:
            return StateTransition(
                state=previous,
                previous_state=previous,
                raw_band=raw_band,
                changed=False,
                hysteresis_applied=True,
                reason="NO_AUTO_RECOVERY_FROM_TERMINAL_STATE",
                severity=current_severity,
            )
        if open_incident and self.no_recovery_with_incident:
            return StateTransition(
                state=previous,
                previous_state=previous,
                raw_band=raw_band,
                changed=False,
                hysteresis_applied=True,
                reason="RECOVERY_BLOCKED_BY_OPEN_INCIDENT",
                severity=current_severity,
            )

        decisive_recovery = tci >= self.band_minimum(raw_band) + self.recovery_buffer
        confirmations = self._consecutive_recent(
            window, lambda band: self.severity(band) <= target_severity
        )
        if decisive_recovery and confirmations >= max(1, self.recovery_confirmations):
            return StateTransition(
                state=raw_band,
                previous_state=previous,
                raw_band=raw_band,
                changed=True,
                hysteresis_applied=True,
                reason="RECOVERED_AFTER_SUSTAINED_IMPROVEMENT",
                severity=target_severity,
                detail={
                    "tci": round(tci, 2),
                    "confirmations": confirmations,
                    "required": self.recovery_confirmations,
                },
            )

        return StateTransition(
            state=previous,
            previous_state=previous,
            raw_band=raw_band,
            changed=False,
            hysteresis_applied=True,
            reason="RECOVERY_HELD_PENDING_CONFIRMATION",
            severity=current_severity,
            detail={
                "tci": round(tci, 2),
                "confirmations": confirmations,
                "required": self.recovery_confirmations,
            },
        )


__all__ = ["StateTransition", "TrustStateMachine"]
