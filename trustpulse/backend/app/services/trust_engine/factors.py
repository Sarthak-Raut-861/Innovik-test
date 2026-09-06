"""TRUSTPULSE — TCI factor scorers: ``T_t = F(I, D, B, N, C, H)``.

Each scorer takes only what it needs and returns a :class:`FactorScore` with the
reasons behind its value. A scorer that has no evidence marks itself
``available=False`` so fusion renormalizes the remaining weights instead of
silently scoring the session down for our own blind spot.

Every value here comes from :mod:`app.core.trust_config`; nothing is hard-coded.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from trustpulse_ml.trust_fusion.fusion import FactorScore

from app.core.trust_config import TrustModelConfig
from app.schemas.trust import EvidenceRecord


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _naive_aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# --------------------------------------------------------------------------- I
def score_identity(
    *,
    auth_method: str,
    mfa_used: bool,
    session_created_at: Optional[datetime],
    config: TrustModelConfig,
) -> FactorScore:
    """I — Identity assurance: how strongly the user proved who they are."""
    section = config.section("identity_assurance")
    methods: Dict[str, float] = {
        str(k): float(v) for k, v in (section.get("method_scores") or {}).items()
    }
    method = (auth_method or "UNKNOWN").upper()
    base = methods.get(method, float(section.get("unknown_method_score", 40)))
    reasons: List[str] = []

    if method not in methods:
        reasons.append("UNKNOWN_AUTH_METHOD")
    if mfa_used:
        base = max(base, float(methods.get("PASSWORD_MFA", 90)))
        reasons.append("MFA_VERIFIED")
    else:
        reasons.append("MFA_NOT_USED")

    created = _naive_aware(session_created_at)
    if created is not None:
        age_hours = max(0.0, (_now() - created).total_seconds() / 3600.0)
        decay = age_hours * float(section.get("age_decay_per_hour", 1.5))
        if decay > 0:
            base -= decay
            reasons.append("IDENTITY_ASSURANCE_AGED")

    score = max(float(section.get("min_score", 15)), min(100.0, base))
    return FactorScore(
        name="identity",
        score=score,
        weight=float(config.weights.get("identity", 0.15)),
        available=True,
        reasons=reasons,
        detail={"auth_method": method, "mfa_used": bool(mfa_used)},
    )


# --------------------------------------------------------------------------- D
def score_device(
    *,
    device: Optional[Any],
    fingerprint_matches: Optional[bool] = None,
    session_device_fingerprint: Optional[str] = None,
    config: TrustModelConfig = None,  # type: ignore[assignment]
) -> FactorScore:
    """D — Device trust: is this a known, registered, unflagged device?"""
    section = config.section("device_trust")
    if device is None:
        return FactorScore(
            name="device",
            score=0.0,
            weight=float(config.weights.get("device", 0.20)),
            available=False,
            reasons=["NO_DEVICE_CONTEXT"],
        )

    reasons: List[str] = []
    is_flagged = bool(getattr(device, "is_flagged", False))
    is_registered = bool(getattr(device, "is_registered", False))
    observations = int(getattr(device, "observation_count", 0) or 0)
    min_obs = int(section.get("min_observations_for_trust", 5))
    credit = int(section.get("observation_credit_per_session", 6))

    if is_flagged:
        score = float(section.get("flagged_device", 10))
        reasons.append("DEVICE_FLAGGED")
    elif is_registered:
        score = float(section.get("registered_known", 95))
        reasons.append("DEVICE_REGISTERED")
    elif observations > 0:
        score = float(section.get("known_unregistered", 70))
        reasons.append("DEVICE_KNOWN_NOT_REGISTERED")
    else:
        score = float(section.get("new_device", 35))
        reasons.append("NEW_DEVICE")

    if observations < min_obs and not is_flagged:
        score -= max(0.0, (min_obs - observations) * credit * 0.5)
        reasons.append("DEVICE_LOW_HISTORY")

    if fingerprint_matches is False:
        score -= float(section.get("fingerprint_mismatch_penalty", 30))
        reasons.append("DEVICE_FINGERPRINT_MISMATCH")

    return FactorScore(
        name="device",
        score=max(0.0, min(100.0, score)),
        weight=float(config.weights.get("device", 0.20)),
        available=True,
        reasons=reasons,
        detail={
            "trust_level": getattr(device, "trust_level", None),
            "is_registered": is_registered,
            "is_flagged": is_flagged,
            "observation_count": observations,
            "fingerprint": (session_device_fingerprint or "")[:12],
        },
    )


# --------------------------------------------------------------------------- B
def score_behavior(
    *,
    anomaly_score: Optional[float],
    anomaly_reasons: Optional[List[str]],
    core_observations: int,
    shadow_observations: int,
    features_compared: int,
    drift_distance: Optional[float] = None,
    consecutive_anomalies: int = 0,
    config: TrustModelConfig = None,  # type: ignore[assignment]
) -> FactorScore:
    """B — Behavioral confidence from the Trusted Core / Adaptive Shadow comparison.

    ``consecutive_anomalies`` implements evidence accumulation: a deviation that
    repeats is stronger evidence than one that appears once, so sustained
    anomalous interaction keeps eroding the score instead of plateauing.
    """
    section = config.section("behavior")
    reasons: List[str] = []

    if anomaly_score is None:
        # A baseline exists but no fresh observation has arrived yet. That is
        # materially better evidence than a true cold start, and must not be
        # scored as if the user were unknown.
        if core_observations > 0 or shadow_observations > 0:
            return FactorScore(
                name="behavior",
                score=float(section.get("baseline_established_score", 78)),
                weight=float(config.weights.get("behavior", 0.30)),
                available=True,
                reasons=["BASELINE_ESTABLISHED_AWAITING_OBSERVATION"],
                detail={
                    "core_observations": core_observations,
                    "shadow_observations": shadow_observations,
                },
            )
        score = float(section.get("cold_start_score", 55))
        reasons.append("COLD_START_NO_BEHAVIORAL_EVIDENCE")
        return FactorScore(
            name="behavior",
            score=score,
            weight=float(config.weights.get("behavior", 0.30)),
            available=False,
            reasons=reasons,
            detail={"core_observations": 0, "shadow_observations": 0},
        )

    anomaly_weight = float(section.get("anomaly_weight", 1.0))
    score = 100.0 * (1.0 - min(1.0, max(0.0, anomaly_score)) * anomaly_weight)

    if drift_distance is not None and drift_distance == float("inf"):
        reasons.append("BASELINE_INCOMPARABLE")
    elif drift_distance is not None:
        drift_weight = float(section.get("drift_penalty_weight", 0.35))
        penalty = min(30.0, drift_distance * 30.0 * drift_weight)
        score -= penalty
        if penalty > 1.0:
            reasons.append("BASELINE_DEVIATION")

    # Evidence accumulation: repeated anomalies are stronger evidence than one.
    if consecutive_anomalies > 1:
        penalty = min(
            float(section.get("max_sustained_penalty", 40)),
            float(section.get("sustained_anomaly_penalty", 8)) * (consecutive_anomalies - 1),
        )
        score -= penalty
        reasons.append("SUSTAINED_BEHAVIORAL_DEVIATION")

    min_features = int(section.get("min_features_for_full_weight", 6))
    if features_compared < min_features:
        floor = float(section.get("partial_evidence_floor", 0.4))
        coverage = features_compared / max(1, min_features)
        score = max(score * max(floor, coverage), 0.0)
        reasons.append("PARTIAL_BEHAVIORAL_EVIDENCE")

    for reason in anomaly_reasons or []:
        if reason not in reasons:
            reasons.append(reason)

    return FactorScore(
        name="behavior",
        score=max(0.0, min(100.0, score)),
        weight=float(config.weights.get("behavior", 0.30)),
        available=True,
        reasons=reasons,
        detail={
            "anomaly_score": round(float(anomaly_score), 4),
            "features_compared": features_compared,
            "core_observations": core_observations,
            "shadow_observations": shadow_observations,
            "consecutive_anomalies": consecutive_anomalies,
            "drift_distance": None
            if drift_distance in (None, float("inf"))
            else round(drift_distance, 4),
        },
    )


# --------------------------------------------------------------------------- N
def score_network(
    *,
    country: Optional[str],
    asn: Optional[str],
    is_vpn: bool,
    is_proxy_or_tor: bool,
    baseline_country: Optional[str],
    baseline_asn: Optional[str] = None,
    config: TrustModelConfig = None,  # type: ignore[assignment]
) -> FactorScore:
    """N — Network / context confidence."""
    section = config.section("network")
    if not country and not asn:
        return FactorScore(
            name="network",
            score=float(section.get("no_context_score", 60)),
            weight=float(config.weights.get("network", 0.15)),
            available=False,
            reasons=["NO_NETWORK_CONTEXT"],
        )

    reasons: List[str] = []
    same_asn = bool(asn and baseline_asn and asn == baseline_asn)
    same_country = bool(country and baseline_country and country == baseline_country)
    has_baseline = bool(baseline_asn or baseline_country)

    if not has_baseline:
        # Nothing to compare against. A blind spot is not evidence of distrust, so
        # the factor is excluded from fusion -- unless the present context is
        # itself suspicious, which IS evidence and must be scored.
        if is_vpn or is_proxy_or_tor:
            score = 100.0
            reasons.append("NO_NETWORK_BASELINE")
            score -= float(section.get("vpn_penalty", 20)) if is_vpn else 0.0
            score -= float(section.get("tor_or_proxy_penalty", 45)) if is_proxy_or_tor else 0.0
            if is_vpn:
                reasons.append("VPN_DETECTED")
            if is_proxy_or_tor:
                reasons.append("PROXY_OR_TOR_DETECTED")
            return FactorScore(
                name="network",
                score=max(0.0, min(100.0, score)),
                weight=float(config.weights.get("network", 0.15)),
                available=True,
                reasons=reasons,
                detail={
                    "country": country,
                    "asn": asn,
                    "is_vpn": bool(is_vpn),
                    "is_tor": bool(is_proxy_or_tor),
                    "baseline": None,
                },
            )
        return FactorScore(
            name="network",
            score=float(section.get("no_context_score", 60)),
            weight=float(config.weights.get("network", 0.15)),
            available=False,
            reasons=["NO_NETWORK_BASELINE"],
            detail={"country": country, "asn": asn},
        )

    if same_asn:
        score = float(section.get("same_network", 95))
        reasons.append("NETWORK_MATCHES_BASELINE")
    elif same_country:
        score = float(section.get("same_country_new_network", 65))
        reasons.append("NETWORK_SAME_COUNTRY_NEW_ASN")
    elif baseline_country and country and country != baseline_country:
        score = float(section.get("new_country", 35))
        reasons.append("NETWORK_CHANGE")
    else:
        score = float(section.get("same_country_new_network", 65))
        reasons.append("NETWORK_NO_BASELINE_FOR_COMPARISON")

    if is_vpn:
        score -= float(section.get("vpn_penalty", 20))
        reasons.append("VPN_DETECTED")
    if is_proxy_or_tor:
        score -= float(section.get("tor_or_proxy_penalty", 45))
        reasons.append("PROXY_OR_TOR_DETECTED")

    return FactorScore(
        name="network",
        score=max(0.0, min(100.0, score)),
        weight=float(config.weights.get("network", 0.15)),
        available=True,
        reasons=reasons,
        detail={
            "country": country,
            "asn": asn,
            "is_vpn": bool(is_vpn),
            "is_tor": bool(is_proxy_or_tor),
        },
    )


# --------------------------------------------------------------------------- C
def score_session(
    *,
    status: str,
    is_contained: bool,
    created_at: Optional[datetime],
    last_seen_at: Optional[datetime],
    last_telemetry_at: Optional[datetime],
    suspicious_event_count: int,
    step_up_failures: int,
    config: TrustModelConfig = None,  # type: ignore[assignment]
) -> FactorScore:
    """C — Session context: continuity and prior suspicion inside THIS session."""
    section = config.section("session_context")
    reasons: List[str] = []

    if is_contained:
        return FactorScore(
            name="session",
            score=float(section.get("contained_score", 0)),
            weight=float(config.weights.get("session", 0.10)),
            available=True,
            reasons=["SESSION_CONTAINED"],
        )
    if (status or "").upper() in {"TERMINATED", "REVOKED"}:
        return FactorScore(
            name="session",
            score=float(section.get("terminated_score", 0)),
            weight=float(config.weights.get("session", 0.10)),
            available=True,
            reasons=["SESSION_TERMINATED"],
        )

    score = float(section.get("fresh_session_base", 90))

    reference = _naive_aware(last_telemetry_at) or _naive_aware(last_seen_at)
    if reference is not None:
        gap_seconds = max(0.0, (_now() - reference).total_seconds())
        max_gap = float(section.get("max_telemetry_gap_seconds", 300))
        if gap_seconds > max_gap:
            penalty = float(section.get("telemetry_gap_penalty", 25))
            overshoot = min(3.0, gap_seconds / max(1.0, max_gap))
            score -= penalty * min(1.0, overshoot / 3.0 + 0.5)
            reasons.append("TELEMETRY_GAP")

    if suspicious_event_count > 0:
        penalty = float(section.get("prior_suspicion_penalty", 20))
        score -= min(penalty, penalty * 0.5 * suspicious_event_count)
        reasons.append("PRIOR_SUSPICIOUS_EVENTS_IN_SESSION")

    if step_up_failures > 0:
        per_failure = float(section.get("step_up_failure_penalty", 15))
        cap = float(section.get("step_up_failure_penalty_max", 30))
        score -= min(cap, per_failure * step_up_failures)
        reasons.append("STEP_UP_FAILURES_IN_SESSION")

    return FactorScore(
        name="session",
        score=max(0.0, min(100.0, score)),
        weight=float(config.weights.get("session", 0.10)),
        available=True,
        reasons=reasons,
        detail={
            "status": status,
            "suspicious_events": suspicious_event_count,
            "step_up_failures": step_up_failures,
            "session_age_seconds": (
                round((_now() - _naive_aware(created_at)).total_seconds())
                if _naive_aware(created_at)
                else None
            ),
        },
    )


# --------------------------------------------------------------------------- H
def score_history(
    *,
    rolling_tci_values: Optional[List[float]],
    past_incident_count: int,
    step_up_failure_count: int,
    config: TrustModelConfig = None,  # type: ignore[assignment]
) -> FactorScore:
    """H — Historical evidence for this user/device across previous sessions."""
    section = config.section("history")
    neutral = float(section.get("neutral", 75))
    reasons: List[str] = []

    score = neutral
    values = [float(v) for v in (rolling_tci_values or []) if v is not None]
    if values:
        rolling_weight = float(section.get("rolling_history_weight", 0.4))
        average = sum(values) / len(values)
        score = (1 - rolling_weight) * neutral + rolling_weight * average
        reasons.append("HISTORY_ROLLING_TCI")
        if average < 50:
            reasons.append("HISTORY_RISK")
    else:
        reasons.append("NO_SESSION_HISTORY")

    score -= min(60.0, float(section.get("per_past_incident_penalty", 18)) * past_incident_count)
    if past_incident_count:
        reasons.append("PAST_INCIDENTS")
    score -= min(
        30.0, float(section.get("per_step_up_failure_penalty", 12)) * step_up_failure_count
    )
    if step_up_failure_count:
        reasons.append("PAST_STEP_UP_FAILURES")

    return FactorScore(
        name="history",
        score=max(float(section.get("min_score", 5)), min(100.0, score)),
        weight=float(config.weights.get("history", 0.10)),
        available=True,
        reasons=reasons,
        detail={
            "samples": len(values),
            "past_incidents": past_incident_count,
            "step_up_failures": step_up_failure_count,
        },
    )


# --------------------------------------------------------------- evidence helper
def evidence_from_factors(
    factors: List[FactorScore],
    *,
    now: Optional[datetime] = None,
) -> List[EvidenceRecord]:
    """Turns factor reasons into explainable evidence records for the SOC."""
    observed_at = now or _now()
    mapping = {
        "identity": ("IDENTITY_ASSURANCE_DROP", 60.0),
        "device": ("DEVICE_CHANGE", 60.0),
        "behavior": ("BEHAVIOR_DEVIATION", 70.0),
        "network": ("NETWORK_CHANGE", 55.0),
        "session": ("SESSION_ANOMALY", 50.0),
        "history": ("HISTORY_RISK", 45.0),
    }
    records: List[EvidenceRecord] = []
    for factor in factors:
        if not factor.available or factor.score >= 75:
            continue
        event_type, base_severity = mapping.get(factor.name, ("SESSION_ANOMALY", 40.0))
        severity = max(0.05, min(1.0, (base_severity + (100 - factor.score)) / 200.0))
        description = _describe(factor)
        records.append(
            EvidenceRecord(
                type=event_type,
                severity=round(severity, 2),
                description=description,
                source="TRUST_ENGINE",
                observed_at=observed_at,
                metadata={"factor": factor.name, "factor_score": round(factor.score, 2)},
            )
        )
    return records


def _describe(factor: FactorScore) -> str:
    labels = {
        "identity": "Identity assurance",
        "device": "Device trust",
        "behavior": "Behavioral confidence",
        "network": "Network/context confidence",
        "session": "Session context",
        "history": "Historical evidence",
    }
    label = labels.get(factor.name, factor.name.title())
    reasons = ", ".join(factor.reasons[:4]) if factor.reasons else "no detail"
    return f"{label} is {factor.score:.0f}/100 ({reasons})"


__all__ = [
    "evidence_from_factors",
    "score_behavior",
    "score_device",
    "score_history",
    "score_identity",
    "score_network",
    "score_session",
]
