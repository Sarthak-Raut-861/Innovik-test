"""Privacy-minimized behavioral feature schema and normalization.

Contract
--------
* Input is **derived aggregate telemetry** produced by the browser SDK: means,
  standard deviations, rates and counts. Never raw events, never characters.
* Output is a canonical ``feature_name -> float`` vector in stable units.
* Any payload key that looks like raw text (typed characters, key values,
  element text) is rejected rather than silently dropped, because accepting it
  would violate the project privacy rule "never store actual typed characters".
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Keys that must never reach the server. Matched case-insensitively.
FORBIDDEN_KEY_PATTERNS: Tuple[str, ...] = (
    "character",
    "charcode",
    "keyvalue",
    "key_value",
    "keystroke",
    "keypress",
    "password",
    "secret",
    "token",
    "clipboard",
    "selection",
    "inputvalue",
    "input_value",
    "text",
    "content",
    "email",
    "phone",
    "ssn",
    "cardnumber",
)


class RawDataRejectedError(ValueError):
    """Raised when a payload appears to carry raw (non-derived) data."""


@dataclass(frozen=True)
class FeatureSpec:
    """Definition of one canonical behavioral feature."""

    name: str
    sdk_paths: Tuple[str, ...]
    minimum: float
    maximum: float
    unit: str
    log_scale: bool = False
    is_count: bool = False  # counts are metadata, excluded from the baseline vector
    relative_std: float = 0.15  # expected human variation, expressed in RAW units

    def clamp(self, value: float) -> float:
        return max(self.minimum, min(self.maximum, value))

    def initial_std(self, transformed_value: float) -> float:
        """Prior standard deviation for a freshly seen feature.

        ``relative_std`` is expressed in RAW units (e.g. "typing dwell varies by
        ~15%"), then mapped into the transformed space so a log-scaled feature
        does not inherit an absurdly wide prior.
        """
        raw = math.expm1(transformed_value) if self.log_scale else transformed_value
        raw = max(0.0, raw)
        deviation = raw * self.relative_std
        if self.log_scale:
            return max(MIN_LOG_STD, math.log1p(raw + deviation) - math.log1p(raw))
        return max(MIN_LINEAR_STD, deviation)


FEATURE_SPECS: Tuple[FeatureSpec, ...] = (
    # ---- typing rhythm (no characters, timings only) ----
    FeatureSpec("typing_speed", ("typing.speedCps", "typing.typingSpeed"), 0.0, 50.0, "keys/s"),
    FeatureSpec("typing_dwell", ("typing.meanDwellTime",), 0.0, 5000.0, "ms", log_scale=True),
    FeatureSpec("typing_dwell_std", ("typing.dwellStdDev",), 0.0, 5000.0, "ms", log_scale=True),
    FeatureSpec("typing_flight", ("typing.meanFlightTime",), 0.0, 5000.0, "ms", log_scale=True),
    FeatureSpec("typing_flight_std", ("typing.flightStdDev",), 0.0, 5000.0, "ms", log_scale=True),
    FeatureSpec("typing_pause_rate", ("typing.pauseRate",), 0.0, 1.0, "ratio"),
    # ---- pointer kinematics ----
    FeatureSpec("mouse_velocity", ("mouse.meanVelocity",), 0.0, 50_000.0, "px/s", log_scale=True),
    FeatureSpec(
        "mouse_velocity_std", ("mouse.velocityStdDev",), 0.0, 50_000.0, "px/s", log_scale=True
    ),
    FeatureSpec(
        "mouse_acceleration", ("mouse.meanAcceleration",), 0.0, 500_000.0, "px/s^2", log_scale=True
    ),
    FeatureSpec(
        "mouse_direction_change_rate",
        ("mouse.directionChangeRate",),
        0.0,
        100.0,
        "changes/s",
        log_scale=True,
    ),
    FeatureSpec("mouse_distance", ("mouse.totalDistance",), 0.0, 1_000_000.0, "px", log_scale=True),
    FeatureSpec("mouse_duration", ("mouse.movementDuration",), 0.0, 60_000.0, "ms", log_scale=True),
    FeatureSpec(
        "mouse_pause_duration", ("mouse.meanPauseTime",), 0.0, 60_000.0, "ms", log_scale=True
    ),
    # ---- click cadence ----
    FeatureSpec("click_interval", ("click.meanInterval",), 0.0, 60_000.0, "ms", log_scale=True),
    FeatureSpec(
        "click_interval_std", ("click.intervalStdDev",), 0.0, 60_000.0, "ms", log_scale=True
    ),
    FeatureSpec(
        "click_frequency", ("click.clickFrequency",), 0.0, 1000.0, "clicks/s", log_scale=True
    ),
    FeatureSpec("click_count", ("click.clickCount",), 0.0, 100_000.0, "count", is_count=True),
    # ---- scroll behaviour ----
    FeatureSpec(
        "scroll_velocity", ("scroll.meanVelocity",), 0.0, 100_000.0, "px/s", log_scale=True
    ),
    FeatureSpec(
        "scroll_distance", ("scroll.totalDistance",), 0.0, 10_000_000.0, "px", log_scale=True
    ),
    FeatureSpec(
        "scroll_pause_duration",
        ("scroll.meanPauseDuration",),
        0.0,
        60_000.0,
        "ms",
        log_scale=True,
    ),
    FeatureSpec(
        "scroll_event_rate", ("scroll.eventRate",), 0.0, 1000.0, "events/s", log_scale=True
    ),
)

_BY_NAME: Dict[str, FeatureSpec] = {spec.name: spec for spec in FEATURE_SPECS}
_BY_PATH: Dict[str, FeatureSpec] = {}
for _spec in FEATURE_SPECS:
    for _path in _spec.sdk_paths:
        _BY_PATH[_path] = _spec

# Floors for the standard-deviation prior. In log space 0.05 is ~5% variation,
# which is the smallest amount of human inconsistency worth assuming.
MIN_LOG_STD = 0.05
MIN_LINEAR_STD = 1e-3
DEFAULT_RELATIVE_STD = 0.15

# Names used for the baseline vector (excludes counters).
VECTOR_FEATURES: Tuple[str, ...] = tuple(s.name for s in FEATURE_SPECS if not s.is_count)


def feature_names() -> List[str]:
    """Canonical feature names accepted by the model."""
    return list(VECTOR_FEATURES)


def get_spec(name: str) -> Optional[FeatureSpec]:
    return _BY_NAME.get(name)


def assert_no_raw_data(payload: Any, _depth: int = 0) -> None:
    """Reject payloads that appear to carry raw text / typed characters."""
    if _depth > 6:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered = str(key).lower()
            for pattern in FORBIDDEN_KEY_PATTERNS:
                if pattern in lowered:
                    raise RawDataRejectedError(
                        f"Rejected telemetry key '{key}': raw data is never accepted by TRUSTPULSE"
                    )
            if isinstance(value, str) and len(value) > 0 and not _looks_like_token(value):
                # A string value in a derived-feature payload is almost always a leak.
                raise RawDataRejectedError(
                    f"Rejected telemetry value for '{key}': only numeric derived features allowed"
                )
            assert_no_raw_data(value, _depth + 1)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            assert_no_raw_data(item, _depth + 1)


_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+/=-]{1,64}$")


def _looks_like_token(value: str) -> bool:
    """Allow short identifier-like strings (device ids, sdk versions, enum labels)."""
    return bool(_TOKEN_RE.match(value)) and (" " not in value)


def _dig(payload: Dict[str, Any], dotted: str) -> Any:
    node: Any = payload
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _finite(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def extract_feature_vector(payload: Dict[str, Any], reject_raw: bool = True) -> Dict[str, float]:
    """Normalize SDK telemetry into the canonical feature vector.

    Unknown keys are ignored; non-finite values are dropped. Missing features are
    simply absent from the result — absence means "no evidence", never "malicious".
    """
    if not isinstance(payload, dict):
        raise RawDataRejectedError("Feature payload must be an object of derived numeric features")
    if reject_raw:
        assert_no_raw_data(payload)

    vector: Dict[str, float] = {}
    for dotted, spec in _BY_PATH.items():
        raw = _dig(payload, dotted)
        if raw is None:
            continue
        number = _finite(raw)
        if number is None:
            continue
        vector[spec.name] = spec.clamp(number)
    return vector


def to_array(vector: Dict[str, float], names: Sequence[str]) -> List[float]:
    """Dense representation; missing features become ``nan`` so callers can mask them."""
    out: List[float] = []
    for name in names:
        value = vector.get(name)
        out.append(float(value) if value is not None else float("nan"))
    return out


def initial_std(name: str, transformed_value: float) -> float:
    """Standard-deviation prior for feature ``name`` at a transformed value."""
    spec = _BY_NAME.get(name)
    if spec is None:
        return MIN_LOG_STD
    return spec.initial_std(transformed_value)


def transform(vector: Dict[str, float]) -> Dict[str, float]:
    """Applies the per-feature scale transform (log1p for heavy-tailed units)."""
    out: Dict[str, float] = {}
    for name, value in vector.items():
        spec = _BY_NAME.get(name)
        number = _finite(value)
        if spec is None or number is None:
            continue
        out[name] = math.log1p(max(0.0, number)) if spec.log_scale else number
    return out


def inverse_transform(vector: Dict[str, float]) -> Dict[str, float]:
    """Inverse of :func:`transform`, used for human-readable evidence."""
    out: Dict[str, float] = {}
    for name, value in vector.items():
        spec = _BY_NAME.get(name)
        number = _finite(value)
        if spec is None or number is None:
            continue
        out[name] = math.expm1(number) if spec.log_scale else number
    return out


def describe(features: Iterable[str]) -> List[Dict[str, Any]]:
    """Human-readable metadata for the configured feature schema (UI/docs)."""
    result: List[Dict[str, Any]] = []
    wanted = set(features)
    for spec in FEATURE_SPECS:
        if wanted and spec.name not in wanted:
            continue
        result.append(
            {
                "name": spec.name,
                "unit": spec.unit,
                "min": spec.minimum,
                "max": spec.maximum,
                "log_scale": spec.log_scale,
                "is_count": spec.is_count,
            }
        )
    return result
