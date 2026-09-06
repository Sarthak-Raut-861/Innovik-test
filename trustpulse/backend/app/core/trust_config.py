"""TRUSTPULSE trust-model configuration.

Single source of truth is ``shared/constants/trust_model.json``. Everything in it
is a PROTOTYPE parameter and can be overridden at runtime, in this precedence:

1. ``TRUST_MODEL_CONFIG_PATH``  — point at a different JSON file entirely
2. ``TRUST_MODEL_OVERRIDES``    — JSON object deep-merged over the base config
3. Convenience environment variables for the values tuned most often:
   ``TCI_WEIGHT_*``, ``TRUST_STATE_*_MIN``, ``ACTION_RISK_<ACTION_NAME>``

Nothing security-relevant is hard-coded in engine code; engines read this module.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.logging import logger

_SHARED_CANDIDATES = (
    Path(__file__).resolve().parents[3] / "shared" / "constants" / "trust_model.json",
    Path(os.environ.get("SHARED_DIR", "/app/shared")) / "constants" / "trust_model.json",
)

_ENV_WEIGHT_MAP = {
    "TCI_WEIGHT_IDENTITY": ("tci", "weights", "identity"),
    "TCI_WEIGHT_DEVICE": ("tci", "weights", "device"),
    "TCI_WEIGHT_BEHAVIOR": ("tci", "weights", "behavior"),
    "TCI_WEIGHT_NETWORK": ("tci", "weights", "network"),
    "TCI_WEIGHT_SESSION": ("tci", "weights", "session"),
    "TCI_WEIGHT_HISTORY": ("tci", "weights", "history"),
    "TCI_COLD_START": ("tci", "cold_start_tci"),
}

_ENV_STATE_MAP = {
    "TRUST_STATE_TRUSTED_MIN": "TRUSTED",
    "TRUST_STATE_DEGRADED_MIN": "DEGRADED",
    "TRUST_STATE_SUSPICIOUS_MIN": "SUSPICIOUS",
    "TRUST_STATE_CRITICAL_MIN": "CRITICAL",
    "TRUST_STATE_BLOCKED_MIN": "BLOCKED",
}


class TrustConfigError(RuntimeError):
    """Raised when the trust model configuration is internally inconsistent."""


@dataclass
class TrustModelConfig:
    """Validated, immutable view of the trust model parameters."""

    raw: Dict[str, Any] = field(default_factory=dict)
    source: str = "builtin"

    # ------------------------------------------------------------------ accessors
    def section(self, name: str) -> Dict[str, Any]:
        value = self.raw.get(name)
        return dict(value) if isinstance(value, dict) else {}

    def get(self, *path: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in path:
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    # ------------------------------------------------------------------ TCI
    @property
    def schema_version(self) -> str:
        return str(self.raw.get("schema_version", "0.0.0"))

    @property
    def weights(self) -> Dict[str, float]:
        return {k: float(v) for k, v in (self.get("tci", "weights") or {}).items()}

    @property
    def tci_scale_max(self) -> float:
        return float(self.get("tci", "scale_max", default=100))

    @property
    def cold_start_tci(self) -> float:
        return float(self.get("tci", "cold_start_tci", default=62))

    @property
    def high_confidence_min_features(self) -> int:
        return int(self.get("tci", "confidence_levels", "high_min_features", default=8))

    @property
    def medium_confidence_min_features(self) -> int:
        return int(self.get("tci", "confidence_levels", "medium_min_features", default=4))

    # ------------------------------------------------------------------ states
    def state_bands(self) -> List[Dict[str, Any]]:
        bands = self.get("trust_states", "bands", default=[]) or []
        return [dict(band) for band in bands]

    def hysteresis(self) -> Dict[str, Any]:
        return dict(self.get("trust_states", "hysteresis") or {})

    def state_for_tci(self, tci: float) -> str:
        """Raw band lookup, before hysteresis is applied."""
        for band in self.state_bands():
            if tci >= float(band["min"]):
                return str(band["state"])
        bands = self.state_bands()
        return str(bands[-1]["state"]) if bands else "BLOCKED"

    # ------------------------------------------------------------------ actions
    def action_profiles(self) -> Dict[str, Dict[str, Any]]:
        profiles = self.get("action_risk_profiles") or {}
        return {str(k): dict(v) for k, v in profiles.items()}

    def action_risk(self, action: str) -> Optional[int]:
        profile = self.action_profiles().get((action or "").strip().upper())
        if not profile:
            return None
        return int(profile.get("risk", 50))

    def evidence_types(self) -> List[str]:
        return [str(item) for item in (self.raw.get("evidence_types") or [])]

    # ------------------------------------------------------------------ authorization
    @property
    def policy_version(self) -> str:
        return str(self.get("authorization", "policy_version", default="1.0.0"))

    def authorization(self) -> Dict[str, Any]:
        return dict(self.get("authorization") or {})

    def policy_rules(self) -> List[Dict[str, Any]]:
        """Ordered policy rules. First match wins — order is semantic."""
        return [dict(rule) for rule in (self.get("authorization", "rules") or [])]

    @property
    def terminal_trust_states(self) -> List[str]:
        return [str(s) for s in (self.get("authorization", "terminal_trust_states") or [])]

    @property
    def tci_block_floor(self) -> float:
        return float(self.get("authorization", "tci_block_floor", default=45))

    @property
    def tci_block_floor_min_risk(self) -> int:
        return int(self.get("authorization", "tci_block_floor_min_risk", default=30))

    def step_up(self) -> Dict[str, Any]:
        return dict(self.get("authorization", "step_up") or {})

    def receipts_config(self) -> Dict[str, Any]:
        return dict(self.get("authorization", "receipts") or {})

    def containment(self) -> Dict[str, Any]:
        return dict(self.get("authorization", "containment") or {})


# --------------------------------------------------------------------------- loader
def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _set_path(config: Dict[str, Any], path: tuple, value: Any) -> None:
    node = config
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value


def _coerce_number(text: str) -> Any:
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None


def _apply_env_overrides(config: Dict[str, Any]) -> None:
    for env_name, path in _ENV_WEIGHT_MAP.items():
        text = os.environ.get(env_name)
        if text is None:
            continue
        number = _coerce_number(text)
        if number is not None:
            _set_path(config, path, number)

    for env_name, state in _ENV_STATE_MAP.items():
        text = os.environ.get(env_name)
        if text is None:
            continue
        number = _coerce_number(text)
        if number is None:
            continue
        for band in config.get("trust_states", {}).get("bands", []):
            if band.get("state") == state:
                band["min"] = number

    for env_name, text in os.environ.items():
        if not env_name.startswith("ACTION_RISK_"):
            continue
        action = env_name[len("ACTION_RISK_") :]
        number = _coerce_number(text)
        if number is None:
            continue
        profiles = config.setdefault("action_risk_profiles", {})
        profile = profiles.setdefault(action, {})
        profile["risk"] = max(0, min(100, int(number)))


def _validate(config: Dict[str, Any]) -> None:
    weights = config.get("tci", {}).get("weights", {})
    required = {"identity", "device", "behavior", "network", "session", "history"}
    if set(weights) != required:
        raise TrustConfigError(
            f"TCI weights must define exactly {sorted(required)}, got {sorted(weights)}"
        )
    total = sum(float(v) for v in weights.values())
    if total <= 0:
        raise TrustConfigError("TCI weights must sum to a positive value")
    if abs(total - 1.0) > 1e-6:
        logger.warning(
            "TCI weights sum to %.4f; they are renormalized at fusion time. "
            "Weights are prototype parameters, not calibrated probabilities.",
            total,
        )

    bands = config.get("trust_states", {}).get("bands", [])
    if not bands:
        raise TrustConfigError("trust_states.bands must not be empty")
    minimums = [float(band["min"]) for band in bands]
    if minimums != sorted(minimums, reverse=True):
        raise TrustConfigError("trust_states.bands must be ordered from highest to lowest min")
    if minimums[-1] != 0:
        raise TrustConfigError("the lowest trust-state band must start at 0")

    for action, profile in (config.get("action_risk_profiles") or {}).items():
        risk = profile.get("risk")
        if not isinstance(risk, (int, float)) or not 0 <= float(risk) <= 100:
            raise TrustConfigError(f"action risk for {action} must be a number in 0..100")

    _validate_authorization(config)


_VALID_DECISIONS = {"ALLOW", "STEP_UP", "BLOCK", "REVOKE", "CONTAIN"}

# Trust states that no TCI value can produce — they are set by an operator or by
# the containment pipeline. Policy rules may reference them; TCI bands may not.
NON_BAND_TRUST_STATES = frozenset({"CONTAINED"})


def _validate_authorization(config: Dict[str, Any]) -> None:
    """Validates the authorization policy.

    A policy that silently fails open is the worst possible failure mode for a
    security product, so malformed rules are a load-time error rather than a
    runtime surprise.
    """
    auth = config.get("authorization")
    if auth is None:
        return
    if not isinstance(auth, dict):
        raise TrustConfigError("authorization must be an object")

    rules = auth.get("rules")
    if not isinstance(rules, list) or not rules:
        raise TrustConfigError("authorization.rules must be a non-empty list")

    seen: set = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise TrustConfigError(f"authorization.rules[{index}] must be an object")
        rule_id = rule.get("id")
        if not rule_id:
            raise TrustConfigError(f"authorization.rules[{index}] is missing an id")
        if rule_id in seen:
            raise TrustConfigError(f"duplicate policy rule id: {rule_id}")
        seen.add(rule_id)

        decision = rule.get("decision")
        if decision not in _VALID_DECISIONS:
            raise TrustConfigError(
                f"policy rule {rule_id} has decision {decision!r}; "
                f"must be one of {sorted(_VALID_DECISIONS)}"
            )
        if not isinstance(rule.get("requires", {}), dict):
            raise TrustConfigError(f"policy rule {rule_id}.requires must be an object")
        if not rule.get("reason"):
            raise TrustConfigError(f"policy rule {rule_id} must carry a human-readable reason")

    # The last rule must be the catch-all, otherwise unmatched requests fall
    # through to default_decision and the policy is not actually total.
    last = rules[-1]
    if last.get("requires") != {}:
        raise TrustConfigError(
            "the final policy rule must be a catch-all with requires == {}; otherwise the "
            "policy does not cover every request"
        )

    # The valid vocabulary is the TCI bands PLUS operator-driven states.
    # CONTAINED is not a band: no TCI value produces it, containment sets it.
    # It is still a legitimate policy input, so it must be allowed here.
    band_states = {str(band["state"]) for band in config.get("trust_states", {}).get("bands", [])}
    known_states = band_states | NON_BAND_TRUST_STATES
    unknown = band_states - known_states  # defensive: always empty
    if unknown:  # pragma: no cover
        raise TrustConfigError(f"internal error: {sorted(unknown)}")

    terminal = auth.get("terminal_trust_states") or []
    bad_terminal = [state for state in terminal if state not in known_states]
    if bad_terminal:
        raise TrustConfigError(
            f"authorization.terminal_trust_states has unknown states {bad_terminal}"
        )

    for rule in rules:
        for state in rule.get("requires", {}).get("trust_state_in", []) or []:
            if state not in known_states:
                raise TrustConfigError(
                    f"policy rule {rule['id']} references unknown trust state {state!r}"
                )

    receipts = auth.get("receipts") or {}
    ttl = receipts.get("ttl_seconds")
    max_ttl = receipts.get("max_ttl_seconds")
    if ttl is not None and max_ttl is not None and float(ttl) > float(max_ttl):
        raise TrustConfigError("authorization.receipts.ttl_seconds exceeds max_ttl_seconds")
    if ttl is not None and float(ttl) <= 0:
        raise TrustConfigError("authorization.receipts.ttl_seconds must be positive")


def load_trust_config() -> TrustModelConfig:
    """Loads, overrides and validates the trust model configuration."""
    override_path = os.environ.get("TRUST_MODEL_CONFIG_PATH")
    candidates = [Path(override_path)] if override_path else list(_SHARED_CANDIDATES)

    config: Optional[Dict[str, Any]] = None
    source = "builtin"
    for candidate in candidates:
        try:
            if candidate and candidate.is_file():
                config = json.loads(candidate.read_text(encoding="utf-8"))
                source = str(candidate)
                break
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Could not read trust model config %s: %s", candidate, exc)

    if config is None:
        raise TrustConfigError(
            "trust_model.json not found. Set TRUST_MODEL_CONFIG_PATH or SHARED_DIR."
        )

    overrides_text = os.environ.get("TRUST_MODEL_OVERRIDES")
    if overrides_text:
        try:
            overrides = json.loads(overrides_text)
            if isinstance(overrides, dict):
                config = _deep_merge(config, overrides)
                source += "+env-overrides"
            else:
                logger.error("TRUST_MODEL_OVERRIDES must be a JSON object; ignored")
        except json.JSONDecodeError as exc:
            logger.error("TRUST_MODEL_OVERRIDES is not valid JSON (%s); ignored", exc)

    _apply_env_overrides(config)
    _validate(config)
    return TrustModelConfig(raw=config, source=source)


_config: Optional[TrustModelConfig] = None


def get_trust_config(reload: bool = False) -> TrustModelConfig:
    """Process-wide cached configuration."""
    global _config
    if _config is None or reload:
        _config = load_trust_config()
    return _config


def reset_trust_config() -> None:
    """Test helper: forces the next read to reload from disk + environment."""
    global _config
    _config = None
