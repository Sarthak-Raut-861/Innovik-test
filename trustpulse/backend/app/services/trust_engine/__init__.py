"""TRUSTPULSE trust engine package.

Produces trust assessments and evidence. It has NO enforcement authority: every
authorization decision is made by the policy engine and enforced by the PEP.
"""

from app.services.trust_engine.engine import TrustEngine, TrustEvaluation, reset_forest_cache
from app.services.trust_engine.factors import (
    evidence_from_factors,
    score_behavior,
    score_device,
    score_history,
    score_identity,
    score_network,
    score_session,
)
from app.services.trust_engine.state_machine import StateTransition, TrustStateMachine

__all__ = [
    "StateTransition",
    "TrustEngine",
    "TrustEvaluation",
    "TrustStateMachine",
    "evidence_from_factors",
    "reset_forest_cache",
    "score_behavior",
    "score_device",
    "score_history",
    "score_identity",
    "score_network",
    "score_session",
]
