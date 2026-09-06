from app.models.action_request import ActionRequestModel
from app.models.audit_log import AuditLogModel
from app.models.base import Base, async_session_factory, engine, get_db_session
from app.models.baselines import ShadowBaselineModel, TrustedBaselineModel
from app.models.behavioral_profile import BehavioralProfileModel
from app.models.device import DeviceModel
from app.models.incident import IncidentModel
from app.models.integration_client import IntegrationClientModel
from app.models.observations import (
    ActionModel,
    ActionRiskProfileModel,
    BehaviorFeatureModel,
    SecurityEventModel,
    TrustStateModel,
)
from app.models.platform_incident import PlatformIncidentModel
from app.models.receipts import ProofRecordModel, TrustReceiptModel
from app.models.risk_assessment import RiskAssessmentModel
from app.models.security_decision import SecurityDecisionModel
from app.models.session import SessionModel
from app.models.telemetry import TelemetryEventModel
from app.models.user import UserModel

__all__ = [
    "Base",
    "engine",
    "async_session_factory",
    "get_db_session",
    # --- TRUSTPULSE platform entities ---
    "UserModel",
    "DeviceModel",
    "SessionModel",
    "BehaviorFeatureModel",
    "TrustedBaselineModel",
    "ShadowBaselineModel",
    "TrustStateModel",
    "SecurityEventModel",
    "ActionModel",
    "ActionRiskProfileModel",
    "TrustReceiptModel",
    "ProofRecordModel",
    "PlatformIncidentModel",
    # --- SDK-facing entities (Phase 1 SDK contract) ---
    "TelemetryEventModel",
    "BehavioralProfileModel",
    "RiskAssessmentModel",
    "ActionRequestModel",
    "SecurityDecisionModel",
    "IncidentModel",
    "AuditLogModel",
    "IntegrationClientModel",
]
