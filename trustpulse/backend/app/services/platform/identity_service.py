"""TRUSTPULSE — Identity, device and session lifecycle service.

Responsibilities:
  * authenticate the simulated TrustDev user (digest comparison, never plaintext)
  * resolve or create the device record and its trust level
  * create/end a TRUSTPULSE session and run the first trust evaluation

This service does NOT replace an IdP, MFA or an IAM system. It records *how
strongly* a user authenticated so the trust engine can score identity assurance.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.credentials import (
    generate_token,
    hash_identifier,
    hash_token,
    verify_credential,
)
from app.core.exceptions import AuthenticationException, SessionNotFoundException
from app.core.logging import logger
from app.models.device import DeviceModel
from app.models.session import SessionModel
from app.models.user import UserModel
from app.repositories.platform import PlatformRepository
from app.schemas.platform import (
    DeviceContext,
    LoginRequest,
    LoginResponse,
    NetworkContext,
    SessionCreateRequest,
    SessionResponse,
)
from app.schemas.trust import TrustResult
from app.services.trust_engine.engine import TrustEngine

ACTIVE_STATES = ("ACTIVE", "PAUSED")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class IdentityService:
    def __init__(self, db: AsyncSession, tenant_id: str) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.repo = PlatformRepository(db, tenant_id)
        self.trust_engine = TrustEngine(db, tenant_id)

    # ------------------------------------------------------------------ devices
    async def resolve_device(self, context: DeviceContext, user_id: Optional[str]) -> DeviceModel:
        """Finds the device by fingerprint or registers it as new."""
        device = await self.repo.get_device_by_fingerprint(context.fingerprint)
        if device is None:
            device = DeviceModel(
                customer_tenant_id=self.tenant_id,
                device_fingerprint=context.fingerprint,
                user_id=user_id,
                label=context.label,
                platform=context.platform,
                browser=context.browser,
                os_name=context.os_name,
                screen=context.screen,
                timezone=context.timezone,
                trust_level="NEW",
                is_registered=False,
                observation_count=0,
                first_seen_at=_now(),
                last_seen_at=_now(),
            )
            await self.repo.add_device(device)
            logger.info("Registered new device %s for user %s", context.fingerprint[:12], user_id)
        else:
            device.last_seen_at = _now()
            device.observation_count = int(device.observation_count or 0) + 1
            if user_id and not device.user_id:
                device.user_id = user_id
            for field, value in (
                ("platform", context.platform),
                ("browser", context.browser),
                ("os_name", context.os_name),
                ("screen", context.screen),
                ("timezone", context.timezone),
            ):
                if value:
                    setattr(device, field, value)
            if not device.is_flagged:
                if device.is_registered:
                    device.trust_level = "TRUSTED"
                elif device.observation_count >= 5:
                    device.trust_level = "KNOWN"
        await self.db.flush()
        return device

    # ----------------------------------------------------------- network context
    async def baseline_network_for_user(
        self, user_id: Optional[str]
    ) -> tuple[Optional[str], Optional[str]]:
        """Most frequently seen (country, ASN) for this user — the context baseline."""
        return await self.repo.baseline_network_for_user(user_id)

    # ------------------------------------------------------------------- login
    async def login(self, request: LoginRequest) -> LoginResponse:
        user = await self.repo.get_user_by_username(request.username)
        if user is None or not user.is_active:
            # Deliberately identical error for unknown user and bad password.
            raise AuthenticationException("Invalid credentials")
        if not verify_credential(request.password, user.credential_hash, user.credential_salt):
            raise AuthenticationException("Invalid credentials")

        mfa_used = bool(request.mfa_code) and user.mfa_enabled
        if user.mfa_enabled and not mfa_used:
            raise AuthenticationException("MFA code required for this account")

        auth_method = user.default_auth_method or "PASSWORD"
        if mfa_used and auth_method == "PASSWORD":
            auth_method = "PASSWORD_MFA"

        device = await self.resolve_device(request.device, user.id)
        session = await self._create_session(
            user=user,
            device=device,
            network=request.network,
            auth_method=auth_method,
            mfa_used=mfa_used,
            application_id=request.application_id,
            session_id=None,
        )
        evaluation = await self.trust_engine.evaluate(session, trigger="LOGIN")
        await self.db.flush()

        token = generate_token()
        session.extra = {**(session.extra or {}), "token_hash": hash_token(token)}
        await self.db.flush()

        return LoginResponse(
            session=self._to_response(session, user, device, evaluation.result),
            token=token,
            trust=evaluation.result,
        )

    # ----------------------------------------------------------------- sessions
    async def create_session(self, request: SessionCreateRequest) -> SessionResponse:
        user = await self.repo.get_user_by_external_id(request.user_id)
        if user is None:
            user = await self.repo.get_user_by_username(request.user_id)
        if user is None or not user.is_active:
            raise SessionNotFoundException(request.user_id)

        device = await self.resolve_device(request.device, user.id)
        auth_method = request.auth_method
        if request.mfa_used and auth_method == "PASSWORD":
            auth_method = "PASSWORD_MFA"

        session = await self._create_session(
            user=user,
            device=device,
            network=request.network,
            auth_method=auth_method,
            mfa_used=request.mfa_used,
            application_id=request.application_id,
            session_id=request.session_id,
        )
        evaluation = await self.trust_engine.evaluate(session, trigger="LOGIN")
        await self.db.flush()
        return self._to_response(session, user, device, evaluation.result)

    async def end_session(self, session_id: str, reason: str = "USER_LOGOUT") -> SessionResponse:
        session = await self.repo.get_session_by_session_id(session_id)
        if session is None:
            raise SessionNotFoundException(session_id)
        session.status = "TERMINATED"
        session.revoked_at = _now()
        session.revocation_reason = reason
        await self.trust_engine.evaluate(session, trigger="SESSION_END")
        await self.db.flush()
        user = await self.repo.get_user(session.user_ref_id) if session.user_ref_id else None
        device = (
            await self.repo.get_device(session.device_ref_id) if session.device_ref_id else None
        )
        return self._to_response(session, user, device)

    async def _create_session(
        self,
        *,
        user: UserModel,
        device: DeviceModel,
        network: Optional[NetworkContext],
        auth_method: str,
        mfa_used: bool,
        application_id: str,
        session_id: Optional[str],
    ) -> SessionModel:
        network = network or NetworkContext()
        baseline_country, baseline_asn = await self.baseline_network_for_user(user.id)
        session = SessionModel(
            id=str(uuid.uuid4()),
            session_id=session_id or f"TS-{uuid.uuid4().hex[:12].upper()}",
            customer_tenant_id=self.tenant_id,
            subject_id=user.external_user_id,
            device_id=device.device_fingerprint,
            user_ref_id=user.id,
            device_ref_id=device.id,
            application_id=application_id,
            status="ACTIVE",
            auth_method=auth_method,
            mfa_used=mfa_used,
            ip_hash=hash_identifier(network.client_ip) if network.client_ip else None,
            network_country=network.country,
            network_asn=network.asn,
            is_vpn=network.is_vpn,
            is_proxy_or_tor=network.is_proxy_or_tor,
            # Baselines come from HISTORY only. Seeding them from the current
            # observation would let a session corroborate itself.
            baseline_network_country=baseline_country,
            baseline_network_asn=baseline_asn,
            trust_state="TRUSTED",
            trust_state_since=_now(),
            tci_confidence="LOW",
            created_at=_now(),
            last_seen_at=_now(),
        )
        await self.repo.add_session(session)
        return session

    # -------------------------------------------------------------- projections
    def _to_response(
        self,
        session: SessionModel,
        user: Optional[UserModel],
        device: Optional[DeviceModel],
        trust: Optional[TrustResult] = None,
    ) -> SessionResponse:
        return SessionResponse(
            session_id=session.session_id,
            status=session.status,
            user_id=user.external_user_id if user else session.subject_id,
            username=user.username if user else None,
            device_id=device.id if device else session.device_ref_id,
            device_fingerprint=device.device_fingerprint if device else session.device_id,
            application_id=session.application_id,
            auth_method=session.auth_method,
            mfa_used=session.mfa_used,
            tci=session.tci,
            confidence=session.tci_confidence,
            trend=session.tci_trend,
            trust_state=session.trust_state,
            evaluations=int(session.trust_evaluations or 0),
            is_contained=bool(session.is_contained),
            created_at=session.created_at,
            last_seen_at=session.last_seen_at,
            trust=trust,
        )

    async def list_active_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        sessions = await self.repo.list_sessions(limit=limit)
        payload: List[Dict[str, Any]] = []
        for session in sessions:
            user = await self.repo.get_user(session.user_ref_id) if session.user_ref_id else None
            payload.append(
                {
                    "session_id": session.session_id,
                    "user": user.username if user else session.subject_id,
                    "tci": session.tci,
                    "trust_state": session.trust_state,
                    "status": session.status,
                }
            )
        return payload


__all__ = ["IdentityService", "ACTIVE_STATES"]
