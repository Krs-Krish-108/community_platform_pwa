"""
Admin authentication service — interim email + password login.

This is the bridge mechanism for Phases 2-4: administrators need to sign in
to perform imports, approvals, and moderation before the WebAuthn/passkey
flow is extended to admin accounts in Phase 5. Regular members NEVER use
this path — they always go through OTP + passkey (see auth_service.py,
Phase 4, and webauthn_service.py, Phase 5).

Security properties preserved:
- Passwords are bcrypt-hashed, never stored or logged in plaintext.
- Sessions are opaque, HMAC-hashed, HttpOnly, Secure, SameSite=Strict.
- Failed logins are rate-limited and recorded as security events.
- Generic error messages prevent account enumeration.
"""
from typing import Any, Dict, Optional

from app.core.errors import AuthenticationRequired
from app.core.logging import get_logger
from app.core.security import (
    generate_opaque_token,
    hash_session_token,
    verify_password,
)
from app.domain.audit_service import AuditService
from app.repositories.members_repo import MembersRepository
from app.domain.security_service import SecurityService
from app.repositories.sessions_repo import SessionsRepository

logger = get_logger(__name__)


class AdminLoginResult:
    def __init__(self, member: Dict[str, Any], raw_session_token: str):
        self.member = member
        self.raw_session_token = raw_session_token


class AdminAuthService:
    def __init__(self, db):
        self.db = db
        self.members_repo = MembersRepository(db)
        self.sessions_repo = SessionsRepository(db)
        self.security_service = SecurityService(db)
        self.audit = AuditService(db)

    async def login(self, email: str, password: str) -> Optional[AdminLoginResult]:
        """
        Attempt admin login. Returns None on any failure — callers must
        respond with a generic error regardless of which check failed.
        """
        email_normalized = email.strip().lower()
        member = await self.members_repo.find_by_email(email_normalized)

        if not member:
            await self.security_service.record_event(
                event_type="IDENTITY_MISMATCH",
                metadata={"context": "admin_login", "reason": "no_such_email"},
            )
            return None

        if member.get("role") != "admin":
            await self.security_service.record_event(
                event_type="UNAUTHORIZED_POST_ATTEMPT",  # reuse: unauthorized privileged action attempt
                member_ref=member.get("member_id"),
                metadata={"context": "admin_login", "reason": "not_admin_role"},
            )
            return None

        password_hash = member.get("password_hash")
        if not password_hash or not verify_password(password, password_hash):
            await self.security_service.record_event(
                event_type="OTP_FAILED",  # reuse taxonomy: credential verification failure
                member_ref=member.get("member_id"),
                metadata={"context": "admin_login", "reason": "bad_password"},
            )
            return None

        status = member.get("status")
        if status in ("SUSPENDED", "DEACTIVATED"):
            await self.security_service.record_event(
                event_type="UNAUTHORIZED_POST_ATTEMPT",
                member_ref=member.get("member_id"),
                metadata={"context": "admin_login", "reason": f"status_{status}"},
            )
            return None

        # On first successful login, PENDING_ENROLLMENT admins become ACTIVE.
        # (Full passkey enrolment for admins arrives in Phase 5; for now,
        # a verified password login is sufficient to activate the bootstrap admin.)
        if status == "PENDING_ENROLLMENT":
            await self.members_repo.activate_member(member["member_id"])
            member["status"] = "ACTIVE"

        raw_token = generate_opaque_token()
        token_hash = hash_session_token(raw_token)
        await self.sessions_repo.create_session(
            member_id=member["member_id"],
            session_token_hash=token_hash,
            device_id=None,
        )

        await self.audit.log(
            actor=member["member_id"],
            action="ADMIN_LOGIN",
            target=member["member_id"],
        )

        logger.info("Admin login successful for member_id=%s", member["member_id"])
        return AdminLoginResult(member=member, raw_session_token=raw_token)

    async def logout(self, session_token: str, actor_member_id: str) -> None:
        token_hash = hash_session_token(session_token)
        await self.sessions_repo.revoke_session(token_hash)
        await self.audit.log(
            actor=actor_member_id,
            action="ADMIN_LOGOUT",
            target=actor_member_id,
        )
