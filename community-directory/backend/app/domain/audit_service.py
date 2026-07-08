"""
Audit service — the single entry point domain services use to record
accountability events. Never accepts secret values in before/after payloads.
"""
from typing import Any, Dict, Optional

from app.repositories.audit_repo import AuditRepository

# Fields that must never appear in audit before/after snapshots
_FORBIDDEN_KEYS = {
    "password", "password_hash", "otp", "otp_hash", "session_token",
    "session_token_hash", "device_cookie_hash", "public_key", "private_key",
    "smtp_password", "secret", "credential_id",
}


def _redact(payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if payload is None:
        return None
    return {
        k: ("***REDACTED***" if k.lower() in _FORBIDDEN_KEYS else v)
        for k, v in payload.items()
    }


class AuditService:
    def __init__(self, db):
        self.repo = AuditRepository(db)

    async def log(
        self,
        actor: str,
        action: str,
        target: str,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> str:
        """
        Record an audit entry. Use for every high-impact admin action:
        approvals, suspensions, device decisions, moderation, exports, config changes.
        """
        return await self.repo.record(
            actor=actor,
            action=action,
            target=target,
            before=_redact(before),
            after=_redact(after),
            reason=reason,
        )
