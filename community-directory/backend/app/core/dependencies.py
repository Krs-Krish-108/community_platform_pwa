"""
FastAPI dependency functions.

These are injected into route handlers via Depends().
They enforce the access decision model:
  Valid session → Active member → Active device → Required role → Privacy projection

Every protected route must use at least `require_active_session`.
"""
from typing import Optional
from fastapi import Cookie, Depends, Request

from app.core.config import get_settings
from app.core.errors import (
    AuthenticationRequired,
    AccountSuspended,
    AccountNotActive,
    DeviceNotApproved,
    DeviceRevoked,
    PermissionDenied,
    SessionExpired,
)
from app.core.logging import get_logger
from app.core.security import hash_session_token, hash_device_token

logger = get_logger(__name__)
settings = get_settings()


# ── Database dependency ───────────────────────────────────────────────────────

async def get_db(request: Request):
    """Return the MongoDB database instance from app state."""
    return request.app.state.db


# ── Session extraction ────────────────────────────────────────────────────────

async def get_session_token(
    cd_session: Optional[str] = Cookie(default=None, alias="__Host-cd_session"),
) -> Optional[str]:
    """Extract raw session token from HttpOnly cookie (never from headers or query)."""
    return cd_session


async def get_device_token(
    cd_device: Optional[str] = Cookie(default=None, alias="__Host-cd_device"),
) -> Optional[str]:
    """Extract raw device token from HttpOnly cookie."""
    return cd_device


# ── Session validation ────────────────────────────────────────────────────────

async def require_active_session(
    session_token: Optional[str] = Depends(get_session_token),
    db=Depends(get_db),
) -> dict:
    """
    Validate the session cookie. Returns the session document.
    Raises AuthenticationRequired or SessionExpired on failure.
    Does NOT check member status or device — call require_active_member for that.
    """
    if not session_token:
        raise AuthenticationRequired()

    from app.repositories.sessions_repo import SessionsRepository
    sessions_repo = SessionsRepository(db)

    token_hash = hash_session_token(session_token)
    session = await sessions_repo.find_active_session(token_hash)

    if not session:
        raise SessionExpired()

    return session


async def require_active_member(
    session: dict = Depends(require_active_session),
    device_token: Optional[str] = Depends(get_device_token),
    db=Depends(get_db),
) -> dict:
    """
    Full access gate: validates session + member status + device status.
    Returns a dict with keys: session, member, device.

    This is the dependency to use on ALL directory, post, and media routes.
    """
    from app.repositories.members_repo import MembersRepository
    from app.repositories.devices_repo import DevicesRepository

    members_repo = MembersRepository(db)
    devices_repo = DevicesRepository(db)

    # 1. Load member
    member = await members_repo.find_by_member_id(session["member_id"])
    if not member:
        logger.warning("Session references non-existent member %s", session["member_id"])
        raise SessionExpired()

    # 2. Check member status
    status = member.get("status", "")
    if status == "SUSPENDED":
        raise AccountSuspended()
    if status == "DEACTIVATED":
        raise AccountNotActive()
    if status not in ("ACTIVE",):
        raise AccountNotActive()

    # 3. Check device
    if not device_token:
        raise DeviceNotApproved()

    device_token_hash = hash_device_token(device_token)
    device = await devices_repo.find_active_device_by_hash(device_token_hash)

    if not device:
        raise DeviceNotApproved()

    if device["status"] == "REVOKED":
        raise DeviceRevoked()

    if device["status"] != "ACTIVE":
        raise DeviceNotApproved()

    # 4. Ensure device belongs to this member
    if device.get("member_id") != member.get("member_id"):
        logger.warning(
            "Device/member mismatch: device member=%s, session member=%s",
            device.get("member_id"), member.get("member_id")
        )
        raise DeviceRevoked()

    return {"session": session, "member": member, "device": device}


async def require_admin(
    context: dict = Depends(require_active_member),
) -> dict:
    """
    Require the authenticated member to have the Admin role.
    Raises PermissionDenied for non-admins.

    Uses the FULL access gate (session + member + device). This is the
    long-term dependency for admin routes once WebAuthn (Phase 5) is wired
    for administrators too.
    """
    member = context["member"]
    if member.get("role") != "admin":
        raise PermissionDenied()
    return context


async def require_admin_session(
    session: dict = Depends(require_active_session),
    db=Depends(get_db),
) -> dict:
    """
    Interim admin authorization gate for Phases 2-4.

    Validates session + admin role + account status, WITHOUT requiring a
    trusted device. Administrators authenticate with email + password
    (see domain/admin_auth_service.py) until WebAuthn/passkey enrolment is
    extended to admins in Phase 5.

    Do not use this dependency for member-facing routes (directory, posts) —
    those must use require_active_member, which enforces the full device gate.
    """
    from app.repositories.members_repo import MembersRepository

    members_repo = MembersRepository(db)
    member = await members_repo.find_by_member_id(session["member_id"])

    if not member:
        logger.warning("Admin session references non-existent member %s", session["member_id"])
        raise SessionExpired()

    if member.get("role") != "admin":
        raise PermissionDenied()

    status = member.get("status", "")
    if status == "SUSPENDED":
        raise AccountSuspended()
    if status == "DEACTIVATED":
        raise AccountNotActive()

    return {"session": session, "member": member}


# ── Convenience extractors ────────────────────────────────────────────────────

def current_member_id(context: dict = Depends(require_active_member)) -> str:
    """Extract just the member_id string from the auth context."""
    return context["member"]["member_id"]


def current_member(context: dict = Depends(require_active_member)) -> dict:
    """Extract just the member document from the auth context."""
    return context["member"]
