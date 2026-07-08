"""
Identity and OTP routes — the front door for member enrolment and device
change requests. See app/domain/auth_service.py for the full flow rationale.

Every response here is deliberately generic where the SRS requires it
(FR-AUTH-003): the /identify endpoint always returns the same message
regardless of whether the submitted Member ID/email match a real record.
"""
from fastapi import APIRouter, Cookie, Depends, Request, Response
from typing import Optional

from app.core.dependencies import get_db, require_active_session
from app.core.errors import OTPError, OTPExpired, OTPMaxAttempts
from app.core.logging import get_request_id
from app.core.rate_limit import identify_limiter, otp_verify_limiter
from app.core.security import clear_session_cookie_params
from app.domain.auth_service import AuthService
from app.schemas.auth import (
    GenericMessageResponse,
    IdentifyRequest,
    OTPVerifyRequest,
    OTPVerifyResponse,
)
from app.schemas.common import Meta

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _meta() -> dict:
    return Meta(request_id=get_request_id()).model_dump()


@router.post("/identify")
async def identify(
    payload: IdentifyRequest,
    request: Request,
    db=Depends(get_db),
):
    """
    FR-AUTH-002/003: accepts Member ID + registered email. Always returns
    the same generic message — callers cannot distinguish "record exists,
    OTP sent" from "no such record" from this response alone.
    """
    limiter = identify_limiter()
    await limiter.check(request)

    service = AuthService(db)
    await service.identify(payload.member_id, payload.email)

    response = GenericMessageResponse(
        message="If the submitted details match an approved record, "
        "a verification code has been sent to the registered email."
    )
    return {"data": response.model_dump(), "meta": _meta()}


@router.post("/otp/verify")
async def verify_otp(
    payload: OTPVerifyRequest,
    request: Request,
    db=Depends(get_db),
):
    """
    FR-AUTH-005/007: verifies the OTP against the active challenge.
    On success, returns either an enrollment ticket (first-time enrolment,
    consumed by Phase 5's passkey registration) or a pending-approval
    status (existing member on a new device, awaiting admin review).

    OTP verification alone NEVER creates a session or grants directory
    access — see AuthService for the non-negotiable rule this enforces.
    """
    limiter = otp_verify_limiter()
    await limiter.check(request)

    service = AuthService(db)
    result = await service.verify_otp(payload.member_id, payload.otp)

    response = OTPVerifyResponse(**result)
    return {"data": response.model_dump(exclude_none=True), "meta": _meta()}


@router.get("/me")
async def get_current_identity(
    session: dict = Depends(require_active_session),
    db=Depends(get_db),
):
    """
    Lightweight identity check — session validity only, no device gate.
    Useful for the frontend to distinguish "not signed in" from "signed in
    but device not yet approved" (e.g. mid-enrolment, or awaiting admin
    approval of a device change).
    """
    from app.repositories.members_repo import MembersRepository
    from app.repositories.devices_repo import DevicesRepository

    members_repo = MembersRepository(db)
    member = await members_repo.find_by_member_id(session["member_id"])
    if not member:
        from app.core.errors import SessionExpired
        raise SessionExpired()

    device_approved = False
    if session.get("device_id"):
        devices_repo = DevicesRepository(db)
        device_oid = devices_repo.to_object_id(session["device_id"])
        device = await devices_repo.collection.find_one({"_id": device_oid}) if device_oid else None
        device_approved = bool(device and device.get("status") == "ACTIVE")

    return {
        "data": {
            "member_id": member["member_id"],
            "status": member.get("status"),
            "role": member.get("role", "member"),
            "device_approved": device_approved,
        },
        "meta": _meta(),
    }


@router.post("/logout")
async def logout(
    response: Response,
    session: dict = Depends(require_active_session),
    cd_session: Optional[str] = Cookie(default=None, alias="__Host-cd_session"),
    db=Depends(get_db),
):
    """
    Ends the current session only. The trusted-device cookie is left
    intact — logging out does not revoke device trust, so the member can
    log back in with just their passkey (no OTP/admin approval needed).
    """
    from app.core.security import hash_session_token
    from app.repositories.sessions_repo import SessionsRepository

    if cd_session:
        sessions_repo = SessionsRepository(db)
        await sessions_repo.revoke_session(hash_session_token(cd_session))

    response.set_cookie(**clear_session_cookie_params())
    return {"data": {"logged_out": True}, "meta": _meta()}
