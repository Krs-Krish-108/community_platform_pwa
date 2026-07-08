"""
WebAuthn registration and login routes.

Registration consumes an enrollment ticket issued by Phase 4's OTP
verification (either first-time enrolment or post-approval device change).
Login uses the trusted-device cookie to identify which credential should
be challenged — no Member ID re-entry needed for routine daily access.
"""
import json
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Request, Response
from webauthn.helpers import options_to_json

from app.core.config import get_settings
from app.core.dependencies import get_db
from app.core.errors import DeviceNotApproved
from app.core.logging import get_request_id
from app.core.security import make_device_cookie_params, make_session_cookie_params
from app.domain.webauthn_service import WebAuthnService
from app.schemas.common import Meta
from app.schemas.webauthn import (
    LoginVerifyRequest,
    RegisterOptionsRequest,
    RegisterVerifyRequest,
    WebAuthnResultResponse,
)

router = APIRouter(prefix="/api/webauthn", tags=["webauthn"])


def _meta() -> dict:
    return Meta(request_id=get_request_id()).model_dump()


# ── Registration ──────────────────────────────────────────────────────────

@router.post("/register/options")
async def register_options(payload: RegisterOptionsRequest, db=Depends(get_db)):
    service = WebAuthnService(db)
    options = await service.begin_registration(payload.enrollment_ticket)
    return {"data": json.loads(options_to_json(options)), "meta": _meta()}


@router.post("/register/verify")
async def register_verify(
    payload: RegisterVerifyRequest,
    response: Response,
    db=Depends(get_db),
):
    settings = get_settings()
    service = WebAuthnService(db)
    result = await service.finish_registration(payload.enrollment_ticket, payload.credential)

    response.set_cookie(
        **make_session_cookie_params(
            result["raw_session_token"], expire_hours=settings.session_expire_hours
        )
    )
    response.set_cookie(
        **make_device_cookie_params(
            result["raw_device_token"], expire_days=settings.device_cookie_expire_days
        )
    )

    body = WebAuthnResultResponse(member_id=result["member_id"], status="ACTIVE")
    return {"data": body.model_dump(), "meta": _meta()}


# ── Login ─────────────────────────────────────────────────────────────────

@router.post("/login/options")
async def login_options(
    db=Depends(get_db),
    cd_device: Optional[str] = Cookie(default=None, alias="__Host-cd_device"),
):
    if not cd_device:
        raise DeviceNotApproved()

    service = WebAuthnService(db)
    options = await service.begin_login(cd_device)
    return {"data": json.loads(options_to_json(options)), "meta": _meta()}


@router.post("/login/verify")
async def login_verify(
    payload: LoginVerifyRequest,
    response: Response,
    db=Depends(get_db),
    cd_device: Optional[str] = Cookie(default=None, alias="__Host-cd_device"),
):
    if not cd_device:
        raise DeviceNotApproved()

    settings = get_settings()
    service = WebAuthnService(db)
    result = await service.finish_login(cd_device, payload.credential)

    response.set_cookie(
        **make_session_cookie_params(
            result["raw_session_token"], expire_hours=settings.session_expire_hours
        )
    )

    body = WebAuthnResultResponse(member_id=result["member_id"], status="ACTIVE")
    return {"data": body.model_dump(), "meta": _meta()}
