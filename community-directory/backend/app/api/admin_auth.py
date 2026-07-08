"""
Admin authentication routes — interim email + password login (Phases 2-4).

See app/domain/admin_auth_service.py for the security rationale: this path
is exclusively for administrators until WebAuthn is extended to admin
accounts in Phase 5. Regular members never use these routes.
"""
from fastapi import APIRouter, Cookie, Depends, Request, Response
from typing import Optional

from app.core.dependencies import get_db, require_admin_session
from app.core.errors import AuthenticationRequired
from app.core.logging import get_request_id
from app.core.rate_limit import admin_login_limiter
from app.core.security import make_session_cookie_params, clear_session_cookie_params
from app.domain.admin_auth_service import AdminAuthService
from app.schemas.admin import AdminLoginRequest, AdminMeResponse
from app.schemas.common import Meta

router = APIRouter(prefix="/api/admin/auth", tags=["admin-auth"])


@router.post("/login")
async def admin_login(
    payload: AdminLoginRequest,
    request: Request,
    response: Response,
    db=Depends(get_db),
):
    limiter = admin_login_limiter()
    await limiter.check(request)

    service = AdminAuthService(db)
    result = await service.login(payload.email, payload.password)

    if not result:
        # Generic message — do not reveal whether the email exists,
        # whether the password was wrong, or whether the account is suspended.
        raise AuthenticationRequired(
            detail="Invalid email or password, or this account is not an active administrator."
        )

    cookie_params = make_session_cookie_params(
        result.raw_session_token, expire_hours=24
    )
    response.set_cookie(**cookie_params)

    return {
        "data": {
            "member_id": result.member["member_id"],
            "role": result.member["role"],
            "status": result.member["status"],
        },
        "meta": Meta(request_id=get_request_id()).model_dump(),
    }


@router.post("/logout")
async def admin_logout(
    response: Response,
    context: dict = Depends(require_admin_session),
    cd_session: Optional[str] = Cookie(default=None, alias="__Host-cd_session"),
    db=Depends(get_db),
):
    service = AdminAuthService(db)
    if cd_session:
        await service.logout(cd_session, context["member"]["member_id"])

    response.set_cookie(**clear_session_cookie_params())
    return {"data": {"logged_out": True}, "meta": Meta(request_id=get_request_id()).model_dump()}


@router.get("/me", response_model=None)
async def admin_me(context: dict = Depends(require_admin_session)):
    member = context["member"]
    data = AdminMeResponse(
        member_id=member["member_id"],
        role=member["role"],
        status=member["status"],
        name=member.get("profile", {}).get("name"),
    )
    return {"data": data.model_dump(), "meta": Meta(request_id=get_request_id()).model_dump()}
