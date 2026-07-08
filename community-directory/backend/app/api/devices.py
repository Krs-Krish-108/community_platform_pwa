"""
Device management routes — for an ALREADY authenticated member (valid
session + active device) managing their own device trust.

This is distinct from the OTP-based device-change flow (Phase 4) used when
a member has LOST their trusted device (new browser, cleared cookies) and
has no valid session to authenticate these routes with. Here, the member
is proactively managing a device they can still currently use.
"""
from fastapi import APIRouter, Depends, Response

from app.core.dependencies import get_db, require_active_member
from app.core.logging import get_request_id
from app.core.security import clear_device_cookie_params, clear_session_cookie_params
from app.domain.audit_service import AuditService
from app.repositories.device_change_requests_repo import DeviceChangeRequestsRepository
from app.repositories.devices_repo import DevicesRepository
from app.repositories.sessions_repo import SessionsRepository
from app.schemas.common import Meta

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _meta() -> dict:
    return Meta(request_id=get_request_id()).model_dump()


@router.get("/current")
async def get_current_device(context: dict = Depends(require_active_member)):
    device = context["device"]
    return {
        "data": {
            "device_id": str(device["_id"]),
            "status": device.get("status"),
            "created_at": device.get("created_at"),
            "approved_at": device.get("approved_at"),
        },
        "meta": _meta(),
    }


@router.post("/change-request")
async def request_device_change(
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    A member who still has their current trusted device but wants to
    register a new one (e.g. upgrading phones) can request this while
    still authenticated — no OTP re-verification needed since they're
    already proven to be holding an active session and device.
    """
    member_id = context["member"]["member_id"]
    repo = DeviceChangeRequestsRepository(db)

    existing = await repo.find_pending_for_member(member_id)
    if not existing:
        await repo.create_request(member_id)

    return {"data": {"status": "PENDING_ADMIN_APPROVAL"}, "meta": _meta()}


@router.delete("/current")
async def remove_current_device(
    response: Response,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    Self-service device removal (e.g. member lost or sold their phone).
    Revokes the device and every session tied to it, and clears both
    cookies on this response.
    """
    device = context["device"]
    member_id = context["member"]["member_id"]

    devices_repo = DevicesRepository(db)
    sessions_repo = SessionsRepository(db)
    audit = AuditService(db)

    await devices_repo.revoke_device(device["_id"])
    await sessions_repo.revoke_all_for_device(str(device["_id"]))

    await audit.log(
        actor=member_id,
        action="DEVICE_SELF_REMOVED",
        target=member_id,
        after={"device_id": str(device["_id"])},
    )

    response.set_cookie(**clear_session_cookie_params())
    response.set_cookie(**clear_device_cookie_params())

    return {"data": {"status": "REVOKED"}, "meta": _meta()}
