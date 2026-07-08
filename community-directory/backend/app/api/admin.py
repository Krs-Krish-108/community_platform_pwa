"""
Admin management routes — CSV import, member approval, edit, suspend,
deactivate, reactivate, plus security flag and audit log review.

All routes require require_admin_session (Phase 2-4 interim admin gate).
Every state-changing action is audited by the underlying domain services.
"""
from typing import Optional
from fastapi import APIRouter, Depends, File, Query, UploadFile
from bson import ObjectId

from app.core.dependencies import get_db, require_admin_session
from app.core.errors import ValidationError
from app.core.logging import get_request_id
from app.domain.import_service import ImportService
from app.domain.member_service import MemberService
from app.repositories.device_change_requests_repo import DeviceChangeRequestsRepository
from app.repositories.devices_repo import DevicesRepository
from app.repositories.sessions_repo import SessionsRepository
from app.repositories.security_repo import SecurityFlagsRepository
from app.repositories.audit_repo import AuditRepository
from app.repositories.members_repo import MembersRepository
from app.domain.audit_service import AuditService
from app.schemas.admin import (
    DeviceChangeDecisionRequest,
    EditMemberRequest,
    ImportSummaryResponse,
    ResolveFlagRequest,
    StatusActionRequest,
)
from app.schemas.common import Meta

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _meta() -> dict:
    return Meta(request_id=get_request_id()).model_dump()


# ── Import ────────────────────────────────────────────────────────────────────

@router.post("/imports/members")
async def import_members_csv(
    file: UploadFile = File(...),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    if not file.filename.lower().endswith(".csv"):
        raise ValidationError("Only .csv files are accepted.")

    raw_bytes = await file.read()
    try:
        csv_text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValidationError("File must be UTF-8 encoded CSV text.")

    service = ImportService(db)
    result = await service.import_csv(
        csv_text=csv_text,
        uploader_member_id=context["member"]["member_id"],
        source_name=file.filename,
    )

    summary = ImportSummaryResponse(
        import_run_id=result.import_run_id,
        total_rows=result.total_rows,
        valid_rows=result.valid_rows,
        invalid_rows=result.invalid_rows,
        errors=result.errors,
    )
    return {"data": summary.model_dump(), "meta": _meta()}


@router.get("/imports")
async def list_import_runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    from app.repositories.import_runs_repo import ImportRunsRepository
    repo = ImportRunsRepository(db)
    runs = await repo.list_recent(page, page_size)
    return {"data": [repo.serialize(r) for r in runs], "meta": _meta()}


# ── Staged / pending member review ───────────────────────────────────────────

@router.get("/members/staged")
async def list_staged_members(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    docs = await service.list_staged(page, page_size)
    return {"data": docs, "meta": _meta()}


@router.get("/members/pending-enrollment")
async def list_pending_enrollment(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    docs = await service.list_pending_enrollment(page, page_size)
    return {"data": docs, "meta": _meta()}


@router.post("/members/staged/{staged_id}/approve")
async def approve_staged_member(
    staged_id: str,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    result = await service.approve_staged_member(
        staged_object_id=staged_id,
        actor_member_id=context["member"]["member_id"],
    )
    return {"data": result, "meta": _meta()}


# ── Member editing and lifecycle ─────────────────────────────────────────────

@router.patch("/members/{member_id}")
async def edit_member(
    member_id: str,
    payload: EditMemberRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    updates = payload.model_dump(exclude_none=True)
    result = await service.edit_member(
        member_id=member_id,
        updates=updates,
        actor_member_id=context["member"]["member_id"],
    )
    return {"data": result, "meta": _meta()}


@router.post("/members/{member_id}/suspend")
async def suspend_member(
    member_id: str,
    payload: StatusActionRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    result = await service.suspend_member(
        member_id=member_id,
        actor_member_id=context["member"]["member_id"],
        reason=payload.reason,
    )
    return {"data": result, "meta": _meta()}


@router.post("/members/{member_id}/deactivate")
async def deactivate_member(
    member_id: str,
    payload: StatusActionRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    result = await service.deactivate_member(
        member_id=member_id,
        actor_member_id=context["member"]["member_id"],
        reason=payload.reason,
    )
    return {"data": result, "meta": _meta()}


@router.post("/members/{member_id}/reactivate")
async def reactivate_member(
    member_id: str,
    payload: StatusActionRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    result = await service.reactivate_member(
        member_id=member_id,
        actor_member_id=context["member"]["member_id"],
        reason=payload.reason,
    )
    return {"data": result, "meta": _meta()}


@router.get("/members/export")
async def export_active_members(
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    service = MemberService(db)
    docs = await service.export_active_members()

    await AuditService(db).log(
        actor=context["member"]["member_id"],
        action="MEMBERS_EXPORTED",
        target="directory",
        after={"count": len(docs)},
    )

    return {"data": docs, "meta": _meta()}


# ── Device-change request approvals ──────────────────────────────────────────

@router.get("/device-change-requests")
async def list_device_change_requests(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    repo = DeviceChangeRequestsRepository(db)
    docs = await repo.list_pending(page, page_size)
    return {"data": [repo.serialize(d) for d in docs], "meta": _meta()}


@router.post("/device-change-requests/{request_id}/approve")
async def approve_device_change_request(
    request_id: str,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    """
    Approves a pending device change. Revokes the member's old device(s)
    and sessions. The member must then complete passkey registration
    (Phase 5) to activate the new device.
    """
    repo = DeviceChangeRequestsRepository(db)
    devices_repo = DevicesRepository(db)
    sessions_repo = SessionsRepository(db)
    audit = AuditService(db)

    oid = ObjectId(request_id)
    req = await repo.collection.find_one({"_id": oid})
    if not req:
        from app.core.errors import NotFound
        raise NotFound("Device change request not found.")

    admin_id = context["member"]["member_id"]
    await repo.approve(oid, admin_id)

    revoked_devices = await devices_repo.revoke_all_for_member(req["member_id"])
    revoked_sessions = await sessions_repo.revoke_all_for_member(req["member_id"])

    await audit.log(
        actor=admin_id,
        action="DEVICE_CHANGE_APPROVED",
        target=req["member_id"],
        after={"revoked_devices": revoked_devices, "revoked_sessions": revoked_sessions},
    )

    return {
        "data": {
            "member_id": req["member_id"],
            "status": "APPROVED",
            "revoked_devices": revoked_devices,
            "revoked_sessions": revoked_sessions,
        },
        "meta": _meta(),
    }


@router.post("/device-change-requests/{request_id}/reject")
async def reject_device_change_request(
    request_id: str,
    payload: DeviceChangeDecisionRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    repo = DeviceChangeRequestsRepository(db)
    audit = AuditService(db)

    oid = ObjectId(request_id)
    req = await repo.collection.find_one({"_id": oid})
    if not req:
        from app.core.errors import NotFound
        raise NotFound("Device change request not found.")

    admin_id = context["member"]["member_id"]
    await repo.reject(oid, admin_id, payload.reason or "")

    await audit.log(
        actor=admin_id,
        action="DEVICE_CHANGE_REJECTED",
        target=req["member_id"],
        reason=payload.reason,
    )

    return {"data": {"member_id": req["member_id"], "status": "REJECTED"}, "meta": _meta()}


# ── Security flags ────────────────────────────────────────────────────────────

@router.get("/security-flags")
async def list_security_flags(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    repo = SecurityFlagsRepository(db)
    docs = await repo.list_open(page, page_size)
    return {"data": [repo.serialize(d) for d in docs], "meta": _meta()}


@router.post("/security-flags/{flag_id}/resolve")
async def resolve_security_flag(
    flag_id: str,
    payload: ResolveFlagRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    repo = SecurityFlagsRepository(db)
    audit = AuditService(db)

    oid = ObjectId(flag_id)
    await repo.resolve(oid, payload.admin_notes)

    await audit.log(
        actor=context["member"]["member_id"],
        action="SECURITY_FLAG_RESOLVED",
        target=flag_id,
        reason=payload.admin_notes,
    )

    return {"data": {"flag_id": flag_id, "status": "RESOLVED"}, "meta": _meta()}


# ── Audit log viewer ──────────────────────────────────────────────────────────

@router.get("/audit-logs")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    actor: Optional[str] = Query(default=None),
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    repo = AuditRepository(db)
    docs = await repo.list_recent(page, page_size, actor)
    return {"data": [repo.serialize(d) for d in docs], "meta": _meta()}


# ── Post Moderation & Emergency Resolution ────────────────────────────────────

@router.post("/posts/{post_id}/remove")
async def remove_post_admin(
    post_id: str,
    payload: StatusActionRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    """
    Soft-remove a post for moderation. Gated by require_admin_session.
    """
    from app.domain.post_service import PostService
    service = PostService(db)
    success = await service.remove_post(
        post_id=post_id,
        actioned_by=context["member"]["member_id"],
        reason=payload.reason or "",
    )
    return {"data": {"success": success}, "meta": _meta()}


@router.post("/emergency-alerts/{alert_id}/resolve")
async def resolve_emergency_alert_admin(
    alert_id: str,
    payload: StatusActionRequest,
    context: dict = Depends(require_admin_session),
    db=Depends(get_db),
):
    """
    Resolve an emergency alert. Gated by require_admin_session.
    """
    from app.domain.post_service import PostService
    service = PostService(db)
    doc = await service.resolve_emergency(
        post_id=alert_id,
        resolved_by=context["member"]["member_id"],
        note=payload.reason,
    )
    
    serialized = {
        "id": str(doc["_id"]),
        "type": doc["type"],
        "author_member_id": doc["author_member_id"],
        "message": doc.get("message"),
        "media_ids": doc.get("media_ids", []),
        "status": doc["status"],
        "priority": doc["priority"],
        "reported_count": doc.get("reported_count", 0),
        "moderation": doc.get("moderation"),
        "resolution": doc.get("resolution"),
        "created_at": doc["created_at"],
        "updated_at": doc["updated_at"],
    }
    return {"data": serialized, "meta": _meta()}

