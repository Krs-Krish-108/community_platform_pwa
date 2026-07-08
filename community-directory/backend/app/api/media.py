"""
Media upload and download routing.
Gated by require_active_member.
"""
from fastapi import APIRouter, Depends

from app.core.dependencies import get_db, require_active_member
from app.core.logging import get_request_id
from app.domain.media_service import MediaService
from app.schemas.common import Meta
from app.schemas.media import (
    UploadIntentRequest,
    UploadIntentResponse,
    UploadCompleteRequest,
    MediaAccessResponse,
)

router = APIRouter(prefix="/api/media", tags=["media"])


def _meta() -> dict:
    return Meta(request_id=get_request_id()).model_dump()


@router.post("/upload-intent", status_code=201)
async def create_upload_intent(
    payload: UploadIntentRequest,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    Initialize media upload. Checks file type and size.
    Returns storage details and a signed upload URL.
    """
    member_id = context["member"]["member_id"]
    service = MediaService(db)
    media_id, storage_key, upload_url = await service.create_upload_intent(
        owner_member_id=member_id,
        filename=payload.filename,
        content_type=payload.content_type,
        size_bytes=payload.size_bytes,
    )
    response = UploadIntentResponse(
        media_id=media_id,
        storage_key=storage_key,
        upload_url=upload_url,
    )
    return {"data": response.model_dump(), "meta": _meta()}


@router.post("/complete")
async def confirm_upload(
    payload: UploadCompleteRequest,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    Confirm media write completion. Ownership is validated.
    """
    member = context["member"]
    is_admin = member.get("role") == "admin"
    service = MediaService(db)
    success = await service.confirm_upload(
        media_id=payload.media_id,
        member_id=member["member_id"],
        is_admin=is_admin,
    )
    return {"data": {"success": success}, "meta": _meta()}


@router.get("/{media_id}/access-url")
async def get_access_url(
    media_id: str,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    Get a secure presigned URL to view/download media.
    Access is restricted based on the visibility of the linked post/profile.
    """
    member = context["member"]
    service = MediaService(db)
    access_url = await service.get_access_url(
        media_id=media_id,
        viewer_member_id=member["member_id"],
        viewer_role=member.get("role", "member"),
    )
    response = MediaAccessResponse(access_url=access_url)
    return {"data": response.model_dump(), "meta": _meta()}
