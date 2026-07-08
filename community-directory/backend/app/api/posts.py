"""
Shared Inbox and Emergency alert routes.
Gated by require_active_member or require_admin.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request

from app.core.dependencies import get_db, require_active_member, require_admin
from app.core.logging import get_request_id
from app.core.rate_limit import post_limiter
from app.domain.post_service import PostService
from app.schemas.common import Meta
from app.schemas.posts import PostCreate, PostResponse, ResolveEmergencyRequest

router = APIRouter(tags=["posts"])


def _meta(page: Optional[int] = None, page_size: Optional[int] = None, total: Optional[int] = None) -> dict:
    return Meta(
        request_id=get_request_id(), page=page, page_size=page_size, total=total
    ).model_dump()


def _serialize_post(post: dict) -> dict:
    return {
        "id": str(post["_id"]),
        "type": post["type"],
        "author_member_id": post["author_member_id"],
        "message": post.get("message"),
        "media_ids": post.get("media_ids", []),
        "status": post["status"],
        "priority": post["priority"],
        "reported_count": post.get("reported_count", 0),
        "moderation": post.get("moderation"),
        "resolution": post.get("resolution"),
        "created_at": post["created_at"],
        "updated_at": post["updated_at"],
    }


@router.get("/api/posts")
async def list_posts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """List paginated inbox posts (excl. REMOVED posts by default)."""
    service = PostService(db)
    docs, total = await service.list_feed("INBOX", page=page, page_size=page_size, status=status)
    serialized = [_serialize_post(d) for d in docs]
    return {"data": serialized, "meta": _meta(page=page, page_size=page_size, total=total)}


@router.post("/api/posts", status_code=201)
async def create_post(
    payload: PostCreate,
    request: Request,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """Create a new inbox post. Author is derived from active session."""
    limiter = post_limiter()
    await limiter.check(request)

    author_id = context["member"]["member_id"]
    service = PostService(db)
    doc = await service.create_post(
        post_type="INBOX",
        author_member_id=author_id,
        message=payload.message,
        media_ids=payload.media_ids,
    )
    return {"data": _serialize_post(doc), "meta": _meta()}


@router.post("/api/posts/{post_id}/report")
async def report_post(
    post_id: str,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """Report a post for moderation. Increments report count."""
    service = PostService(db)
    success = await service.report_post(post_id)
    return {"data": {"success": success}, "meta": _meta()}


@router.get("/api/emergency-alerts")
async def list_emergency_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """List paginated emergency alerts (excl. REMOVED alerts by default)."""
    service = PostService(db)
    docs, total = await service.list_feed("EMERGENCY", page=page, page_size=page_size, status=status)
    serialized = [_serialize_post(d) for d in docs]
    return {"data": serialized, "meta": _meta(page=page, page_size=page_size, total=total)}


@router.post("/api/emergency-alerts", status_code=201)
async def create_emergency_alert(
    payload: PostCreate,
    request: Request,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """Create a new emergency alert. Author is derived from active session. Priority is URGENT."""
    limiter = post_limiter()
    await limiter.check(request)

    author_id = context["member"]["member_id"]
    service = PostService(db)
    doc = await service.create_post(
        post_type="EMERGENCY",
        author_member_id=author_id,
        message=payload.message,
        media_ids=payload.media_ids,
    )
    return {"data": _serialize_post(doc), "meta": _meta()}


@router.post("/api/emergency-alerts/{alert_id}/resolve")
async def resolve_emergency_alert(
    alert_id: str,
    payload: ResolveEmergencyRequest,
    context: dict = Depends(require_admin),
    db=Depends(get_db),
):
    """Mark an emergency alert as RESOLVED. Admin role required."""
    admin_member_id = context["member"]["member_id"]
    service = PostService(db)
    doc = await service.resolve_emergency(
        post_id=alert_id,
        resolved_by=admin_member_id,
        note=payload.note,
    )
    return {"data": _serialize_post(doc), "meta": _meta()}
