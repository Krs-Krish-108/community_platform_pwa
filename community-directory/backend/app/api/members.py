"""
Directory and profile routes.

FR-DIR-001: every route here requires a valid session AND an active trusted
device (require_active_member) — never session alone. This is the full
access gate from the Backend Blueprint's decision model:

    Valid session -> Active member -> Active device -> Required role -> Privacy projection

Unauthenticated requests, sessions without an approved device, suspended
members, and revoked devices are all denied before any data is touched.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query

from app.core.dependencies import get_db, require_active_member
from app.core.logging import get_request_id
from app.domain.directory_service import DirectoryService
from app.schemas.common import Meta

router = APIRouter(prefix="/api/members", tags=["directory"])


def _meta(page: Optional[int] = None, page_size: Optional[int] = None, total: Optional[int] = None) -> dict:
    return Meta(
        request_id=get_request_id(), page=page, page_size=page_size, total=total
    ).model_dump()


@router.get("/filters")
async def get_directory_filters(
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """Distinct values for each filter category, used to populate filter chips."""
    service = DirectoryService(db)
    options = await service.get_filter_options()
    return {"data": options, "meta": _meta()}


@router.get("")
async def search_directory(
    q: Optional[str] = Query(default=None, max_length=200),
    state: Optional[str] = Query(default=None, max_length=100),
    blood_group: Optional[str] = Query(default=None, max_length=20),
    occupation: Optional[str] = Query(default=None, max_length=100),
    education_sector: Optional[str] = Query(default=None, max_length=100),
    sub_caste: Optional[str] = Query(default=None, max_length=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    FR-DIR-002/003/004: paginated, searchable, filterable directory.
    Only card-level fields are ever returned here — full profiles require
    a separate authenticated request to /api/members/{member_id}.
    """
    service = DirectoryService(db)
    cards, total = await service.search_directory(
        q=q,
        state=state,
        blood_group=blood_group,
        occupation=occupation,
        education_sector=education_sector,
        sub_caste=sub_caste,
        page=page,
        page_size=page_size,
    )
    return {"data": cards, "meta": _meta(page=page, page_size=page_size, total=total)}


@router.get("/{member_id}")
async def get_member_profile(
    member_id: str,
    context: dict = Depends(require_active_member),
    db=Depends(get_db),
):
    """
    FR-DIR-005: privacy-projected profile based on viewer role and target
    member's visibility settings. A member can always see their own full
    self-view regardless of their own visibility settings (those settings
    control what OTHERS see, not what the member sees of themselves).
    """
    viewer = context["member"]
    service = DirectoryService(db)
    profile = await service.get_profile(
        member_id=member_id,
        viewer_member_id=viewer["member_id"],
        viewer_role=viewer.get("role", "member"),
    )
    return {"data": profile, "meta": _meta()}
