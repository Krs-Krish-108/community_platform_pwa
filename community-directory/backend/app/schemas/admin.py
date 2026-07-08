"""
Pydantic schemas for admin authentication, import, and member management routes.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, EmailStr, Field


# ── Admin auth ────────────────────────────────────────────────────────────────

class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class AdminMeResponse(BaseModel):
    member_id: str
    role: str
    status: str
    name: Optional[str] = None


# ── Import ────────────────────────────────────────────────────────────────────

class ImportRowError(BaseModel):
    row_number: int
    reason: str


class ImportSummaryResponse(BaseModel):
    import_run_id: str
    total_rows: int
    valid_rows: int
    invalid_rows: int
    errors: List[ImportRowError]


# ── Member management ─────────────────────────────────────────────────────────

class StagedMemberOut(BaseModel):
    id: str = Field(alias="_id")
    registered_email: str
    profile: Dict[str, Any]
    status: str
    created_at: Any

    model_config = {"populate_by_name": True}


class ApproveMemberResponse(BaseModel):
    member_id: str
    status: str
    registered_email: str


class EditMemberRequest(BaseModel):
    profile: Optional[Dict[str, Any]] = None
    visibility_settings: Optional[Dict[str, Any]] = None


class StatusActionRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


class MemberStatusResponse(BaseModel):
    member_id: str
    status: str


# ── Device change requests (admin approval side) ─────────────────────────────

class DeviceChangeRequestOut(BaseModel):
    id: str = Field(alias="_id")
    member_id: str
    status: str
    requested_at: Any

    model_config = {"populate_by_name": True}


class DeviceChangeDecisionRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


# ── Security flags / audit ────────────────────────────────────────────────────

class SecurityFlagOut(BaseModel):
    id: str = Field(alias="_id")
    rule_code: str
    severity: str
    target_ref: str
    status: str
    created_at: Any

    model_config = {"populate_by_name": True}


class ResolveFlagRequest(BaseModel):
    admin_notes: Optional[str] = Field(default=None, max_length=1000)


class AuditLogOut(BaseModel):
    id: str = Field(alias="_id")
    actor: str
    action: str
    target: str
    reason: Optional[str] = None
    created_at: Any

    model_config = {"populate_by_name": True}
