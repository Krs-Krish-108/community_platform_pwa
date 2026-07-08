"""
Pydantic schemas for shared Inbox posts and Emergency alerts.
"""
from typing import Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, model_validator


class PostCreate(BaseModel):
    message: Optional[str] = Field(None, max_length=5000)
    media_ids: Optional[List[str]] = None

    @model_validator(mode="after")
    def validate_content(self) -> "PostCreate":
        message_val = self.message.strip() if self.message else ""
        has_message = len(message_val) > 0
        has_media = bool(self.media_ids and len(self.media_ids) > 0)
        
        if not has_message and not has_media:
            raise ValueError("Post must contain either a message or media attachments.")
        return self


class PostModerationInfo(BaseModel):
    reason: str
    actioned_by: str
    actioned_at: datetime


class PostResolutionInfo(BaseModel):
    note: Optional[str] = None
    resolved_by: str
    resolved_at: datetime


class PostResponse(BaseModel):
    id: str
    type: str
    author_member_id: str
    message: Optional[str] = None
    media_ids: List[str] = []
    status: str
    priority: str
    reported_count: int
    moderation: Optional[PostModerationInfo] = None
    resolution: Optional[PostResolutionInfo] = None
    created_at: Any
    updated_at: Any

    class Config:
        from_attributes = True


class ResolveEmergencyRequest(BaseModel):
    note: Optional[str] = None

