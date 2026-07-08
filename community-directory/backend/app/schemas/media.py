"""
Pydantic schemas for media uploads, complete confirmation, and access URLs.
"""
from typing import Optional
from pydantic import BaseModel, Field, model_validator

from app.core.config import get_settings


class UploadIntentRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_type: str
    size_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def validate_type_and_size(self) -> "UploadIntentRequest":
        settings = get_settings()
        content_type_lower = self.content_type.lower().strip()
        
        allowed_images = {"image/jpeg", "image/png", "image/gif", "image/webp"}
        allowed_videos = {"video/mp4", "video/quicktime", "video/webm"}
        
        is_image = content_type_lower in allowed_images
        is_video = content_type_lower in allowed_videos
        
        if not is_image and not is_video:
            raise ValueError(
                f"Unsupported content type '{self.content_type}'. "
                "Only standard image (JPEG, PNG, GIF, WEBP) and video (MP4, MOV, WEBM) formats are allowed."
            )
            
        if is_image:
            limit_bytes = settings.media_max_image_mb * 1024 * 1024
            if self.size_bytes > limit_bytes:
                raise ValueError(f"Image file size exceeds the {settings.media_max_image_mb} MB limit.")
        elif is_video:
            limit_bytes = settings.media_max_video_mb * 1024 * 1024
            if self.size_bytes > limit_bytes:
                raise ValueError(f"Video file size exceeds the {settings.media_max_video_mb} MB limit.")
                
        return self


class UploadIntentResponse(BaseModel):
    media_id: str
    storage_key: str
    upload_url: str


class UploadCompleteRequest(BaseModel):
    media_id: str


class MediaAccessResponse(BaseModel):
    access_url: str
