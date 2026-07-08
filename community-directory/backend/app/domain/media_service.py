"""
Media service — orchestrates creating upload intents, confirming completed uploads,
verifying ownership/validation rules, and checking view permissions to generate access URLs.
"""
import uuid
from typing import Any, Dict, Optional, Tuple
from bson import ObjectId

from app.adapters.object_storage_adapter import ObjectStorageAdapter
from app.core.config import get_settings
from app.core.errors import NotFound, PermissionDenied
from app.repositories.media_repo import MediaRepository
from app.repositories.posts_repo import PostsRepository


class MediaService:
    def __init__(self, db):
        self.db = db
        self.media_repo = MediaRepository(db)
        self.posts_repo = PostsRepository(db)
        self.storage = ObjectStorageAdapter()
        self.settings = get_settings()

    async def create_upload_intent(
        self, owner_member_id: str, filename: str, content_type: str, size_bytes: int
    ) -> Tuple[str, str, str]:
        """
        Create a pending media record in the database and generate a presigned S3 upload URL.
        """
        # Ensure safe alphanumeric key names
        safe_filename = "".join(c for c in filename if c.isalnum() or c in "._-")
        storage_key = f"{owner_member_id}/{uuid.uuid4()}-{safe_filename}"
        
        media_id = await self.media_repo.create_pending(
            owner_member_id=owner_member_id,
            storage_key=storage_key,
            content_type=content_type,
            size_bytes=size_bytes,
        )
        
        upload_url = self.storage.generate_presigned_upload_url(
            storage_key=storage_key,
            content_type=content_type,
            expires_in=self.settings.media_signed_url_expire_seconds,
        )
        
        return media_id, storage_key, upload_url

    async def confirm_upload(
        self, media_id: str, member_id: str, is_admin: bool = False
    ) -> bool:
        """
        Confirm that a client has finished writing bytes to the presigned URL.
        Validates ownership before updating status.
        """
        try:
            oid = ObjectId(media_id)
        except Exception:
            raise NotFound("Media object not found.")
            
        media = await self.media_repo.find_by_id(oid)
        if not media:
            raise NotFound("Media object not found.")
            
        # Enforce ownership check
        if media["owner_member_id"] != member_id and not is_admin:
            raise PermissionDenied("You do not own this media object.")
            
        return await self.media_repo.confirm(oid)

    async def get_access_url(
        self, media_id: str, viewer_member_id: str, viewer_role: str
    ) -> str:
        """
        Validate that the viewer is authorized to access the media and return a presigned download URL.
        """
        try:
            oid = ObjectId(media_id)
        except Exception:
            raise NotFound("Media object not found.")
            
        media = await self.media_repo.find_by_id(oid)
        if not media:
            raise NotFound("Media object not found.")
            
        if media["status"] != "CONFIRMED":
            raise PermissionDenied("Media upload is not confirmed.")

        is_admin = viewer_role == "admin"
        linked_post_id = media.get("linked_post_id")

        if not linked_post_id:
            # Unlinked: restricted to owner/admin
            if media["owner_member_id"] != viewer_member_id and not is_admin:
                raise PermissionDenied("Access to unlinked media is restricted to the owner.")
        else:
            # Linked: verify the parent post status
            try:
                p_oid = ObjectId(linked_post_id)
            except Exception:
                raise NotFound("Associated post not found.")
                
            post = await self.posts_repo.find_by_id(p_oid)
            if not post:
                raise NotFound("Associated post not found.")
                
            # If the post is soft-removed by admin, normal members are blocked from media too
            if post["status"] == "REMOVED" and not is_admin:
                raise PermissionDenied("Access to moderated media is restricted.")

        return self.storage.generate_presigned_download_url(
            storage_key=media["storage_key"],
            expires_in=self.settings.media_signed_url_expire_seconds,
        )
