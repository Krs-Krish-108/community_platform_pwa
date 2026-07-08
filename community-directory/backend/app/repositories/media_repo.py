"""
Media objects repository — private media metadata storage.
Actual file bytes live in object storage (R2/S3); this stores only metadata
and ownership references.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class MediaRepository(BaseRepository):
    collection_name = "media_objects"

    async def create_pending(
        self,
        owner_member_id: str,
        storage_key: str,
        content_type: str,
        size_bytes: int,
    ) -> str:
        doc = {
            "owner_member_id": owner_member_id,
            "storage_key": storage_key,
            "content_type": content_type,
            "size_bytes": size_bytes,
            "status": "PENDING",  # PENDING | CONFIRMED | REJECTED
            "linked_post_id": None,
            "created_at": utc_now(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def confirm(self, media_id) -> bool:
        result = await self.collection.update_one(
            {"_id": media_id}, {"$set": {"status": "CONFIRMED"}}
        )
        return result.modified_count > 0

    async def link_to_post(self, media_id, post_id) -> bool:
        result = await self.collection.update_one(
            {"_id": media_id}, {"$set": {"linked_post_id": str(post_id)}}
        )
        return result.modified_count > 0

    async def find_by_id(self, media_id) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"_id": media_id})

    async def find_orphans(self, older_than) -> List[Dict[str, Any]]:
        """Media never linked to a post after a grace period — for cleanup job."""
        cursor = self.collection.find(
            {"linked_post_id": None, "created_at": {"$lt": older_than}}
        )
        return [doc async for doc in cursor]
