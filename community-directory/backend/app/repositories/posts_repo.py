"""
Posts repository — Inbox messages and Emergency alerts (unified collection).
Author identity is always passed in from the session by the calling service —
this repository never derives or accepts identity from a client payload.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class PostsRepository(BaseRepository):
    collection_name = "posts"

    async def create_post(
        self,
        post_type: str,          # "INBOX" | "EMERGENCY"
        author_member_id: str,
        message: str,
        media_ids: Optional[List[str]] = None,
    ) -> str:
        doc = {
            "type": post_type,
            "author_member_id": author_member_id,
            "message": message,
            "media_ids": media_ids or [],
            "status": "ACTIVE",       # ACTIVE | REMOVED | RESOLVED | ARCHIVED
            "priority": "URGENT" if post_type == "EMERGENCY" else "NORMAL",
            "reported_count": 0,
            "moderation": None,
            "resolution": None,
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def list_feed(
        self, post_type: str, page: int = 1, page_size: int = 20, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Returns ACTIVE + RESOLVED by default; excludes REMOVED unless status filter is explicitly specified."""
        skip = (page - 1) * page_size
        
        if status:
            status_filter = status
        else:
            status_filter = {"$in": ["ACTIVE", "RESOLVED"]}
            
        cursor = (
            self.collection.find(
                {"type": post_type, "status": status_filter}
            )
            .sort("created_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        return [doc async for doc in cursor]

    async def find_by_id(self, post_id) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"_id": post_id})

    async def report_post(self, post_id) -> bool:
        result = await self.collection.update_one(
            {"_id": post_id}, {"$inc": {"reported_count": 1}}
        )
        return result.modified_count > 0

    async def remove_post(self, post_id, actioned_by: str, reason: str) -> bool:
        result = await self.collection.update_one(
            {"_id": post_id},
            {
                "$set": {
                    "status": "REMOVED",
                    "moderation": {
                        "reason": reason,
                        "actioned_by": actioned_by,
                        "actioned_at": utc_now(),
                    },
                    "updated_at": utc_now(),
                }
            },
        )
        return result.modified_count > 0

    async def resolve_emergency(
        self, post_id, resolved_by: str, note: Optional[str] = None
    ) -> bool:
        result = await self.collection.update_one(
            {"_id": post_id, "type": "EMERGENCY"},
            {
                "$set": {
                    "status": "RESOLVED",
                    "resolution": {
                        "note": note,
                        "resolved_by": resolved_by,
                        "resolved_at": utc_now(),
                    },
                    "updated_at": utc_now(),
                }
            },
        )
        return result.modified_count > 0

    async def count_by_author_since(
        self, author_member_id: str, since
    ) -> int:
        """Used for per-member burst rate limiting."""
        return await self.collection.count_documents(
            {"author_member_id": author_member_id, "created_at": {"$gte": since}}
        )
