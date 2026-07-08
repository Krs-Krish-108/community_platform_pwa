"""
Device change requests repository — pending new-device approval workflow.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class DeviceChangeRequestsRepository(BaseRepository):
    collection_name = "device_change_requests"

    async def create_request(self, member_id: str) -> str:
        doc = {
            "member_id": member_id,
            "status": "PENDING",  # PENDING | APPROVED | REJECTED
            "requested_at": utc_now(),
            "reviewed_by": None,
            "reviewed_at": None,
            "review_reason": None,
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_pending_for_member(self, member_id: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {"member_id": member_id, "status": "PENDING"}
        )

    async def find_latest_for_member(self, member_id: str) -> Optional[Dict[str, Any]]:
        """Most recent request regardless of status — used to check for an
        APPROVED request awaiting the member's new passkey registration."""
        return await self.collection.find_one(
            {"member_id": member_id}, sort=[("requested_at", -1)]
        )

    async def mark_completed(self, request_id) -> bool:
        """Called once the member successfully registers their new passkey
        after admin approval, closing the loop on this request."""
        result = await self.collection.update_one(
            {"_id": request_id},
            {"$set": {"status": "COMPLETED", "completed_at": utc_now()}},
        )
        return result.modified_count > 0

    async def list_pending(self, page: int = 1, page_size: int = 50) -> List[Dict[str, Any]]:
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find({"status": "PENDING"})
            .sort("requested_at", 1)
            .skip(skip)
            .limit(page_size)
        )
        return [doc async for doc in cursor]

    async def approve(self, request_id, admin_member_id: str) -> bool:
        result = await self.collection.update_one(
            {"_id": request_id},
            {
                "$set": {
                    "status": "APPROVED",
                    "reviewed_by": admin_member_id,
                    "reviewed_at": utc_now(),
                }
            },
        )
        return result.modified_count > 0

    async def reject(self, request_id, admin_member_id: str, reason: str) -> bool:
        result = await self.collection.update_one(
            {"_id": request_id},
            {
                "$set": {
                    "status": "REJECTED",
                    "reviewed_by": admin_member_id,
                    "reviewed_at": utc_now(),
                    "review_reason": reason,
                }
            },
        )
        return result.modified_count > 0
