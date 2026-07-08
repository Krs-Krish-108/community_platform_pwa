"""
Members repository — database access for the members collection.
No business rules here; see domain/member_service.py for policy logic.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class MembersRepository(BaseRepository):
    collection_name = "members"

    async def find_by_member_id(self, member_id: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"member_id": member_id})

    async def find_by_email(self, email_normalized: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {"registered_email_normalized": email_normalized}
        )

    async def find_by_member_id_and_email(
        self, member_id: str, email_normalized: str
    ) -> Optional[Dict[str, Any]]:
        """Used during enrolment identity check. Must match BOTH fields."""
        return await self.collection.find_one(
            {
                "member_id": member_id,
                "registered_email_normalized": email_normalized,
            }
        )

    async def insert_staged(self, record: Dict[str, Any]) -> str:
        record.setdefault("status", "STAGED")
        record.setdefault("created_at", utc_now())
        record.setdefault("updated_at", utc_now())
        result = await self.collection.insert_one(record)
        return str(result.inserted_id)

    async def approve_and_issue_id(
        self, object_id, member_id: str
    ) -> Optional[Dict[str, Any]]:
        result = await self.collection.find_one_and_update(
            {"_id": object_id},
            {
                "$set": {
                    "member_id": member_id,
                    "status": "PENDING_ENROLLMENT",
                    "updated_at": utc_now(),
                }
            },
            return_document=True,
        )
        return result

    async def update_status(self, member_id: str, status: str) -> bool:
        result = await self.collection.update_one(
            {"member_id": member_id},
            {"$set": {"status": status, "updated_at": utc_now()}},
        )
        return result.modified_count > 0

    async def update_profile(
        self, member_id: str, updates: Dict[str, Any]
    ) -> bool:
        updates["updated_at"] = utc_now()
        result = await self.collection.update_one(
            {"member_id": member_id}, {"$set": updates}
        )
        return result.modified_count > 0

    async def activate_member(self, member_id: str) -> bool:
        """Called after successful device/passkey enrolment."""
        result = await self.collection.update_one(
            {"member_id": member_id},
            {"$set": {"status": "ACTIVE", "updated_at": utc_now()}},
        )
        return result.modified_count > 0

    async def list_directory(
        self,
        query: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return only ACTIVE members matching filters, paginated."""
        filters = {"status": "ACTIVE"}
        if query:
            filters.update(query)

        skip = (page - 1) * page_size
        cursor = (
            self.collection.find(filters)
            .sort("name", 1)
            .skip(skip)
            .limit(page_size)
        )
        return [doc async for doc in cursor]

    async def count_directory(self, query: Optional[Dict[str, Any]] = None) -> int:
        filters = {"status": "ACTIVE"}
        if query:
            filters.update(query)
        return await self.collection.count_documents(filters)

    async def distinct_values(self, field: str) -> List[str]:
        """Return distinct non-empty values for a directory filter field."""
        values = await self.collection.distinct(field, {"status": "ACTIVE"})
        return sorted([v for v in values if v])

    async def count_staged(self) -> int:
        return await self.collection.count_documents({"status": "STAGED"})

    async def list_by_status(
        self, status: str, page: int = 1, page_size: int = 50
    ) -> List[Dict[str, Any]]:
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find({"status": status})
            .sort("created_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        return [doc async for doc in cursor]
