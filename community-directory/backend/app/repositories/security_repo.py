"""
Security repository — low-level security events and admin-reviewable flags.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class SecurityRepository(BaseRepository):
    collection_name = "security_events"

    async def record_event(
        self,
        event_type: str,
        member_ref: Optional[str] = None,
        source_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        doc = {
            "event_type": event_type,
            "member_ref": member_ref,
            "source_hash": source_hash,
            "metadata": metadata or {},
            "created_at": utc_now(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def count_recent_by_type(
        self, event_type: str, since, member_ref: Optional[str] = None
    ) -> int:
        query: Dict[str, Any] = {"event_type": event_type, "created_at": {"$gte": since}}
        if member_ref:
            query["member_ref"] = member_ref
        return await self.collection.count_documents(query)

    async def list_recent(self, page: int = 1, page_size: int = 50) -> List[Dict[str, Any]]:
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find({}).sort("created_at", -1).skip(skip).limit(page_size)
        )
        return [doc async for doc in cursor]


class SecurityFlagsRepository(BaseRepository):
    collection_name = "security_flags"

    async def create_flag(
        self,
        rule_code: str,
        severity: str,
        target_ref: str,
        evidence_event_ids: List[str],
    ) -> str:
        doc = {
            "rule_code": rule_code,
            "severity": severity,  # LOW | MEDIUM | HIGH
            "target_ref": target_ref,
            "evidence_event_ids": evidence_event_ids,
            "status": "OPEN",  # OPEN | REVIEWING | RESOLVED
            "admin_notes": None,
            "created_at": utc_now(),
            "resolved_at": None,
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_open_for_target(self, target_ref: str, rule_code: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {"target_ref": target_ref, "rule_code": rule_code, "status": {"$ne": "RESOLVED"}}
        )

    async def list_open(self, page: int = 1, page_size: int = 50) -> List[Dict[str, Any]]:
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find({"status": {"$ne": "RESOLVED"}})
            .sort("created_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        return [doc async for doc in cursor]

    async def resolve(self, flag_id, admin_notes: Optional[str] = None) -> bool:
        result = await self.collection.update_one(
            {"_id": flag_id},
            {
                "$set": {
                    "status": "RESOLVED",
                    "admin_notes": admin_notes,
                    "resolved_at": utc_now(),
                }
            },
        )
        return result.modified_count > 0
