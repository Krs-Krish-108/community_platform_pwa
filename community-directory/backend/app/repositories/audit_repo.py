"""
Audit logs repository — append-only accountability trail for admin actions.
Never stores secrets (OTPs, tokens, passwords) in before/after snapshots.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class AuditRepository(BaseRepository):
    collection_name = "audit_logs"

    async def record(
        self,
        actor: str,
        action: str,
        target: str,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> str:
        doc = {
            "actor": actor,
            "action": action,
            "target": target,
            "before": before,
            "after": after,
            "reason": reason,
            "created_at": utc_now(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def list_recent(
        self, page: int = 1, page_size: int = 50, actor: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        query = {"actor": actor} if actor else {}
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find(query).sort("created_at", -1).skip(skip).limit(page_size)
        )
        return [doc async for doc in cursor]

    async def list_for_target(self, target: str) -> List[Dict[str, Any]]:
        cursor = self.collection.find({"target": target}).sort("created_at", -1)
        return [doc async for doc in cursor]
