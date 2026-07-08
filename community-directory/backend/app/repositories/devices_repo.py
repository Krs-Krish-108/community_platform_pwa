"""
Devices repository — trusted-device lifecycle storage.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now, device_cookie_expiry
from app.repositories.base import BaseRepository


class DevicesRepository(BaseRepository):
    collection_name = "devices"

    async def create_device(
        self,
        member_id: str,
        device_cookie_hash: str,
        credential_id: str,
        status: str = "ACTIVE",
    ) -> str:
        doc = {
            "member_id": member_id,
            "member_ref_id": member_id,
            "device_cookie_hash": device_cookie_hash,
            "credential_id": credential_id,
            "status": status,  # PENDING | ACTIVE | REVOKED
            "created_at": utc_now(),
            "approved_at": utc_now() if status == "ACTIVE" else None,
            "revoked_at": None,
            "expires_at": device_cookie_expiry(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_active_device_by_hash(
        self, device_cookie_hash: str
    ) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {
                "device_cookie_hash": device_cookie_hash,
                "status": "ACTIVE",
            }
        )

    async def find_by_hash(self, device_cookie_hash: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"device_cookie_hash": device_cookie_hash})

    async def find_current_for_member(self, member_id: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {"member_id": member_id, "status": "ACTIVE"},
            sort=[("created_at", -1)],
        )

    async def revoke_device(self, device_id) -> bool:
        result = await self.collection.update_one(
            {"_id": device_id},
            {"$set": {"status": "REVOKED", "revoked_at": utc_now()}},
        )
        return result.modified_count > 0

    async def revoke_all_for_member(self, member_id: str) -> int:
        result = await self.collection.update_many(
            {"member_id": member_id, "status": "ACTIVE"},
            {"$set": {"status": "REVOKED", "revoked_at": utc_now()}},
        )
        return result.modified_count

    async def list_for_member(self, member_id: str) -> List[Dict[str, Any]]:
        cursor = self.collection.find({"member_id": member_id}).sort("created_at", -1)
        return [doc async for doc in cursor]
