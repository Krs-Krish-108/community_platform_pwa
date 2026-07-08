"""
Sessions repository — opaque server-side session storage.
Raw session tokens are never stored; only their HMAC hash.
"""
from typing import Any, Dict, Optional

from app.core.security import utc_now, session_expiry
from app.repositories.base import BaseRepository


class SessionsRepository(BaseRepository):
    collection_name = "sessions"

    async def create_session(
        self, member_id: str, session_token_hash: str, device_id: str = None
    ) -> str:
        doc = {
            "session_token_hash": session_token_hash,
            "member_id": member_id,
            "device_id": device_id,  # None for admin password sessions until WebAuthn (Phase 5)
            "created_at": utc_now(),
            "expires_at": session_expiry(),
            "revoked_at": None,
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_active_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {
                "session_token_hash": token_hash,
                "revoked_at": None,
                "expires_at": {"$gt": utc_now()},
            }
        )

    async def revoke_session(self, token_hash: str) -> bool:
        result = await self.collection.update_one(
            {"session_token_hash": token_hash},
            {"$set": {"revoked_at": utc_now()}},
        )
        return result.modified_count > 0

    async def revoke_all_for_device(self, device_id: str) -> int:
        """Called when a device is revoked — invalidate every session tied to it."""
        result = await self.collection.update_many(
            {"device_id": device_id, "revoked_at": None},
            {"$set": {"revoked_at": utc_now()}},
        )
        return result.modified_count

    async def revoke_all_for_member(self, member_id: str) -> int:
        """Called when a member is suspended/deactivated."""
        result = await self.collection.update_many(
            {"member_id": member_id, "revoked_at": None},
            {"$set": {"revoked_at": utc_now()}},
        )
        return result.modified_count
