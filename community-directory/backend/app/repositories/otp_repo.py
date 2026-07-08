"""
OTP challenges repository — short-lived verification code storage.
Raw OTP values are never stored, only their SHA-256 hash.
"""
from typing import Any, Dict, Optional

from app.core.security import utc_now, otp_expiry
from app.repositories.base import BaseRepository


class OTPRepository(BaseRepository):
    collection_name = "otp_challenges"

    async def create_challenge(
        self, member_id: str, purpose: str, otp_hash: str
    ) -> str:
        """
        purpose: "ENROLLMENT" | "DEVICE_CHANGE" | "LOGIN_RECOVERY"
        """
        doc = {
            "member_id": member_id,
            "purpose": purpose,
            "otp_hash": otp_hash,
            "attempts": 0,
            "created_at": utc_now(),
            "expires_at": otp_expiry(),
            "consumed_at": None,
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_active_challenge(
        self, member_id: str, purpose: str
    ) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {
                "member_id": member_id,
                "purpose": purpose,
                "consumed_at": None,
                "expires_at": {"$gt": utc_now()},
            },
            sort=[("created_at", -1)],
        )

    async def find_last_challenge_any_state(
        self, member_id: str, purpose: str
    ) -> Optional[Dict[str, Any]]:
        """Used for resend-cooldown checks, regardless of consumed/expired state."""
        return await self.collection.find_one(
            {"member_id": member_id, "purpose": purpose},
            sort=[("created_at", -1)],
        )

    async def increment_attempts(self, challenge_id) -> int:
        result = await self.collection.find_one_and_update(
            {"_id": challenge_id},
            {"$inc": {"attempts": 1}},
            return_document=True,
        )
        return result["attempts"] if result else 0

    async def consume_challenge(self, challenge_id) -> bool:
        result = await self.collection.update_one(
            {"_id": challenge_id},
            {"$set": {"consumed_at": utc_now()}},
        )
        return result.modified_count > 0

    async def expire_challenge(self, challenge_id) -> bool:
        result = await self.collection.update_one(
            {"_id": challenge_id},
            {"$set": {"expires_at": utc_now()}},
        )
        return result.modified_count > 0

    async def count_today(self, member_id: str, purpose: str) -> int:
        from datetime import timedelta
        start_of_day = utc_now().replace(hour=0, minute=0, second=0, microsecond=0)
        return await self.collection.count_documents(
            {
                "member_id": member_id,
                "purpose": purpose,
                "created_at": {"$gte": start_of_day},
            }
        )
