"""
Enrollment tickets repository.

An enrollment ticket is a short-lived, opaque, server-side proof that a
member has JUST completed OTP verification. It is consumed by the WebAuthn
registration step (Phase 5) — OTP success alone never grants directory
access or creates a session (non-negotiable rule: no OTP-only activation).

Raw ticket values are returned to the client once and never stored —
only their HMAC hash is persisted, exactly like sessions and device cookies.
"""
from typing import Any, Dict, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class EnrollmentTicketsRepository(BaseRepository):
    collection_name = "enrollment_tickets"

    async def create(
        self, member_id: str, purpose: str, token_hash: str, ttl_minutes: int = 10
    ) -> str:
        from datetime import timedelta
        doc = {
            "member_id": member_id,
            "purpose": purpose,  # e.g. "PASSKEY_REGISTRATION"
            "token_hash": token_hash,
            "created_at": utc_now(),
            "expires_at": utc_now() + timedelta(minutes=ttl_minutes),
            "consumed_at": None,
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_valid(self, token_hash: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {
                "token_hash": token_hash,
                "consumed_at": None,
                "expires_at": {"$gt": utc_now()},
            }
        )

    async def consume(self, ticket_id) -> bool:
        result = await self.collection.update_one(
            {"_id": ticket_id}, {"$set": {"consumed_at": utc_now()}}
        )
        return result.modified_count > 0
