"""
WebAuthn challenges repository.

Stores the server-generated challenge between the "options" and "verify"
steps of both registration and login ceremonies. Challenges are single-use
and short-lived (5 minutes), keyed by subject:

  - Registration: subject_type="member", subject_id=<member_id>
    (no device exists yet, so we key by the member proving enrolment)
  - Login: subject_type="device", subject_id=<device _id string>
    (the device cookie identifies which device/credential is authenticating)

Challenge bytes are stored base64url-encoded (text-safe for any DB backend).
"""
from datetime import timedelta
from typing import Any, Dict, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository

CHALLENGE_TTL_MINUTES = 5


class WebAuthnChallengesRepository(BaseRepository):
    collection_name = "webauthn_challenges"

    async def create(
        self, subject_type: str, subject_id: str, purpose: str, challenge_b64: str
    ) -> str:
        doc = {
            "subject_type": subject_type,  # "member" | "device"
            "subject_id": subject_id,
            "purpose": purpose,  # "REGISTRATION" | "LOGIN"
            "challenge": challenge_b64,
            "created_at": utc_now(),
            "expires_at": utc_now() + timedelta(minutes=CHALLENGE_TTL_MINUTES),
            "consumed_at": None,
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_valid(
        self, subject_type: str, subject_id: str, purpose: str
    ) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one(
            {
                "subject_type": subject_type,
                "subject_id": subject_id,
                "purpose": purpose,
                "consumed_at": None,
                "expires_at": {"$gt": utc_now()},
            },
            sort=[("created_at", -1)],
        )

    async def consume(self, challenge_id) -> bool:
        result = await self.collection.update_one(
            {"_id": challenge_id}, {"$set": {"consumed_at": utc_now()}}
        )
        return result.modified_count > 0
