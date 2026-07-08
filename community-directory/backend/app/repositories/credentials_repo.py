"""
WebAuthn credentials repository — passkey public-key material storage.
"""
from typing import Any, Dict, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class CredentialsRepository(BaseRepository):
    collection_name = "webauthn_credentials"

    async def create_credential(
        self,
        member_id: str,
        device_id: str,
        credential_id: str,
        public_key: bytes,
        sign_count: int,
    ) -> str:
        doc = {
            "member_id": member_id,
            "device_id": device_id,
            "credential_id": credential_id,
            "public_key": public_key,
            "sign_count": sign_count,
            "created_at": utc_now(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def find_by_credential_id(
        self, credential_id: str
    ) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"credential_id": credential_id})

    async def find_by_device_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"device_id": device_id})

    async def update_sign_count(self, credential_id: str, new_count: int) -> bool:
        result = await self.collection.update_one(
            {"credential_id": credential_id},
            {"$set": {"sign_count": new_count}},
        )
        return result.modified_count > 0

    async def delete_for_device(self, device_id: str) -> int:
        result = await self.collection.delete_many({"device_id": device_id})
        return result.deleted_count
