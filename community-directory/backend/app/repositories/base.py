"""
Base repository class. All repositories inherit from this.
Repositories own ONLY database access — no business logic, no policy decisions.
"""
from typing import Any, Dict, Optional
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase, AsyncIOMotorCollection


class BaseRepository:
    collection_name: str = ""

    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    @property
    def collection(self) -> AsyncIOMotorCollection:
        return self.db[self.collection_name]

    @staticmethod
    def to_object_id(id_value: str) -> Optional[ObjectId]:
        try:
            return ObjectId(id_value)
        except Exception:
            return None

    @staticmethod
    def serialize(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Convert MongoDB ObjectId fields to strings for API responses."""
        if doc is None:
            return None
        doc = dict(doc)
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return doc
