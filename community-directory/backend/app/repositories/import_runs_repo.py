"""
Import runs repository — CSV import history and validation trail.
"""
from typing import Any, Dict, List, Optional

from app.core.security import utc_now
from app.repositories.base import BaseRepository


class ImportRunsRepository(BaseRepository):
    collection_name = "import_runs"

    async def create_run(
        self,
        uploader_id: str,
        source_name: str,
        total_rows: int,
        valid_rows: int,
        invalid_rows: int,
        errors: List[Dict[str, Any]],
    ) -> str:
        doc = {
            "uploader_id": uploader_id,
            "source_name": source_name,
            "status": "COMPLETED",
            "totals": {
                "total": total_rows,
                "valid": valid_rows,
                "invalid": invalid_rows,
            },
            "errors": errors,
            "created_at": utc_now(),
        }
        result = await self.collection.insert_one(doc)
        return str(result.inserted_id)

    async def list_recent(self, page: int = 1, page_size: int = 20) -> List[Dict[str, Any]]:
        skip = (page - 1) * page_size
        cursor = (
            self.collection.find({}).sort("created_at", -1).skip(skip).limit(page_size)
        )
        return [doc async for doc in cursor]

    async def find_by_id(self, run_id) -> Optional[Dict[str, Any]]:
        return await self.collection.find_one({"_id": run_id})
