"""
Common response schemas shared across route modules.
"""
from typing import Any, Generic, Optional, TypeVar
from pydantic import BaseModel

T = TypeVar("T")


class Meta(BaseModel):
    request_id: str
    page: Optional[int] = None
    page_size: Optional[int] = None
    total: Optional[int] = None


class SuccessResponse(BaseModel, Generic[T]):
    data: T
    meta: Meta


class PaginationParams(BaseModel):
    page: int = 1
    page_size: int = 20

    def clamp(self) -> "PaginationParams":
        self.page = max(1, self.page)
        self.page_size = max(1, min(self.page_size, 100))
        return self
