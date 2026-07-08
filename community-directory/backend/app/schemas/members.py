"""
Pydantic schemas for directory search, filters, and profile responses.
"""
from typing import Any, List, Optional
from pydantic import BaseModel


class DirectoryCardOut(BaseModel):
    member_id: str
    name: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    occupation: Optional[str] = None
    organisation: Optional[str] = None
    updated_at: Optional[Any] = None


class DirectoryFiltersOut(BaseModel):
    state: List[str] = []
    blood_group: List[str] = []
    occupation: List[str] = []
    education_sector: List[str] = []
    sub_caste: List[str] = []


class MemberProfileOut(BaseModel):
    """
    Flexible response model — actual fields present depend on viewer role
    and target member's visibility settings (see privacy_service.py).
    Extra fields beyond this base set are allowed and passed through.
    """
    member_id: str
    name: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    occupation: Optional[str] = None
    organisation: Optional[str] = None
    education_sector: Optional[str] = None
    about: Optional[str] = None

    model_config = {"extra": "allow"}
