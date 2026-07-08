"""
Directory service — orchestrates search/filter query construction and
privacy-projected responses. This is the layer routes call; it owns no
database access directly (that's the repository's job) and no HTTP concerns.

FR-DIR-002/003: supports search by name/city/state/organisation/occupation
plus structured filters on State, Blood Group, Occupation, Education Sector,
Sub-Caste.
FR-DIR-004: results are paginated; only card-level fields are returned in lists.
FR-DIR-006: never exposes an unrestricted raw dump or direct Sheet/CSV source.
"""
import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.errors import NotFound
from app.domain.privacy_service import project_directory_card, project_profile
from app.repositories.members_repo import MembersRepository

# Filter field -> profile sub-field mapping (Backend Blueprint §7.2)
FILTERABLE_FIELDS = {
    "state": "profile.state",
    "blood_group": "profile.blood_group",
    "occupation": "profile.occupation",
    "education_sector": "profile.education_sector",
    "sub_caste": "profile.sub_caste",
}

# Fields searched by free-text `q` (case-insensitive substring match)
SEARCH_FIELDS = [
    "profile.name", "profile.city", "profile.state",
    "profile.organisation", "profile.occupation", "profile.about",
]

MAX_PAGE_SIZE = 100


def _escape_regex(text: str) -> str:
    return re.escape(text)


def build_directory_query(
    q: Optional[str] = None,
    state: Optional[str] = None,
    blood_group: Optional[str] = None,
    occupation: Optional[str] = None,
    education_sector: Optional[str] = None,
    sub_caste: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the Mongo filter dict from search/filter parameters."""
    query: Dict[str, Any] = {}

    filter_values = {
        "state": state,
        "blood_group": blood_group,
        "occupation": occupation,
        "education_sector": education_sector,
        "sub_caste": sub_caste,
    }
    for key, value in filter_values.items():
        if value:
            query[FILTERABLE_FIELDS[key]] = value

    if q and q.strip():
        pattern = _escape_regex(q.strip())
        query["$or"] = [
            {field: {"$regex": pattern, "$options": "i"}} for field in SEARCH_FIELDS
        ]

    return query


class DirectoryService:
    def __init__(self, db):
        self.db = db
        self.members_repo = MembersRepository(db)

    async def search_directory(
        self,
        q: Optional[str] = None,
        state: Optional[str] = None,
        blood_group: Optional[str] = None,
        occupation: Optional[str] = None,
        education_sector: Optional[str] = None,
        sub_caste: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Returns (card_results, total_count). Only ACTIVE members are ever
        included — enforced inside MembersRepository.list_directory.
        """
        page = max(1, page)
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))

        query = build_directory_query(
            q=q, state=state, blood_group=blood_group,
            occupation=occupation, education_sector=education_sector,
            sub_caste=sub_caste,
        )

        docs = await self.members_repo.list_directory(query, page, page_size)
        total = await self.members_repo.count_directory(query)

        cards = [project_directory_card(doc) for doc in docs]
        return cards, total

    async def get_filter_options(self) -> Dict[str, List[str]]:
        """Distinct values for each filterable field, for populating filter chips."""
        result = {}
        for key in FILTERABLE_FIELDS:
            result[key] = await self.members_repo.distinct_values(f"profile.{key}")
        return result

    async def get_profile(
        self, member_id: str, viewer_member_id: str, viewer_role: str
    ) -> Dict[str, Any]:
        """
        Return a privacy-projected profile. Only ACTIVE members can be viewed
        (FR-DIR-001) — even by other active members. Admins may view any
        status via a separate admin route (not this one).
        """
        member = await self.members_repo.find_by_member_id(member_id)
        if not member or member.get("status") != "ACTIVE":
            raise NotFound("Member not found.")

        return project_profile(member, viewer_member_id, viewer_role)
