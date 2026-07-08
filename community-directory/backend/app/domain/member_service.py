"""
Member service — approval workflow, secure Member ID issuance, and lifecycle
status transitions (suspend, deactivate, reactivate).

FR-IMP-005: Member IDs are backend-generated, random, and never derived from
a name, timestamp, or any client-supplied value.

Every state-changing action here is audited (SEC-009 / FR-ADM-005).
"""
import secrets
import string
from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.core.errors import ConflictError, NotFound, ValidationError
from app.core.logging import get_logger
from app.domain.audit_service import AuditService
from app.repositories.devices_repo import DevicesRepository
from app.repositories.members_repo import MembersRepository
from app.repositories.sessions_repo import SessionsRepository

logger = get_logger(__name__)

# Member ID alphabet excludes ambiguous characters (0/O, 1/I) for readability
_ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_ID_LENGTH = 8
_MAX_ID_GENERATION_ATTEMPTS = 10

VALID_STATUSES = {
    "STAGED", "PENDING_ENROLLMENT", "ACTIVE", "SUSPENDED", "DEACTIVATED",
}


def _generate_candidate_id() -> str:
    """Generate a random, non-guessable Member ID. Never derived from PII."""
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(_ID_LENGTH))


class MemberService:
    def __init__(self, db):
        self.db = db
        self.members_repo = MembersRepository(db)
        self.devices_repo = DevicesRepository(db)
        self.sessions_repo = SessionsRepository(db)
        self.audit = AuditService(db)

    async def _generate_unique_member_id(self) -> str:
        for _ in range(_MAX_ID_GENERATION_ATTEMPTS):
            candidate = _generate_candidate_id()
            existing = await self.members_repo.find_by_member_id(candidate)
            if not existing:
                return candidate
        # Astronomically unlikely with 32^8 keyspace, but fail safely if it happens
        raise RuntimeError("Could not generate a unique Member ID after multiple attempts")

    async def approve_staged_member(
        self, staged_object_id: str, actor_member_id: str
    ) -> Dict[str, Any]:
        """
        FR-IMP-005/006: Approve a STAGED record. Backend issues a secure random
        Member ID and moves the record to PENDING_ENROLLMENT.
        """
        oid = ObjectId(staged_object_id) if not isinstance(staged_object_id, ObjectId) else staged_object_id

        existing = await self.members_repo.collection.find_one({"_id": oid})
        if not existing:
            raise NotFound("Staged member record not found.")
        if existing.get("status") != "STAGED":
            raise ConflictError(
                f"Record is not in STAGED status (current: {existing.get('status')})."
            )

        member_id = await self._generate_unique_member_id()
        updated = await self.members_repo.approve_and_issue_id(oid, member_id)

        await self.audit.log(
            actor=actor_member_id,
            action="MEMBER_APPROVED",
            target=member_id,
            before={"status": "STAGED"},
            after={"status": "PENDING_ENROLLMENT", "member_id": member_id},
        )

        logger.info("Member approved: %s (was staged _id=%s)", member_id, staged_object_id)
        return self.members_repo.serialize(updated)

    async def edit_member(
        self, member_id: str, updates: Dict[str, Any], actor_member_id: str
    ) -> Dict[str, Any]:
        """Admin edits a member's profile fields."""
        before = await self.members_repo.find_by_member_id(member_id)
        if not before:
            raise NotFound("Member not found.")

        # Only allow editing the profile sub-document and a defined allow-list
        allowed_top_level = {"visibility_settings"}
        profile_updates = {}
        top_level_updates = {}

        for key, value in updates.items():
            if key == "profile" and isinstance(value, dict):
                profile_updates = value
            elif key in allowed_top_level:
                top_level_updates[key] = value

        set_doc = dict(top_level_updates)
        for k, v in profile_updates.items():
            set_doc[f"profile.{k}"] = v

        if not set_doc:
            raise ValidationError("No valid fields to update.")

        await self.members_repo.update_profile(member_id, set_doc)
        after = await self.members_repo.find_by_member_id(member_id)

        await self.audit.log(
            actor=actor_member_id,
            action="MEMBER_EDITED",
            target=member_id,
            before={"profile": before.get("profile")},
            after={"profile": after.get("profile")},
        )

        return self.members_repo.serialize(after)

    async def suspend_member(
        self, member_id: str, actor_member_id: str, reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Suspend a member: revoke all sessions and devices immediately.
        A suspended member cannot access directory, posts, or media (SEC-003).
        """
        member = await self.members_repo.find_by_member_id(member_id)
        if not member:
            raise NotFound("Member not found.")

        before_status = member.get("status")
        await self.members_repo.update_status(member_id, "SUSPENDED")
        await self.sessions_repo.revoke_all_for_member(member_id)
        await self.devices_repo.revoke_all_for_member(member_id)

        await self.audit.log(
            actor=actor_member_id,
            action="MEMBER_SUSPENDED",
            target=member_id,
            before={"status": before_status},
            after={"status": "SUSPENDED"},
            reason=reason,
        )

        logger.info("Member suspended: %s (reason: %s)", member_id, reason)
        return {"member_id": member_id, "status": "SUSPENDED"}

    async def deactivate_member(
        self, member_id: str, actor_member_id: str, reason: Optional[str] = None
    ) -> Dict[str, Any]:
        member = await self.members_repo.find_by_member_id(member_id)
        if not member:
            raise NotFound("Member not found.")

        before_status = member.get("status")
        await self.members_repo.update_status(member_id, "DEACTIVATED")
        await self.sessions_repo.revoke_all_for_member(member_id)
        await self.devices_repo.revoke_all_for_member(member_id)

        await self.audit.log(
            actor=actor_member_id,
            action="MEMBER_DEACTIVATED",
            target=member_id,
            before={"status": before_status},
            after={"status": "DEACTIVATED"},
            reason=reason,
        )

        logger.info("Member deactivated: %s (reason: %s)", member_id, reason)
        return {"member_id": member_id, "status": "DEACTIVATED"}

    async def reactivate_member(
        self, member_id: str, actor_member_id: str, reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Reactivate a suspended/deactivated member. Does NOT restore old
        sessions or devices — the member must re-enrol via OTP + passkey.
        """
        member = await self.members_repo.find_by_member_id(member_id)
        if not member:
            raise NotFound("Member not found.")

        before_status = member.get("status")
        if before_status not in ("SUSPENDED", "DEACTIVATED"):
            raise ConflictError(f"Member is not suspended/deactivated (current: {before_status}).")

        await self.members_repo.update_status(member_id, "PENDING_ENROLLMENT")

        await self.audit.log(
            actor=actor_member_id,
            action="MEMBER_REACTIVATED",
            target=member_id,
            before={"status": before_status},
            after={"status": "PENDING_ENROLLMENT"},
            reason=reason,
        )

        logger.info("Member reactivated (pending re-enrolment): %s", member_id)
        return {"member_id": member_id, "status": "PENDING_ENROLLMENT"}

    async def list_staged(self, page: int = 1, page_size: int = 50) -> List[Dict[str, Any]]:
        docs = await self.members_repo.list_by_status("STAGED", page, page_size)
        return [self.members_repo.serialize(d) for d in docs]

    async def list_pending_enrollment(self, page: int = 1, page_size: int = 50) -> List[Dict[str, Any]]:
        docs = await self.members_repo.list_by_status("PENDING_ENROLLMENT", page, page_size)
        return [self.members_repo.serialize(d) for d in docs]

    async def export_active_members(self) -> List[Dict[str, Any]]:
        """Admin export of all ACTIVE member records (full fields, admin-only view)."""
        docs = await self.members_repo.list_directory(page=1, page_size=10_000)
        return [self.members_repo.serialize(d) for d in docs]
