"""
Auth service — the enrolment/re-verification front door.

Two purposes share the same identify + OTP flow, distinguished by the
member's current status (Backend Blueprint §6.1, §6.3):

  - status == PENDING_ENROLLMENT -> purpose ENROLLMENT (first-time device)
    On OTP success: issue a short-lived enrollment ticket. Phase 5's
    WebAuthn registration consumes this ticket to create the first
    trusted device. The member is NOT activated and NO session is created
    here — OTP alone never grants access.

  - status == ACTIVE -> purpose DEVICE_CHANGE (existing member, new/reset device)
    On OTP success: create a PENDING device-change request for admin
    review (Phase 2's admin approval routes already handle the admin side).
    OTP proves control of the registered email; it does NOT bypass the
    device-approval policy (FR-DEV-007).

  - Any other status (STAGED, SUSPENDED, DEACTIVATED) or no match at all:
    generic response, no OTP sent, security event recorded
    (FR-AUTH-003: never reveal whether a Member ID/email exists).
"""
from typing import Any, Dict, Optional

from app.core.logging import get_logger
from app.core.security import utc_now
from app.adapters.smtp_adapter import SMTPAdapter
from app.domain.otp_service import OTPService
from app.domain.security_service import SecurityService
from app.repositories.device_change_requests_repo import DeviceChangeRequestsRepository
from app.repositories.enrollment_tickets_repo import EnrollmentTicketsRepository
from app.repositories.members_repo import MembersRepository

logger = get_logger(__name__)

PURPOSE_ENROLLMENT = "ENROLLMENT"
PURPOSE_DEVICE_CHANGE = "DEVICE_CHANGE"

# Statuses eligible to receive an OTP, mapped to the resulting purpose
_ELIGIBLE_STATUS_PURPOSE = {
    "PENDING_ENROLLMENT": PURPOSE_ENROLLMENT,
    "ACTIVE": PURPOSE_DEVICE_CHANGE,
}


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _normalize_member_id(member_id: str) -> str:
    return member_id.strip().upper()


class AuthService:
    def __init__(self, db):
        self.db = db
        self.members_repo = MembersRepository(db)
        self.otp_service = OTPService(db)
        self.security_service = SecurityService(db)
        self.enrollment_tickets_repo = EnrollmentTicketsRepository(db)
        self.device_change_requests_repo = DeviceChangeRequestsRepository(db)
        self.email_adapter = SMTPAdapter()

    async def identify(self, member_id: str, email: str) -> None:
        """
        FR-AUTH-002/003/004: always completes without revealing outcome to
        the caller. The route layer returns the same generic message
        regardless of what happens inside this method.
        """
        member_id = _normalize_member_id(member_id)
        email_normalized = _normalize_email(email)

        member = await self.members_repo.find_by_member_id_and_email(
            member_id, email_normalized
        )

        if not member:
            await self.security_service.record_event(
                event_type="IDENTITY_MISMATCH",
                metadata={"reason": "no_matching_record"},
            )
            return

        status = member.get("status")
        purpose = _ELIGIBLE_STATUS_PURPOSE.get(status)

        if not purpose:
            await self.security_service.record_event(
                event_type="IDENTITY_MISMATCH",
                member_ref=member_id,
                metadata={"reason": f"status_not_eligible_{status}"},
            )
            return

        otp = await self.otp_service.issue_challenge(member_id, purpose)
        await self.email_adapter.send_otp_email(member["registered_email"], otp)

    async def verify_otp(self, member_id: str, submitted_otp: str) -> Dict[str, Any]:
        """
        Returns a dict describing the next step:
          {"next_step": "PASSKEY_REGISTRATION", "enrollment_ticket": "..."}
        or
          {"next_step": "PENDING_ADMIN_APPROVAL"}

        Raises OTPExpired / OTPMaxAttempts / OTPError on failure — these
        are already vague, non-enumerating error types from Phase 1.
        """
        member_id = _normalize_member_id(member_id)
        member = await self.members_repo.find_by_member_id(member_id)

        if not member:
            # Reuse OTPError's generic message — do not distinguish
            # "no such member" from "wrong code" to the caller.
            from app.core.errors import OTPError
            raise OTPError()

        status = member.get("status")
        purpose = _ELIGIBLE_STATUS_PURPOSE.get(status)

        if not purpose:
            from app.core.errors import OTPError
            raise OTPError()

        await self.otp_service.verify_challenge(member_id, purpose, submitted_otp)

        if purpose == PURPOSE_ENROLLMENT:
            from app.core.security import generate_opaque_token, hash_enrollment_ticket

            raw_ticket = generate_opaque_token()
            ticket_hash = hash_enrollment_ticket(raw_ticket)
            await self.enrollment_tickets_repo.create(
                member_id=member_id,
                purpose="PASSKEY_REGISTRATION",
                token_hash=ticket_hash,
            )
            return {
                "next_step": "PASSKEY_REGISTRATION",
                "enrollment_ticket": raw_ticket,
            }

        else:  # PURPOSE_DEVICE_CHANGE
            latest_request = await self.device_change_requests_repo.find_latest_for_member(
                member_id
            )

            if latest_request and latest_request.get("status") == "APPROVED":
                # Admin already approved a prior device-change request — this
                # OTP re-proves identity so the member can register their new
                # passkey. Issue the same kind of ticket first-time enrolment
                # uses; the request is closed out once registration succeeds
                # (see webauthn_service.finish_registration).
                from app.core.security import generate_opaque_token, hash_enrollment_ticket

                raw_ticket = generate_opaque_token()
                ticket_hash = hash_enrollment_ticket(raw_ticket)
                await self.enrollment_tickets_repo.create(
                    member_id=member_id,
                    purpose="PASSKEY_REGISTRATION",
                    token_hash=ticket_hash,
                )
                return {
                    "next_step": "PASSKEY_REGISTRATION",
                    "enrollment_ticket": raw_ticket,
                }

            existing_pending = await self.device_change_requests_repo.find_pending_for_member(
                member_id
            )
            if not existing_pending:
                await self.device_change_requests_repo.create_request(member_id)
                logger.info("Device-change request created for member_id=%s", member_id)

            return {"next_step": "PENDING_ADMIN_APPROVAL"}
