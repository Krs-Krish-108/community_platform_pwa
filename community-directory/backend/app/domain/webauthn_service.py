"""
WebAuthn service — passkey registration and login ceremonies.

Registration (consumes an enrollment ticket from Phase 4):
    begin_registration()  -> options for navigator.credentials.create()
    finish_registration() -> verifies attestation, creates device + credential,
                              activates member, issues first session

Login (device cookie already present, session expired/absent):
    begin_login()  -> options for navigator.credentials.get()
    finish_login() -> verifies assertion, updates signature counter,
                       issues a fresh session

Non-negotiable rules enforced here:
  - A device is never marked ACTIVE without a verified attestation.
  - Session issuance always follows verified registration/login — never
    OTP alone, never a client-supplied claim.
  - Challenges are single-use and expire after 5 minutes.
"""
from typing import Any, Dict, Union

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from app.core.config import get_settings
from app.core.errors import DeviceNotApproved, WebAuthnError, AccountNotActive, AccountSuspended
from app.core.logging import get_logger
from app.core.security import (
    generate_opaque_token,
    hash_device_token,
    hash_enrollment_ticket,
    hash_session_token,
)
from app.domain.audit_service import AuditService
from app.repositories.credentials_repo import CredentialsRepository
from app.repositories.device_change_requests_repo import DeviceChangeRequestsRepository
from app.repositories.devices_repo import DevicesRepository
from app.repositories.enrollment_tickets_repo import EnrollmentTicketsRepository
from app.repositories.members_repo import MembersRepository
from app.repositories.sessions_repo import SessionsRepository
from app.repositories.webauthn_challenges_repo import WebAuthnChallengesRepository

logger = get_logger(__name__)


class WebAuthnService:
    def __init__(self, db):
        self.db = db
        self.settings = get_settings()
        self.members_repo = MembersRepository(db)
        self.devices_repo = DevicesRepository(db)
        self.credentials_repo = CredentialsRepository(db)
        self.sessions_repo = SessionsRepository(db)
        self.enrollment_tickets_repo = EnrollmentTicketsRepository(db)
        self.device_change_requests_repo = DeviceChangeRequestsRepository(db)
        self.challenges_repo = WebAuthnChallengesRepository(db)
        self.audit = AuditService(db)

    # ── Registration ──────────────────────────────────────────────────────

    async def begin_registration(self, raw_enrollment_ticket: str) -> Dict[str, Any]:
        ticket_hash = hash_enrollment_ticket(raw_enrollment_ticket)
        ticket = await self.enrollment_tickets_repo.find_valid(ticket_hash)
        if not ticket:
            raise WebAuthnError(
                "Your enrollment session has expired. Please verify your email again."
            )

        member_id = ticket["member_id"]
        member = await self.members_repo.find_by_member_id(member_id)
        if not member:
            raise WebAuthnError()

        display_name = member.get("profile", {}).get("name") or member_id

        options = generate_registration_options(
            rp_id=self.settings.webauthn_rp_id,
            rp_name=self.settings.webauthn_rp_name,
            user_name=member_id,
            user_id=member_id.encode("utf-8"),
            user_display_name=display_name,
        )

        await self.challenges_repo.create(
            subject_type="member",
            subject_id=member_id,
            purpose="REGISTRATION",
            challenge_b64=bytes_to_base64url(options.challenge),
        )

        return options

    async def finish_registration(
        self, raw_enrollment_ticket: str, credential: Union[str, dict]
    ) -> Dict[str, Any]:
        ticket_hash = hash_enrollment_ticket(raw_enrollment_ticket)
        ticket = await self.enrollment_tickets_repo.find_valid(ticket_hash)
        if not ticket:
            raise WebAuthnError(
                "Your enrollment session has expired. Please verify your email again."
            )

        member_id = ticket["member_id"]

        challenge_doc = await self.challenges_repo.find_valid(
            subject_type="member", subject_id=member_id, purpose="REGISTRATION"
        )
        if not challenge_doc:
            raise WebAuthnError(
                "Your passkey registration session has expired. Please try again."
            )

        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge_doc["challenge"]),
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=self.settings.webauthn_origins_list,
            )
        except Exception as exc:
            logger.warning("WebAuthn registration verification failed: %s", exc)
            raise WebAuthnError("Passkey registration could not be verified.") from exc

        await self.challenges_repo.consume(challenge_doc["_id"])
        await self.enrollment_tickets_repo.consume(ticket["_id"])

        credential_id_b64 = bytes_to_base64url(verified.credential_id)

        raw_device_token = generate_opaque_token()
        device_token_hash = hash_device_token(raw_device_token)
        device_id = await self.devices_repo.create_device(
            member_id=member_id,
            device_cookie_hash=device_token_hash,
            credential_id=credential_id_b64,
            status="ACTIVE",
        )

        await self.credentials_repo.create_credential(
            member_id=member_id,
            device_id=device_id,
            credential_id=credential_id_b64,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
        )

        await self.members_repo.activate_member(member_id)

        # If this registration follows an approved device-change request,
        # close that request out now that the new passkey is live.
        latest_request = await self.device_change_requests_repo.find_latest_for_member(
            member_id
        )
        if latest_request and latest_request.get("status") == "APPROVED":
            await self.device_change_requests_repo.mark_completed(latest_request["_id"])

        raw_session_token = generate_opaque_token()
        session_token_hash = hash_session_token(raw_session_token)
        await self.sessions_repo.create_session(
            member_id=member_id,
            session_token_hash=session_token_hash,
            device_id=device_id,
        )

        await self.audit.log(
            actor=member_id,
            action="PASSKEY_REGISTERED",
            target=member_id,
            after={"device_id": device_id},
        )

        logger.info("Passkey registered and device activated for member_id=%s", member_id)

        return {
            "member_id": member_id,
            "raw_session_token": raw_session_token,
            "raw_device_token": raw_device_token,
        }

    # ── Login ─────────────────────────────────────────────────────────────

    async def begin_login(self, raw_device_token: str) -> Dict[str, Any]:
        device_hash = hash_device_token(raw_device_token)
        device = await self.devices_repo.find_active_device_by_hash(device_hash)
        if not device:
            raise DeviceNotApproved()

        device_id = str(device["_id"])
        cred_doc = await self.credentials_repo.find_by_device_id(device_id)
        if not cred_doc:
            raise WebAuthnError("No passkey is registered for this device.")

        options = generate_authentication_options(
            rp_id=self.settings.webauthn_rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred_doc["credential_id"])
                )
            ],
        )

        await self.challenges_repo.create(
            subject_type="device",
            subject_id=device_id,
            purpose="LOGIN",
            challenge_b64=bytes_to_base64url(options.challenge),
        )

        return options

    async def finish_login(
        self, raw_device_token: str, credential: Union[str, dict]
    ) -> Dict[str, Any]:
        device_hash = hash_device_token(raw_device_token)
        device = await self.devices_repo.find_active_device_by_hash(device_hash)
        if not device:
            raise DeviceNotApproved()

        device_id = str(device["_id"])

        challenge_doc = await self.challenges_repo.find_valid(
            subject_type="device", subject_id=device_id, purpose="LOGIN"
        )
        if not challenge_doc:
            raise WebAuthnError("Your login session has expired. Please try again.")

        cred_doc = await self.credentials_repo.find_by_device_id(device_id)
        if not cred_doc:
            raise WebAuthnError("No passkey is registered for this device.")

        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge_doc["challenge"]),
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=self.settings.webauthn_origins_list,
                credential_public_key=cred_doc["public_key"],
                credential_current_sign_count=cred_doc["sign_count"],
            )
        except Exception as exc:
            logger.warning("WebAuthn login verification failed: %s", exc)
            raise WebAuthnError("Passkey verification failed.") from exc

        await self.challenges_repo.consume(challenge_doc["_id"])
        await self.credentials_repo.update_sign_count(
            cred_doc["credential_id"], verified.new_sign_count
        )

        member_id = device["member_id"]
        member = await self.members_repo.find_by_member_id(member_id)
        if not member:
            raise DeviceNotApproved()

        status = member.get("status")
        if status == "SUSPENDED":
            raise AccountSuspended()
        if status != "ACTIVE":
            raise AccountNotActive()

        raw_session_token = generate_opaque_token()
        session_token_hash = hash_session_token(raw_session_token)
        await self.sessions_repo.create_session(
            member_id=member_id,
            session_token_hash=session_token_hash,
            device_id=device_id,
        )

        logger.info("Passkey login successful for member_id=%s", member_id)

        return {"member_id": member_id, "raw_session_token": raw_session_token}
