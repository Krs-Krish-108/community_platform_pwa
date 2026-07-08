"""
Integration tests for app.domain.webauthn_service.

Two testing strategies, matching the Backend Blueprint's own test-layer
guidance (§12.1 "WebAuthn tests: wrong origin rejected, revoked device
denied, sign counter update handled"):

1. Option generation (generate_registration_options / generate_authentication
   _options) requires no authenticator hardware — these are tested for real,
   with no mocking, since they're pure server-side construction.

2. The cryptographic verification step (verify_registration_response /
   verify_authentication_response) requires a real authenticator or a
   browser's virtual authenticator (Chrome DevTools Protocol) to produce
   a genuinely valid signed attestation/assertion — unavailable in this
   sandboxed environment. We mock ONLY this boundary call, exactly as
   the Blueprint anticipates full E2E ceremony testing happens via
   Playwright + a virtual authenticator (Phase 8's PWA hardening/E2E
   suite), not backend unit tests. Everything around that boundary —
   ticket consumption, challenge single-use, device/credential creation,
   member activation, session issuance, sign-count updates, and status
   gating — is real orchestration logic under full test here.
"""
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.errors import AccountNotActive, AccountSuspended, DeviceNotApproved, WebAuthnError
from app.core.security import (
    generate_opaque_token,
    hash_device_token,
    hash_enrollment_ticket,
)
from app.domain.webauthn_service import WebAuthnService


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    yield client["test_webauthn"]


async def _insert_member(db, member_id, email, status="PENDING_ENROLLMENT", name="Test Member"):
    await db.members.insert_one(
        {
            "member_id": member_id,
            "registered_email": email,
            "registered_email_normalized": email.lower(),
            "status": status,
            "role": "member",
            "profile": {"name": name},
        }
    )


async def _issue_enrollment_ticket(db, member_id):
    raw_ticket = generate_opaque_token()
    ticket_hash = hash_enrollment_ticket(raw_ticket)
    await db.enrollment_tickets.insert_one(
        {
            "member_id": member_id,
            "purpose": "PASSKEY_REGISTRATION",
            "token_hash": ticket_hash,
            "created_at": __import__("app.core.security", fromlist=["utc_now"]).utc_now(),
            "expires_at": __import__("app.core.security", fromlist=["utc_now"]).utc_now()
            + __import__("datetime").timedelta(minutes=10),
            "consumed_at": None,
        }
    )
    return raw_ticket


def _fake_verified_registration(credential_id=b"fake-credential-id-001"):
    return SimpleNamespace(
        credential_id=credential_id,
        credential_public_key=b"fake-public-key-bytes",
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt="none",
        credential_type="public-key",
        user_verified=True,
        attestation_object=b"",
        credential_device_type="single_device",
        credential_backed_up=False,
    )


def _fake_verified_authentication(new_sign_count=1):
    return SimpleNamespace(
        credential_id=b"fake-credential-id-001",
        new_sign_count=new_sign_count,
        credential_device_type="single_device",
        credential_backed_up=False,
    )


# ── Registration: options (real, no mocking) ─────────────────────────────────

@pytest.mark.asyncio
async def test_begin_registration_with_valid_ticket_returns_options(mock_db):
    await _insert_member(mock_db, "REG001", "reg001@example.com")
    ticket = await _issue_enrollment_ticket(mock_db, "REG001")

    service = WebAuthnService(mock_db)
    options = await service.begin_registration(ticket)

    assert options.rp.id == service.settings.webauthn_rp_id
    assert options.user.name == "REG001"
    assert options.challenge is not None
    assert len(options.challenge) >= 16  # sufficient entropy


@pytest.mark.asyncio
async def test_begin_registration_stores_challenge(mock_db):
    await _insert_member(mock_db, "REG002", "reg002@example.com")
    ticket = await _issue_enrollment_ticket(mock_db, "REG002")

    service = WebAuthnService(mock_db)
    await service.begin_registration(ticket)

    challenge_doc = await mock_db.webauthn_challenges.find_one(
        {"subject_id": "REG002", "purpose": "REGISTRATION"}
    )
    assert challenge_doc is not None


@pytest.mark.asyncio
async def test_begin_registration_with_invalid_ticket_raises(mock_db):
    service = WebAuthnService(mock_db)
    with pytest.raises(WebAuthnError):
        await service.begin_registration("totally-fake-ticket-value")


@pytest.mark.asyncio
async def test_begin_registration_with_expired_ticket_raises(mock_db):
    import datetime
    from app.core.security import utc_now

    await _insert_member(mock_db, "REG003", "reg003@example.com")
    raw_ticket = generate_opaque_token()
    ticket_hash = hash_enrollment_ticket(raw_ticket)
    await mock_db.enrollment_tickets.insert_one(
        {
            "member_id": "REG003",
            "purpose": "PASSKEY_REGISTRATION",
            "token_hash": ticket_hash,
            "created_at": utc_now() - datetime.timedelta(minutes=20),
            "expires_at": utc_now() - datetime.timedelta(minutes=10),  # already expired
            "consumed_at": None,
        }
    )

    service = WebAuthnService(mock_db)
    with pytest.raises(WebAuthnError):
        await service.begin_registration(raw_ticket)


# ── Registration: verify (crypto boundary mocked) ────────────────────────────

@pytest.mark.asyncio
async def test_finish_registration_creates_device_credential_and_session(mock_db):
    await _insert_member(mock_db, "FIN001", "fin001@example.com")
    ticket = await _issue_enrollment_ticket(mock_db, "FIN001")

    service = WebAuthnService(mock_db)
    await service.begin_registration(ticket)

    with patch(
        "app.domain.webauthn_service.verify_registration_response",
        return_value=_fake_verified_registration(),
    ):
        result = await service.finish_registration(ticket, {"fake": "credential"})

    assert result["member_id"] == "FIN001"
    assert len(result["raw_session_token"]) > 20
    assert len(result["raw_device_token"]) > 20

    member = await mock_db.members.find_one({"member_id": "FIN001"})
    assert member["status"] == "ACTIVE"

    device = await mock_db.devices.find_one({"member_id": "FIN001"})
    assert device["status"] == "ACTIVE"

    credential = await mock_db.webauthn_credentials.find_one({"member_id": "FIN001"})
    assert credential is not None
    assert credential["sign_count"] == 0

    session = await mock_db.sessions.find_one({"member_id": "FIN001"})
    assert session is not None


@pytest.mark.asyncio
async def test_finish_registration_consumes_ticket_and_challenge(mock_db):
    await _insert_member(mock_db, "FIN002", "fin002@example.com")
    ticket = await _issue_enrollment_ticket(mock_db, "FIN002")

    service = WebAuthnService(mock_db)
    await service.begin_registration(ticket)

    with patch(
        "app.domain.webauthn_service.verify_registration_response",
        return_value=_fake_verified_registration(),
    ):
        await service.finish_registration(ticket, {"fake": "credential"})

    ticket_doc = await mock_db.enrollment_tickets.find_one({"member_id": "FIN002"})
    assert ticket_doc["consumed_at"] is not None

    challenge_doc = await mock_db.webauthn_challenges.find_one(
        {"subject_id": "FIN002", "purpose": "REGISTRATION"}
    )
    assert challenge_doc["consumed_at"] is not None


@pytest.mark.asyncio
async def test_finish_registration_rejects_reused_ticket(mock_db):
    """A ticket already consumed by a prior registration cannot be reused."""
    await _insert_member(mock_db, "FIN003", "fin003@example.com")
    ticket = await _issue_enrollment_ticket(mock_db, "FIN003")

    service = WebAuthnService(mock_db)
    await service.begin_registration(ticket)
    with patch(
        "app.domain.webauthn_service.verify_registration_response",
        return_value=_fake_verified_registration(),
    ):
        await service.finish_registration(ticket, {"fake": "credential"})

    # Second attempt with the same (now-consumed) ticket
    with pytest.raises(WebAuthnError):
        await service.finish_registration(ticket, {"fake": "credential"})


@pytest.mark.asyncio
async def test_finish_registration_does_not_consume_ticket_on_crypto_failure(mock_db):
    """If verification fails, the member should be able to retry with the same ticket."""
    await _insert_member(mock_db, "FIN004", "fin004@example.com")
    ticket = await _issue_enrollment_ticket(mock_db, "FIN004")

    service = WebAuthnService(mock_db)
    await service.begin_registration(ticket)

    with patch(
        "app.domain.webauthn_service.verify_registration_response",
        side_effect=Exception("bad signature"),
    ):
        with pytest.raises(WebAuthnError):
            await service.finish_registration(ticket, {"fake": "credential"})

    ticket_doc = await mock_db.enrollment_tickets.find_one({"member_id": "FIN004"})
    assert ticket_doc["consumed_at"] is None  # NOT consumed — retry is possible

    member = await mock_db.members.find_one({"member_id": "FIN004"})
    assert member["status"] == "PENDING_ENROLLMENT"  # not activated on failure


@pytest.mark.asyncio
async def test_finish_registration_after_device_change_approval_marks_request_completed(mock_db):
    """Post-device-change-approval registration closes out the approved request."""
    await _insert_member(mock_db, "DCFIN001", "dcfin001@example.com", status="ACTIVE")
    await mock_db.device_change_requests.insert_one(
        {
            "member_id": "DCFIN001",
            "status": "APPROVED",
            "requested_at": __import__("app.core.security", fromlist=["utc_now"]).utc_now(),
        }
    )
    ticket = await _issue_enrollment_ticket(mock_db, "DCFIN001")

    service = WebAuthnService(mock_db)
    await service.begin_registration(ticket)
    with patch(
        "app.domain.webauthn_service.verify_registration_response",
        return_value=_fake_verified_registration(),
    ):
        await service.finish_registration(ticket, {"fake": "credential"})

    request = await mock_db.device_change_requests.find_one({"member_id": "DCFIN001"})
    assert request["status"] == "COMPLETED"


# ── Login: options ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_begin_login_with_invalid_device_token_raises(mock_db):
    service = WebAuthnService(mock_db)
    with pytest.raises(DeviceNotApproved):
        await service.begin_login("not-a-real-device-token")


@pytest.mark.asyncio
async def test_begin_login_with_active_device_returns_options(mock_db):
    from app.repositories.devices_repo import DevicesRepository
    from app.repositories.credentials_repo import CredentialsRepository

    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_hash = hash_device_token(raw_device_token)
    device_id = await devices_repo.create_device(
        member_id="LOG001", device_cookie_hash=device_hash, credential_id="cred-log-001"
    )

    creds_repo = CredentialsRepository(mock_db)
    await creds_repo.create_credential(
        member_id="LOG001",
        device_id=device_id,
        credential_id="cred-log-001",
        public_key=b"fake-key",
        sign_count=0,
    )

    service = WebAuthnService(mock_db)
    options = await service.begin_login(raw_device_token)
    assert options.rp_id == service.settings.webauthn_rp_id
    assert len(options.allow_credentials) == 1


# ── Login: verify (crypto boundary mocked) ────────────────────────────────────

@pytest.mark.asyncio
async def test_finish_login_updates_sign_count_and_creates_session(mock_db):
    from app.repositories.devices_repo import DevicesRepository
    from app.repositories.credentials_repo import CredentialsRepository

    await _insert_member(mock_db, "LOG002", "log002@example.com", status="ACTIVE")

    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_hash = hash_device_token(raw_device_token)
    device_id = await devices_repo.create_device(
        member_id="LOG002", device_cookie_hash=device_hash, credential_id="cred-log-002"
    )

    creds_repo = CredentialsRepository(mock_db)
    await creds_repo.create_credential(
        member_id="LOG002", device_id=device_id, credential_id="cred-log-002",
        public_key=b"fake-key", sign_count=5,
    )

    service = WebAuthnService(mock_db)
    await service.begin_login(raw_device_token)

    with patch(
        "app.domain.webauthn_service.verify_authentication_response",
        return_value=_fake_verified_authentication(new_sign_count=6),
    ):
        result = await service.finish_login(raw_device_token, {"fake": "assertion"})

    assert result["member_id"] == "LOG002"
    assert len(result["raw_session_token"]) > 20

    credential = await mock_db.webauthn_credentials.find_one({"credential_id": "cred-log-002"})
    assert credential["sign_count"] == 6

    session = await mock_db.sessions.find_one({"member_id": "LOG002"})
    assert session is not None


@pytest.mark.asyncio
async def test_finish_login_blocks_suspended_member_despite_valid_passkey(mock_db):
    """FR-AUTH/SEC-003: a suspended member cannot log in even with a correct passkey."""
    from app.repositories.devices_repo import DevicesRepository
    from app.repositories.credentials_repo import CredentialsRepository

    await _insert_member(mock_db, "SUSPLOG01", "susplog@example.com", status="SUSPENDED")

    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_hash = hash_device_token(raw_device_token)
    device_id = await devices_repo.create_device(
        member_id="SUSPLOG01", device_cookie_hash=device_hash, credential_id="cred-susp-01"
    )
    creds_repo = CredentialsRepository(mock_db)
    await creds_repo.create_credential(
        member_id="SUSPLOG01", device_id=device_id, credential_id="cred-susp-01",
        public_key=b"fake-key", sign_count=0,
    )

    service = WebAuthnService(mock_db)
    await service.begin_login(raw_device_token)

    with patch(
        "app.domain.webauthn_service.verify_authentication_response",
        return_value=_fake_verified_authentication(),
    ):
        with pytest.raises(AccountSuspended):
            await service.finish_login(raw_device_token, {"fake": "assertion"})

    session = await mock_db.sessions.find_one({"member_id": "SUSPLOG01"})
    assert session is None  # no session issued despite valid signature


@pytest.mark.asyncio
async def test_finish_login_with_revoked_device_raises(mock_db):
    from app.repositories.devices_repo import DevicesRepository

    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_hash = hash_device_token(raw_device_token)
    device_id = await devices_repo.create_device(
        member_id="REVLOG01", device_cookie_hash=device_hash, credential_id="cred-rev-01"
    )
    await devices_repo.revoke_device(devices_repo.to_object_id(device_id))

    service = WebAuthnService(mock_db)
    with pytest.raises(DeviceNotApproved):
        await service.finish_login(raw_device_token, {"fake": "assertion"})


@pytest.mark.asyncio
async def test_finish_login_does_not_create_session_on_crypto_failure(mock_db):
    from app.repositories.devices_repo import DevicesRepository
    from app.repositories.credentials_repo import CredentialsRepository

    await _insert_member(mock_db, "BADLOG01", "badlog@example.com", status="ACTIVE")
    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_hash = hash_device_token(raw_device_token)
    device_id = await devices_repo.create_device(
        member_id="BADLOG01", device_cookie_hash=device_hash, credential_id="cred-bad-01"
    )
    creds_repo = CredentialsRepository(mock_db)
    await creds_repo.create_credential(
        member_id="BADLOG01", device_id=device_id, credential_id="cred-bad-01",
        public_key=b"fake-key", sign_count=0,
    )

    service = WebAuthnService(mock_db)
    await service.begin_login(raw_device_token)

    with patch(
        "app.domain.webauthn_service.verify_authentication_response",
        side_effect=Exception("signature mismatch"),
    ):
        with pytest.raises(WebAuthnError):
            await service.finish_login(raw_device_token, {"fake": "assertion"})

    session = await mock_db.sessions.find_one({"member_id": "BADLOG01"})
    assert session is None
