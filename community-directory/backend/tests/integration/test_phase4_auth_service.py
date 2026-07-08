"""
Integration tests for app.domain.auth_service — the full identify + OTP
verification orchestration, including the ENROLLMENT vs DEVICE_CHANGE
purpose split and the non-negotiable rule that OTP alone never creates
a session or activates a device.
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.errors import OTPError
from app.domain.auth_service import AuthService
from app.domain.otp_service import OTPService


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    yield client["test_auth_service"]


async def _insert_member(db, member_id: str, email: str, status: str):
    await db.members.insert_one(
        {
            "member_id": member_id,
            "registered_email": email,
            "registered_email_normalized": email.lower(),
            "status": status,
            "role": "member",
            "profile": {"name": "Test Member"},
        }
    )


# ── Identify: generic behavior ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identify_with_no_matching_record_completes_silently(mock_db):
    """FR-AUTH-003: no exception, no OTP sent, but a security event recorded."""
    service = AuthService(mock_db)
    await service.identify("NOSUCH01", "nobody@example.com")  # must not raise

    event = await mock_db.security_events.find_one({"event_type": "IDENTITY_MISMATCH"})
    assert event is not None

    otp_challenge = await mock_db.otp_challenges.find_one({})
    assert otp_challenge is None  # no OTP was issued


@pytest.mark.asyncio
async def test_identify_for_staged_member_does_not_send_otp(mock_db):
    await _insert_member(mock_db, "STAGE01", "staged@example.com", "STAGED")
    service = AuthService(mock_db)
    await service.identify("STAGE01", "staged@example.com")

    otp_challenge = await mock_db.otp_challenges.find_one({"member_id": "STAGE01"})
    assert otp_challenge is None
    event = await mock_db.security_events.find_one({"member_ref": "STAGE01"})
    assert event is not None
    assert "not_eligible" in event["metadata"]["reason"]


@pytest.mark.asyncio
async def test_identify_for_suspended_member_does_not_send_otp(mock_db):
    await _insert_member(mock_db, "SUSP01", "susp@example.com", "SUSPENDED")
    service = AuthService(mock_db)
    await service.identify("SUSP01", "susp@example.com")

    otp_challenge = await mock_db.otp_challenges.find_one({"member_id": "SUSP01"})
    assert otp_challenge is None


@pytest.mark.asyncio
async def test_identify_for_pending_enrollment_member_sends_otp(mock_db):
    await _insert_member(mock_db, "PEND01", "pend@example.com", "PENDING_ENROLLMENT")
    service = AuthService(mock_db)
    await service.identify("PEND01", "pend@example.com")

    otp_challenge = await mock_db.otp_challenges.find_one(
        {"member_id": "PEND01", "purpose": "ENROLLMENT"}
    )
    assert otp_challenge is not None


@pytest.mark.asyncio
async def test_identify_for_active_member_sends_device_change_otp(mock_db):
    await _insert_member(mock_db, "ACT01", "act@example.com", "ACTIVE")
    service = AuthService(mock_db)
    await service.identify("ACT01", "act@example.com")

    otp_challenge = await mock_db.otp_challenges.find_one(
        {"member_id": "ACT01", "purpose": "DEVICE_CHANGE"}
    )
    assert otp_challenge is not None


@pytest.mark.asyncio
async def test_identify_email_mismatch_for_real_member_does_not_send_otp(mock_db):
    """A correct Member ID with a WRONG email must not leak an OTP."""
    await _insert_member(mock_db, "REAL01", "real@example.com", "PENDING_ENROLLMENT")
    service = AuthService(mock_db)
    await service.identify("REAL01", "wrong-email@example.com")

    otp_challenge = await mock_db.otp_challenges.find_one({"member_id": "REAL01"})
    assert otp_challenge is None


# ── Verify: enrollment path ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_otp_for_pending_enrollment_issues_enrollment_ticket(mock_db):
    await _insert_member(mock_db, "ENR01", "enr@example.com", "PENDING_ENROLLMENT")

    otp_service = OTPService(mock_db)
    otp = await otp_service.issue_challenge("ENR01", "ENROLLMENT")

    auth_service = AuthService(mock_db)
    result = await auth_service.verify_otp("ENR01", otp)

    assert result["next_step"] == "PASSKEY_REGISTRATION"
    assert "enrollment_ticket" in result
    assert len(result["enrollment_ticket"]) > 20


@pytest.mark.asyncio
async def test_successful_enrollment_otp_does_not_activate_member_or_create_session(mock_db):
    """
    Non-negotiable rule: OTP alone never grants access. Member status must
    remain PENDING_ENROLLMENT and no session may be created.
    """
    await _insert_member(mock_db, "NOACT01", "noact@example.com", "PENDING_ENROLLMENT")
    otp_service = OTPService(mock_db)
    otp = await otp_service.issue_challenge("NOACT01", "ENROLLMENT")

    auth_service = AuthService(mock_db)
    await auth_service.verify_otp("NOACT01", otp)

    member = await mock_db.members.find_one({"member_id": "NOACT01"})
    assert member["status"] == "PENDING_ENROLLMENT"  # unchanged

    session = await mock_db.sessions.find_one({"member_id": "NOACT01"})
    assert session is None  # no session was created


@pytest.mark.asyncio
async def test_enrollment_ticket_is_stored_only_as_hash(mock_db):
    await _insert_member(mock_db, "HASHCHK01", "hashchk@example.com", "PENDING_ENROLLMENT")
    otp_service = OTPService(mock_db)
    otp = await otp_service.issue_challenge("HASHCHK01", "ENROLLMENT")

    auth_service = AuthService(mock_db)
    result = await auth_service.verify_otp("HASHCHK01", otp)
    raw_ticket = result["enrollment_ticket"]

    ticket_doc = await mock_db.enrollment_tickets.find_one({"member_id": "HASHCHK01"})
    assert ticket_doc is not None
    assert ticket_doc["token_hash"] != raw_ticket  # raw value never stored


# ── Verify: device change path ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_otp_for_active_member_creates_device_change_request(mock_db):
    await _insert_member(mock_db, "DEVCHG01", "devchg@example.com", "ACTIVE")
    otp_service = OTPService(mock_db)
    otp = await otp_service.issue_challenge("DEVCHG01", "DEVICE_CHANGE")

    auth_service = AuthService(mock_db)
    result = await auth_service.verify_otp("DEVCHG01", otp)

    assert result["next_step"] == "PENDING_ADMIN_APPROVAL"
    assert "enrollment_ticket" not in result

    request = await mock_db.device_change_requests.find_one(
        {"member_id": "DEVCHG01", "status": "PENDING"}
    )
    assert request is not None


@pytest.mark.asyncio
async def test_device_change_request_is_not_duplicated_on_repeat_verification(mock_db):
    """AT-004 style: repeated device-change OTP verification doesn't spam requests."""
    await _insert_member(mock_db, "NODUP01", "nodup@example.com", "ACTIVE")
    otp_service = OTPService(mock_db)
    auth_service = AuthService(mock_db)

    otp1 = await otp_service.issue_challenge("NODUP01", "DEVICE_CHANGE")
    await auth_service.verify_otp("NODUP01", otp1)

    # Manually bypass cooldown to simulate a second legitimate attempt later
    await mock_db.otp_challenges.delete_many({"member_id": "NODUP01"})
    otp2 = await otp_service.issue_challenge("NODUP01", "DEVICE_CHANGE")
    await auth_service.verify_otp("NODUP01", otp2)

    count = await mock_db.device_change_requests.count_documents({"member_id": "NODUP01"})
    assert count == 1  # still only one PENDING request


@pytest.mark.asyncio
async def test_device_change_does_not_grant_directory_access(mock_db):
    """FR-DEV-007: OTP + pending device-change request must not activate access."""
    await _insert_member(mock_db, "NOGRANT01", "nograant@example.com", "ACTIVE")
    otp_service = OTPService(mock_db)
    otp = await otp_service.issue_challenge("NOGRANT01", "DEVICE_CHANGE")

    auth_service = AuthService(mock_db)
    await auth_service.verify_otp("NOGRANT01", otp)

    # No new session, no new device record — member's existing device state untouched
    session = await mock_db.sessions.find_one({"member_id": "NOGRANT01"})
    assert session is None


# ── Verify: failure cases ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_otp_for_nonexistent_member_raises_generic_error(mock_db):
    auth_service = AuthService(mock_db)
    with pytest.raises(OTPError):
        await auth_service.verify_otp("GHOST01", "123456")


@pytest.mark.asyncio
async def test_verify_otp_for_staged_member_raises_generic_error(mock_db):
    await _insert_member(mock_db, "STAGEV01", "stagev@example.com", "STAGED")
    auth_service = AuthService(mock_db)
    with pytest.raises(OTPError):
        await auth_service.verify_otp("STAGEV01", "123456")
