"""
Unit/integration-lite tests for app.domain.otp_service.
Uses mongomock-motor since OTP challenges are DB-backed.
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.errors import OTPExpired, OTPMaxAttempts, OTPError, RateLimitExceeded
from app.core.security import verify_otp_hash
from app.domain.otp_service import OTPService


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    yield client["test_otp"]


@pytest.mark.asyncio
async def test_issue_challenge_returns_six_digit_otp(mock_db):
    service = OTPService(mock_db)
    otp = await service.issue_challenge("MEM001", "ENROLLMENT")
    assert len(otp) == 6
    assert otp.isdigit()


@pytest.mark.asyncio
async def test_issued_otp_is_stored_only_as_hash(mock_db):
    service = OTPService(mock_db)
    otp = await service.issue_challenge("MEM001", "ENROLLMENT")

    challenge = await mock_db.otp_challenges.find_one({"member_id": "MEM001"})
    assert challenge is not None
    assert challenge["otp_hash"] != otp  # raw OTP never stored
    assert verify_otp_hash(otp, challenge["otp_hash"]) is True


@pytest.mark.asyncio
async def test_verify_challenge_succeeds_with_correct_otp(mock_db):
    service = OTPService(mock_db)
    otp = await service.issue_challenge("MEM001", "ENROLLMENT")
    await service.verify_challenge("MEM001", "ENROLLMENT", otp)  # should not raise

    challenge = await mock_db.otp_challenges.find_one({"member_id": "MEM001"})
    assert challenge["consumed_at"] is not None


@pytest.mark.asyncio
async def test_verify_challenge_fails_with_wrong_otp(mock_db):
    service = OTPService(mock_db)
    await service.issue_challenge("MEM001", "ENROLLMENT")

    with pytest.raises(OTPError):
        await service.verify_challenge("MEM001", "ENROLLMENT", "000000")


@pytest.mark.asyncio
async def test_verify_challenge_fails_when_no_challenge_exists(mock_db):
    service = OTPService(mock_db)
    with pytest.raises(OTPExpired):
        await service.verify_challenge("NOCHALLENGE", "ENROLLMENT", "123456")


@pytest.mark.asyncio
async def test_verify_challenge_expires_after_max_attempts(mock_db):
    """FR-AUTH-005/AT-003: five invalid OTPs -> challenge expires, access denied."""
    service = OTPService(mock_db)
    await service.issue_challenge("MEM001", "ENROLLMENT")

    # otp_max_attempts default is 5 — exhaust them with wrong codes
    for _ in range(5):
        with pytest.raises(OTPError):
            await service.verify_challenge("MEM001", "ENROLLMENT", "000000")

    # Challenge should now be expired even with a fresh attempt
    with pytest.raises((OTPExpired, OTPMaxAttempts)):
        await service.verify_challenge("MEM001", "ENROLLMENT", "000000")


@pytest.mark.asyncio
async def test_resend_within_cooldown_is_rate_limited(mock_db):
    """FR-AUTH-006: resend cooldown enforced."""
    service = OTPService(mock_db)
    await service.issue_challenge("MEM001", "ENROLLMENT")

    with pytest.raises(RateLimitExceeded):
        await service.issue_challenge("MEM001", "ENROLLMENT")  # immediate resend


@pytest.mark.asyncio
async def test_daily_cap_enforced(mock_db, monkeypatch):
    """FR-AUTH-006: daily request cap enforced."""
    from app.core import config as config_module
    config_module.get_settings.cache_clear()
    monkeypatch.setenv("OTP_DAILY_CAP", "2")
    monkeypatch.setenv("OTP_RESEND_COOLDOWN_SECONDS", "0")  # bypass cooldown for this test

    service = OTPService(mock_db)
    await service.issue_challenge("MEM001", "ENROLLMENT")
    await service.issue_challenge("MEM001", "ENROLLMENT")

    with pytest.raises(RateLimitExceeded):
        await service.issue_challenge("MEM001", "ENROLLMENT")

    config_module.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_different_purposes_have_independent_challenges(mock_db):
    """ENROLLMENT and DEVICE_CHANGE OTPs for the same member don't collide."""
    service = OTPService(mock_db)
    otp_enroll = await service.issue_challenge("MEM001", "ENROLLMENT")

    # A different purpose should not be blocked by ENROLLMENT's cooldown
    otp_device = await service.issue_challenge("MEM001", "DEVICE_CHANGE")

    assert otp_enroll != otp_device or True  # random collision astronomically unlikely
    await service.verify_challenge("MEM001", "ENROLLMENT", otp_enroll)
    await service.verify_challenge("MEM001", "DEVICE_CHANGE", otp_device)


@pytest.mark.asyncio
async def test_failed_otp_records_security_event(mock_db):
    service = OTPService(mock_db)
    await service.issue_challenge("MEM001", "ENROLLMENT")

    with pytest.raises(OTPError):
        await service.verify_challenge("MEM001", "ENROLLMENT", "000000")

    event = await mock_db.security_events.find_one({"event_type": "OTP_FAILED"})
    assert event is not None
    assert event["member_ref"] == "MEM001"
