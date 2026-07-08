"""
HTTP-level integration tests for /api/auth/identify and /api/auth/otp/verify.
"""
import os
os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)
os.environ.setdefault("DEVICE_TOKEN_SECRET_KEY", "b" * 64)

import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.core.dependencies import get_db
from app.domain.otp_service import OTPService
from app.main import create_app


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    yield client["test_phase4_http"]


@pytest.fixture
async def client(mock_db):
    app = create_app()

    async def override_get_db():
        return mock_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _insert_member(db, member_id: str, email: str, status: str):
    await db.members.insert_one(
        {
            "member_id": member_id,
            "registered_email": email,
            "registered_email_normalized": email.lower(),
            "status": status,
            "role": "member",
            "profile": {"name": "HTTP Test Member"},
        }
    )


@pytest.mark.asyncio
async def test_identify_endpoint_returns_generic_message_for_unknown_member(client, mock_db):
    response = await client.post(
        "/api/auth/identify",
        json={"member_id": "GHOST01", "email": "ghost@example.com"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "verification code has been sent" in body["data"]["message"]


@pytest.mark.asyncio
async def test_identify_endpoint_returns_same_message_for_real_member(client, mock_db):
    await _insert_member(mock_db, "REALHTTP01", "realhttp@example.com", "PENDING_ENROLLMENT")

    response_real = await client.post(
        "/api/auth/identify",
        json={"member_id": "REALHTTP01", "email": "realhttp@example.com"},
    )
    response_fake = await client.post(
        "/api/auth/identify",
        json={"member_id": "FAKEHTTP01", "email": "fake@example.com"},
    )

    # AT-002: identical response shape/content regardless of match
    assert response_real.json()["data"]["message"] == response_fake.json()["data"]["message"]


@pytest.mark.asyncio
async def test_identify_endpoint_rejects_invalid_email_format(client, mock_db):
    response = await client.post(
        "/api/auth/identify",
        json={"member_id": "MEM01", "email": "not-an-email"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_otp_verify_endpoint_full_enrollment_flow(client, mock_db):
    await _insert_member(mock_db, "FLOW01", "flow@example.com", "PENDING_ENROLLMENT")

    await client.post(
        "/api/auth/identify",
        json={"member_id": "FLOW01", "email": "flow@example.com"},
    )

    challenge = await mock_db.otp_challenges.find_one({"member_id": "FLOW01"})
    assert challenge is not None

    # Recover the raw OTP the way a real test would need to (via the DB
    # hash isn't reversible) — so instead, directly issue via service and
    # verify via HTTP to prove the endpoint wiring works end-to-end.
    otp_service = OTPService(mock_db)
    # Clear the challenge created by the identify() call above and issue
    # a fresh one whose raw value we control, respecting purpose semantics.
    await mock_db.otp_challenges.delete_many({"member_id": "FLOW01"})
    otp = await otp_service.issue_challenge("FLOW01", "ENROLLMENT")

    response = await client.post(
        "/api/auth/otp/verify",
        json={"member_id": "FLOW01", "otp": otp},
    )
    assert response.status_code == 200
    body = response.json()["data"]
    assert body["next_step"] == "PASSKEY_REGISTRATION"
    assert "enrollment_ticket" in body


@pytest.mark.asyncio
async def test_otp_verify_endpoint_rejects_wrong_code(client, mock_db):
    await _insert_member(mock_db, "WRONG01", "wrong@example.com", "PENDING_ENROLLMENT")
    otp_service = OTPService(mock_db)
    await otp_service.issue_challenge("WRONG01", "ENROLLMENT")

    response = await client.post(
        "/api/auth/otp/verify",
        json={"member_id": "WRONG01", "otp": "000000"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "OTP_INVALID"


@pytest.mark.asyncio
async def test_otp_verify_endpoint_device_change_flow(client, mock_db):
    await _insert_member(mock_db, "DCHTTP01", "dchttp@example.com", "ACTIVE")
    otp_service = OTPService(mock_db)
    otp = await otp_service.issue_challenge("DCHTTP01", "DEVICE_CHANGE")

    response = await client.post(
        "/api/auth/otp/verify",
        json={"member_id": "DCHTTP01", "otp": otp},
    )
    assert response.status_code == 200
    body = response.json()["data"]
    assert body["next_step"] == "PENDING_ADMIN_APPROVAL"
    assert "enrollment_ticket" not in body
