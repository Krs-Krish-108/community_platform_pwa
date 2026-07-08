"""
HTTP-level integration tests for /api/webauthn/*, /api/devices/*, and the
Phase 5 additions to /api/auth/* (me, logout).
"""
import os
os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)
os.environ.setdefault("DEVICE_TOKEN_SECRET_KEY", "b" * 64)

from unittest.mock import patch
from types import SimpleNamespace

import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.core.dependencies import get_db
from app.core.security import (
    generate_opaque_token,
    hash_device_token,
    hash_enrollment_ticket,
    hash_session_token,
    utc_now,
)
from app.main import create_app
from app.repositories.credentials_repo import CredentialsRepository
from app.repositories.devices_repo import DevicesRepository


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    yield client["test_phase5_http"]


@pytest.fixture
async def client(mock_db):
    app = create_app()

    async def override_get_db():
        return mock_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _fake_verified_registration():
    return SimpleNamespace(
        credential_id=b"http-fake-cred-001",
        credential_public_key=b"http-fake-pubkey",
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
        credential_id=b"http-fake-cred-001",
        new_sign_count=new_sign_count,
        credential_device_type="single_device",
        credential_backed_up=False,
    )


async def _insert_member(db, member_id, email, status="PENDING_ENROLLMENT"):
    await db.members.insert_one(
        {
            "member_id": member_id,
            "registered_email": email,
            "registered_email_normalized": email.lower(),
            "status": status,
            "role": "member",
            "profile": {"name": "HTTP WebAuthn Test"},
        }
    )


async def _issue_ticket(db, member_id):
    raw = generate_opaque_token()
    await db.enrollment_tickets.insert_one(
        {
            "member_id": member_id,
            "purpose": "PASSKEY_REGISTRATION",
            "token_hash": hash_enrollment_ticket(raw),
            "created_at": utc_now(),
            "expires_at": utc_now() + __import__("datetime").timedelta(minutes=10),
            "consumed_at": None,
        }
    )
    return raw


# ── Registration over HTTP ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_options_endpoint_returns_webauthn_options(client, mock_db):
    await _insert_member(mock_db, "HREG01", "hreg01@example.com")
    ticket = await _issue_ticket(mock_db, "HREG01")

    response = await client.post(
        "/api/webauthn/register/options", json={"enrollment_ticket": ticket}
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["rp"]["id"] is not None
    assert data["user"]["name"] == "HREG01"
    assert "challenge" in data


@pytest.mark.asyncio
async def test_register_options_endpoint_rejects_invalid_ticket(client, mock_db):
    response = await client.post(
        "/api/webauthn/register/options", json={"enrollment_ticket": "fake-ticket-value"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "WEBAUTHN_ERROR"


@pytest.mark.asyncio
async def test_register_verify_endpoint_sets_cookies_and_activates_member(client, mock_db):
    await _insert_member(mock_db, "HREG02", "hreg02@example.com")
    ticket = await _issue_ticket(mock_db, "HREG02")

    await client.post("/api/webauthn/register/options", json={"enrollment_ticket": ticket})

    with patch(
        "app.domain.webauthn_service.verify_registration_response",
        return_value=_fake_verified_registration(),
    ):
        response = await client.post(
            "/api/webauthn/register/verify",
            json={"enrollment_ticket": ticket, "credential": {"fake": "cred"}},
        )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["member_id"] == "HREG02"
    assert body["status"] == "ACTIVE"

    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any("__Host-cd_session" in h for h in set_cookie_headers)
    assert any("__Host-cd_device" in h for h in set_cookie_headers)

    member = await mock_db.members.find_one({"member_id": "HREG02"})
    assert member["status"] == "ACTIVE"


# ── Login over HTTP ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_options_endpoint_requires_device_cookie(client, mock_db):
    response = await client.post("/api/webauthn/login/options")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "DEVICE_NOT_APPROVED"


@pytest.mark.asyncio
async def test_login_options_endpoint_with_valid_device_cookie(client, mock_db):
    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_id = await devices_repo.create_device(
        member_id="HLOG01",
        device_cookie_hash=hash_device_token(raw_device_token),
        credential_id="http-log-cred-01",
    )
    creds_repo = CredentialsRepository(mock_db)
    await creds_repo.create_credential(
        member_id="HLOG01", device_id=device_id, credential_id="http-log-cred-01",
        public_key=b"fake-key", sign_count=0,
    )

    client.cookies.set("__Host-cd_device", raw_device_token)
    response = await client.post("/api/webauthn/login/options")
    assert response.status_code == 200
    assert "challenge" in response.json()["data"]


@pytest.mark.asyncio
async def test_login_verify_endpoint_issues_session_cookie(client, mock_db):
    await _insert_member(mock_db, "HLOG02", "hlog02@example.com", status="ACTIVE")
    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_id = await devices_repo.create_device(
        member_id="HLOG02",
        device_cookie_hash=hash_device_token(raw_device_token),
        credential_id="http-log-cred-02",
    )
    creds_repo = CredentialsRepository(mock_db)
    await creds_repo.create_credential(
        member_id="HLOG02", device_id=device_id, credential_id="http-log-cred-02",
        public_key=b"fake-key", sign_count=0,
    )

    client.cookies.set("__Host-cd_device", raw_device_token)
    await client.post("/api/webauthn/login/options")

    with patch(
        "app.domain.webauthn_service.verify_authentication_response",
        return_value=_fake_verified_authentication(),
    ):
        response = await client.post(
            "/api/webauthn/login/verify", json={"credential": {"fake": "assertion"}}
        )

    assert response.status_code == 200
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert any("__Host-cd_session" in h for h in set_cookie_headers)


# ── /api/auth/me and /api/auth/logout ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_auth_me_without_session_returns_401(client, mock_db):
    response = await client.get("/api/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_me_with_valid_session_returns_identity(client, mock_db):
    await _insert_member(mock_db, "HME01", "hme01@example.com", status="ACTIVE")
    raw_session = generate_opaque_token()
    await mock_db.sessions.insert_one(
        {
            "session_token_hash": hash_session_token(raw_session),
            "member_id": "HME01",
            "device_id": None,
            "created_at": utc_now(),
            "expires_at": utc_now() + __import__("datetime").timedelta(hours=1),
            "revoked_at": None,
        }
    )
    client.cookies.set("__Host-cd_session", raw_session)
    response = await client.get("/api/auth/me")
    assert response.status_code == 200
    body = response.json()["data"]
    assert body["member_id"] == "HME01"
    assert body["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_auth_logout_revokes_session(client, mock_db):
    await _insert_member(mock_db, "HLOGOUT01", "hlogout01@example.com", status="ACTIVE")
    raw_session = generate_opaque_token()
    await mock_db.sessions.insert_one(
        {
            "session_token_hash": hash_session_token(raw_session),
            "member_id": "HLOGOUT01",
            "device_id": None,
            "created_at": utc_now(),
            "expires_at": utc_now() + __import__("datetime").timedelta(hours=1),
            "revoked_at": None,
        }
    )
    client.cookies.set("__Host-cd_session", raw_session)
    response = await client.post("/api/auth/logout")
    assert response.status_code == 200

    session = await mock_db.sessions.find_one(
        {"session_token_hash": hash_session_token(raw_session)}
    )
    assert session["revoked_at"] is not None


# ── /api/devices/* ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_devices_current_requires_full_auth_gate(client, mock_db):
    response = await client.get("/api/devices/current")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_devices_current_returns_device_info(client, mock_db):
    await _insert_member(mock_db, "HDEV01", "hdev01@example.com", status="ACTIVE")
    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_id = await devices_repo.create_device(
        member_id="HDEV01",
        device_cookie_hash=hash_device_token(raw_device_token),
        credential_id="dev-cred-01",
    )
    raw_session = generate_opaque_token()
    await mock_db.sessions.insert_one(
        {
            "session_token_hash": hash_session_token(raw_session),
            "member_id": "HDEV01",
            "device_id": device_id,
            "created_at": utc_now(),
            "expires_at": utc_now() + __import__("datetime").timedelta(hours=1),
            "revoked_at": None,
        }
    )

    client.cookies.set("__Host-cd_session", raw_session)
    client.cookies.set("__Host-cd_device", raw_device_token)
    response = await client.get("/api/devices/current")
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_devices_delete_current_clears_cookies_and_revokes(client, mock_db):
    await _insert_member(mock_db, "HDEV02", "hdev02@example.com", status="ACTIVE")
    devices_repo = DevicesRepository(mock_db)
    raw_device_token = generate_opaque_token()
    device_id = await devices_repo.create_device(
        member_id="HDEV02",
        device_cookie_hash=hash_device_token(raw_device_token),
        credential_id="dev-cred-02",
    )
    raw_session = generate_opaque_token()
    await mock_db.sessions.insert_one(
        {
            "session_token_hash": hash_session_token(raw_session),
            "member_id": "HDEV02",
            "device_id": device_id,
            "created_at": utc_now(),
            "expires_at": utc_now() + __import__("datetime").timedelta(hours=1),
            "revoked_at": None,
        }
    )

    client.cookies.set("__Host-cd_session", raw_session)
    client.cookies.set("__Host-cd_device", raw_device_token)
    response = await client.delete("/api/devices/current")
    assert response.status_code == 200

    device = await mock_db.devices.find_one({"member_id": "HDEV02"})
    assert device["status"] == "REVOKED"

    session = await mock_db.sessions.find_one({"member_id": "HDEV02"})
    assert session["revoked_at"] is not None
