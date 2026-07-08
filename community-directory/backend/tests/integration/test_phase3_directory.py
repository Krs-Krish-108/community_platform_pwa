"""
Integration tests for Phase 3: Protected Directory.

Exercises the full HTTP stack (routes -> dependencies -> services -> repos)
against an in-memory MongoDB mock, with get_db overridden so no live
MongoDB connection or lifespan startup is required.

These tests simulate what Phase 4 (OTP/sessions) and Phase 5 (WebAuthn)
will produce — an active session tied to an active trusted device — by
inserting those records directly. This lets Phase 3's authorization gate
and privacy projections be fully verified before the identity flows exist.
"""
import os
os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)
os.environ.setdefault("DEVICE_TOKEN_SECRET_KEY", "b" * 64)

import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.core.dependencies import get_db
from app.core.security import hash_session_token, hash_device_token
from app.main import create_app


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_phase3"]
    yield db


@pytest.fixture
async def client(mock_db):
    app = create_app()

    async def override_get_db():
        return mock_db

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _seed_active_member_with_device(
    db, member_id: str, profile: dict, visibility: dict = None, role: str = "member"
):
    """
    Helper: insert an ACTIVE member + ACTIVE device + valid session, and
    return the raw (session_token, device_token) to use as cookies.
    """
    await db.members.insert_one(
        {
            "member_id": member_id,
            "registered_email": f"{member_id.lower()}@example.com",
            "registered_email_normalized": f"{member_id.lower()}@example.com",
            "role": role,
            "status": "ACTIVE",
            "profile": profile,
            "visibility_settings": visibility or {},
        }
    )

    raw_session_token = f"session-{member_id}"
    raw_device_token = f"device-{member_id}"

    session_hash = hash_session_token(raw_session_token)
    device_hash = hash_device_token(raw_device_token)

    await db.devices.insert_one(
        {
            "member_id": member_id,
            "device_cookie_hash": device_hash,
            "credential_id": f"cred-{member_id}",
            "status": "ACTIVE",
        }
    )

    from datetime import datetime, timedelta, timezone
    await db.sessions.insert_one(
        {
            "session_token_hash": session_hash,
            "member_id": member_id,
            "device_id": f"dev-{member_id}",
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "revoked_at": None,
        }
    )

    return raw_session_token, raw_device_token


def _cookies(session_token=None, device_token=None) -> dict:
    cookies = {}
    if session_token:
        cookies["__Host-cd_session"] = session_token
    if device_token:
        cookies["__Host-cd_device"] = device_token
    return cookies


# ── Access gate: unauthenticated / partial auth ──────────────────────────────

@pytest.mark.asyncio
async def test_directory_denied_without_any_cookies(client, mock_db):
    """AT-001: unauthenticated browser requests directory API -> denied."""
    response = await client.get("/api/members")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_directory_denied_with_session_but_no_device_cookie(client, mock_db):
    session_token, _ = await _seed_active_member_with_device(
        mock_db, "NODEV01", {"name": "No Device"}
    )
    client.cookies.update(_cookies(session_token=session_token))
    response = await client.get("/api/members")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "DEVICE_NOT_APPROVED"


@pytest.mark.asyncio
async def test_directory_denied_with_invalid_session_token(client, mock_db):
    response = await client.get(
        "/api/members", cookies=_cookies(session_token="garbage-token")
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_EXPIRED"


@pytest.mark.asyncio
async def test_directory_denied_for_suspended_member(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "SUSP01", {"name": "Suspended Person"}
    )
    await mock_db.members.update_one(
        {"member_id": "SUSP01"}, {"$set": {"status": "SUSPENDED"}}
    )
    response = await client.get(
        "/api/members",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ACCOUNT_SUSPENDED"


@pytest.mark.asyncio
async def test_directory_denied_for_revoked_device(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "REVDEV01", {"name": "Revoked Device Person"}
    )
    await mock_db.devices.update_one(
        {"member_id": "REVDEV01"}, {"$set": {"status": "REVOKED"}}
    )
    response = await client.get(
        "/api/members",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "DEVICE_NOT_APPROVED"


# ── Successful access + directory content ────────────────────────────────────

@pytest.mark.asyncio
async def test_directory_accessible_with_full_valid_auth(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "VALID01", {"name": "Valid Person", "city": "Lucknow"}
    )
    response = await client.get(
        "/api/members",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 200
    body = response.json()
    names = [m["name"] for m in body["data"]]
    assert "Valid Person" in names


@pytest.mark.asyncio
async def test_directory_excludes_staged_and_pending_members(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "VIEWER01", {"name": "Viewer"}
    )
    await mock_db.members.insert_one(
        {"member_id": None, "status": "STAGED", "profile": {"name": "Staged Ghost"}}
    )
    await mock_db.members.insert_one(
        {"member_id": "PEND01", "status": "PENDING_ENROLLMENT", "profile": {"name": "Pending Ghost"}}
    )

    response = await client.get(
        "/api/members",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 200
    names = [m["name"] for m in response.json()["data"]]
    assert "Staged Ghost" not in names
    assert "Pending Ghost" not in names


@pytest.mark.asyncio
async def test_directory_card_never_contains_sensitive_fields(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "CARDCHK01",
        {
            "name": "Card Check",
            "blood_group": "AB+",
            "dob": "2000-01-01",
            "phone": "+911234567890",
        },
    )
    response = await client.get(
        "/api/members",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    card = response.json()["data"][0]
    assert "blood_group" not in card
    assert "dob" not in card
    assert "phone" not in card


@pytest.mark.asyncio
async def test_directory_search_filters_by_text(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "SEARCH01", {"name": "Alpha Person", "city": "Lucknow"}
    )
    await _seed_active_member_with_device(
        mock_db, "SEARCH02", {"name": "Beta Person", "city": "Jaipur"}
    )

    response = await client.get(
        "/api/members?q=Lucknow",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    names = [m["name"] for m in response.json()["data"]]
    assert "Alpha Person" in names
    assert "Beta Person" not in names


@pytest.mark.asyncio
async def test_directory_filter_by_state(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "FILT01", {"name": "UP Person", "state": "Uttar Pradesh"}
    )
    await _seed_active_member_with_device(
        mock_db, "FILT02", {"name": "Rajasthan Person", "state": "Rajasthan"}
    )

    response = await client.get(
        "/api/members?state=Uttar+Pradesh",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    names = [m["name"] for m in response.json()["data"]]
    assert "UP Person" in names
    assert "Rajasthan Person" not in names


@pytest.mark.asyncio
async def test_directory_page_size_rejected_above_hard_limit(client, mock_db):
    """
    FR-DIR-004: list endpoints must not return unrestricted raw dumps.
    page_size is capped at 100 at the route schema level — requesting more
    is rejected outright (422) rather than silently truncated.
    """
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "CAPCHK01", {"name": "Cap Check"}
    )
    response = await client.get(
        "/api/members?page_size=999",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_directory_page_size_accepted_at_hard_limit(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "CAPCHK02", {"name": "Cap Check Two"}
    )
    response = await client.get(
        "/api/members?page_size=100",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 200
    assert response.json()["meta"]["page_size"] == 100


@pytest.mark.asyncio
async def test_directory_filters_endpoint_returns_distinct_values(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "FOPT01", {"name": "Filter Options Person", "state": "Uttar Pradesh", "blood_group": "O+"}
    )
    response = await client.get(
        "/api/members/filters",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert "Uttar Pradesh" in data["state"]
    assert "O+" in data["blood_group"]


# ── Profile privacy projection via HTTP ───────────────────────────────────────

@pytest.mark.asyncio
async def test_profile_view_by_other_member_hides_sensitive_fields(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "VIEWER02", {"name": "Viewer Two"}
    )
    await _seed_active_member_with_device(
        mock_db, "TARGET02",
        {"name": "Target Two", "phone": "+911111111111", "blood_group": "B+"},
    )

    response = await client.get(
        "/api/members/TARGET02",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 200
    profile = response.json()["data"]
    assert profile["name"] == "Target Two"
    assert "phone" not in profile
    assert "blood_group" not in profile


@pytest.mark.asyncio
async def test_profile_self_view_shows_own_sensitive_fields(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "SELF01",
        {"name": "Self Person", "phone": "+912222222222", "pincode": "226001"},
    )

    response = await client.get(
        "/api/members/SELF01",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 200
    profile = response.json()["data"]
    assert profile["phone"] == "+912222222222"
    assert profile["pincode"] == "226001"


@pytest.mark.asyncio
async def test_profile_admin_view_sees_full_record(client, mock_db):
    admin_session, admin_device = await _seed_active_member_with_device(
        mock_db, "ADMVIEW01", {"name": "Admin Viewer"}, role="admin"
    )
    await _seed_active_member_with_device(
        mock_db, "TARGET03",
        {"name": "Target Three", "blood_group": "AB-", "sub_caste": "Test Caste"},
    )

    response = await client.get(
        "/api/members/TARGET03",
        cookies=_cookies(session_token=admin_session, device_token=admin_device),
    )
    assert response.status_code == 200
    profile = response.json()["data"]
    assert profile["profile"]["blood_group"] == "AB-"
    assert profile["profile"]["sub_caste"] == "Test Caste"
    assert profile["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_profile_returns_404_for_nonexistent_member(client, mock_db):
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "VIEWER03", {"name": "Viewer Three"}
    )
    response = await client.get(
        "/api/members/DOES-NOT-EXIST",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_profile_returns_404_for_staged_or_pending_member(client, mock_db):
    """A STAGED/PENDING member_id must never be viewable, even if guessed."""
    session_token, device_token = await _seed_active_member_with_device(
        mock_db, "VIEWER04", {"name": "Viewer Four"}
    )
    await mock_db.members.insert_one(
        {
            "member_id": "PEND02",
            "status": "PENDING_ENROLLMENT",
            "profile": {"name": "Pending Person"},
        }
    )
    response = await client.get(
        "/api/members/PEND02",
        cookies=_cookies(session_token=session_token, device_token=device_token),
    )
    assert response.status_code == 404
