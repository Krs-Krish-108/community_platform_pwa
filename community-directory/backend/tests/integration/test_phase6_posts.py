"""
Integration tests for Phase 6A: Shared Communication APIs.

Exercises routes, dependencies, services, and repositories under posts/emergency alerts
against an in-memory MongoDB mock.
"""
import os
os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)
os.environ.setdefault("DEVICE_TOKEN_SECRET_KEY", "b" * 64)

from datetime import datetime, timedelta, timezone
from bson import ObjectId
import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.core.dependencies import get_db
from app.core.security import hash_session_token, hash_device_token
from app.main import create_app


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_phase6"]
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
    db, member_id: str, role: str = "member"
) -> tuple:
    """Helper: insert member + device + session; return cookies."""
    await db.members.insert_one(
        {
            "member_id": member_id,
            "registered_email": f"{member_id.lower()}@example.com",
            "registered_email_normalized": f"{member_id.lower()}@example.com",
            "role": role,
            "status": "ACTIVE",
            "profile": {
                "name": member_id.title(),
                "city": "Sample City",
                "state": "Sample State",
            },
            "visibility_settings": {},
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


# ── TEST CASES ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_post_creation_fails(client):
    # No cookies -> 401
    resp = await client.post("/api/posts", json={"message": "hello world"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_post_creation_without_device_approved_fails(client, mock_db):
    s_tok, _ = await _seed_active_member_with_device(mock_db, "MEMBER1")
    # Session cookie but no device cookie -> 403
    resp = await client.post(
        "/api/posts",
        json={"message": "hello world"},
        cookies=_cookies(session_token=s_tok),
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "DEVICE_NOT_APPROVED"


@pytest.mark.asyncio
async def test_authenticated_post_creation_succeeds(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    resp = await client.post(
        "/api/posts",
        json={"message": "this is a shared post"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 201
    data = resp.json()["data"]
    assert data["message"] == "this is a shared post"
    assert data["author_member_id"] == "MEMBER1"
    assert data["type"] == "INBOX"
    assert data["status"] == "ACTIVE"
    assert data["priority"] == "NORMAL"


@pytest.mark.asyncio
async def test_spoofing_prevention_enforced(client, mock_db):
    # Authenticate as MEMBER1, try to pass author_member_id in JSON payload (ignored)
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    resp = await client.post(
        "/api/posts",
        json={"message": "malicious post", "author_member_id": "MEMBER2"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 201
    data = resp.json()["data"]
    # The author_member_id is still MEMBER1 (derived from session)
    assert data["author_member_id"] == "MEMBER1"


@pytest.mark.asyncio
async def test_validation_rejects_empty_post(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    # Empty message and no media -> 422
    resp = await client.post(
        "/api/posts",
        json={"message": "   "},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_creation_succeeds_with_media_only(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    
    # Seed media objects
    media1_id = str((await mock_db.media_objects.insert_one({
        "owner_member_id": "MEMBER1",
        "storage_key": "MEMBER1/photo1.jpg",
        "content_type": "image/jpeg",
        "size_bytes": 1000,
        "status": "CONFIRMED",
        "linked_post_id": None,
        "created_at": datetime.now(timezone.utc),
    })).inserted_id)

    media2_id = str((await mock_db.media_objects.insert_one({
        "owner_member_id": "MEMBER1",
        "storage_key": "MEMBER1/photo2.jpg",
        "content_type": "image/jpeg",
        "size_bytes": 1000,
        "status": "CONFIRMED",
        "linked_post_id": None,
        "created_at": datetime.now(timezone.utc),
    })).inserted_id)

    # No message but valid media_ids list -> 201
    resp = await client.post(
        "/api/posts",
        json={"media_ids": [media1_id, media2_id]},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 201
    data = resp.json()["data"]
    assert data["message"] == ""
    assert data["media_ids"] == [media1_id, media2_id]



@pytest.mark.asyncio
async def test_list_inbox_feed_newest_first_and_excludes_removed(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")

    # Insert posts with distinct timestamps
    now = datetime.now(timezone.utc)
    await mock_db.posts.insert_many([
        {
            "type": "INBOX",
            "author_member_id": "MEMBER2",
            "message": "First post",
            "status": "ACTIVE",
            "priority": "NORMAL",
            "created_at": now - timedelta(minutes=10),
            "updated_at": now - timedelta(minutes=10),
        },
        {
            "type": "INBOX",
            "author_member_id": "MEMBER3",
            "message": "Second post (newest)",
            "status": "ACTIVE",
            "priority": "NORMAL",
            "created_at": now,
            "updated_at": now,
        },
        {
            "type": "INBOX",
            "author_member_id": "MEMBER2",
            "message": "Moderated post",
            "status": "REMOVED",
            "priority": "NORMAL",
            "created_at": now - timedelta(minutes=5),
            "updated_at": now - timedelta(minutes=5),
        }
    ])

    resp = await client.get("/api/posts", cookies=_cookies(s_tok, d_tok))
    assert resp.status_code == 200
    data = resp.json()["data"]
    
    # Second post should be first (newest), and moderated post excluded
    assert len(data) == 2
    assert data[0]["message"] == "Second post (newest)"
    assert data[1]["message"] == "First post"


@pytest.mark.asyncio
async def test_emergency_alert_creation_has_urgent_priority(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    resp = await client.post(
        "/api/emergency-alerts",
        json={"message": "Emergency situation!"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 201
    data = resp.json()["data"]
    assert data["type"] == "EMERGENCY"
    assert data["priority"] == "URGENT"


@pytest.mark.asyncio
async def test_emergency_resolution_admin_vs_member(client, mock_db):
    # Seed alert
    alert_id = str((await mock_db.posts.insert_one({
        "type": "EMERGENCY",
        "author_member_id": "MEMBER2",
        "message": "Help!",
        "status": "ACTIVE",
        "priority": "URGENT",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    # 1. Non-admin member tries to resolve -> 403 Forbidden
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1", role="member")
    resp = await client.post(
        f"/api/emergency-alerts/{alert_id}/resolve",
        json={"note": "False alarm"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 403

    # 2. Admin tries to resolve -> 200 Success
    admin_s_tok, admin_d_tok = await _seed_active_member_with_device(mock_db, "ADMIN1", role="admin")
    resp = await client.post(
        f"/api/emergency-alerts/{alert_id}/resolve",
        json={"note": "Resolved and handled"},
        cookies=_cookies(admin_s_tok, admin_d_tok),
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "RESOLVED"
    assert data["resolution"]["note"] == "Resolved and handled"
    assert data["resolution"]["resolved_by"] == "ADMIN1"


@pytest.mark.asyncio
async def test_report_post_increments_count(client, mock_db):
    post_id = str((await mock_db.posts.insert_one({
        "type": "INBOX",
        "author_member_id": "MEMBER2",
        "message": "spam post",
        "status": "ACTIVE",
        "priority": "NORMAL",
        "reported_count": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    resp = await client.post(
        f"/api/posts/{post_id}/report",
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp.status_code == 200
    
    updated_doc = await mock_db.posts.find_one({"author_member_id": "MEMBER2"})
    assert updated_doc["reported_count"] == 1


@pytest.mark.asyncio
async def test_admin_remove_post_succeeds_and_logs_audit(client, mock_db):
    post_id = str((await mock_db.posts.insert_one({
        "type": "INBOX",
        "author_member_id": "MEMBER2",
        "message": "spam post",
        "status": "ACTIVE",
        "priority": "NORMAL",
        "reported_count": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    admin_s_tok, admin_d_tok = await _seed_active_member_with_device(mock_db, "ADMIN1", role="admin")
    resp = await client.post(
        f"/api/admin/posts/{post_id}/remove",
        json={"reason": "Inappropriate advertising"},
        cookies=_cookies(admin_s_tok, admin_d_tok),
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["success"] is True

    # 1. Verify status is soft-deleted to REMOVED
    updated_doc = await mock_db.posts.find_one({"_id": ObjectId(post_id)})
    assert updated_doc["status"] == "REMOVED"
    assert updated_doc["moderation"]["reason"] == "Inappropriate advertising"
    assert updated_doc["moderation"]["actioned_by"] == "ADMIN1"

    # 2. Verify audit log entry created
    audit = await mock_db.audit_logs.find_one({"action": "POST_REMOVED"})
    assert audit is not None
    assert audit["actor"] == "ADMIN1"
    assert audit["target"] == post_id
    assert audit["reason"] == "Inappropriate advertising"


@pytest.mark.asyncio
async def test_admin_resolve_emergency_succeeds_and_logs_audit(client, mock_db):
    alert_id = str((await mock_db.posts.insert_one({
        "type": "EMERGENCY",
        "author_member_id": "MEMBER2",
        "message": "Water leak!",
        "status": "ACTIVE",
        "priority": "URGENT",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    admin_s_tok, admin_d_tok = await _seed_active_member_with_device(mock_db, "ADMIN1", role="admin")
    resp = await client.post(
        f"/api/admin/emergency-alerts/{alert_id}/resolve",
        json={"reason": "Plumber resolved leak"},
        cookies=_cookies(admin_s_tok, admin_d_tok),
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "RESOLVED"
    assert data["resolution"]["note"] == "Plumber resolved leak"

    # Verify audit log entry created
    audit = await mock_db.audit_logs.find_one({"action": "EMERGENCY_RESOLVED"})
    assert audit is not None
    assert audit["actor"] == "ADMIN1"
    assert audit["target"] == alert_id
    assert audit["reason"] == "Plumber resolved leak"


@pytest.mark.asyncio
async def test_non_admin_moderation_is_forbidden(client, mock_db):
    post_id = str((await mock_db.posts.insert_one({
        "type": "INBOX",
        "author_member_id": "MEMBER2",
        "message": "some post",
        "status": "ACTIVE",
        "priority": "NORMAL",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1", role="member")
    
    # 1. Non-admin remove -> 403
    resp1 = await client.post(
        f"/api/admin/posts/{post_id}/remove",
        json={"reason": "Not allowed"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp1.status_code == 403

    # 2. Non-admin resolve -> 403
    resp2 = await client.post(
        f"/api/admin/emergency-alerts/{post_id}/resolve",
        json={"reason": "Not allowed"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp2.status_code == 403


@pytest.mark.asyncio
async def test_feed_visibility_after_moderation(client, mock_db):
    post_id = str((await mock_db.posts.insert_one({
        "type": "INBOX",
        "author_member_id": "MEMBER2",
        "message": "Spam post",
        "status": "ACTIVE",
        "priority": "NORMAL",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    alert_id = str((await mock_db.posts.insert_one({
        "type": "EMERGENCY",
        "author_member_id": "MEMBER2",
        "message": "Water leak!",
        "status": "ACTIVE",
        "priority": "URGENT",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })).inserted_id)

    admin_s_tok, admin_d_tok = await _seed_active_member_with_device(mock_db, "ADMIN1", role="admin")
    
    # Moderate (remove) post
    await client.post(
        f"/api/admin/posts/{post_id}/remove",
        json={"reason": "Removed spam"},
        cookies=_cookies(admin_s_tok, admin_d_tok),
    )

    # Resolve alert
    await client.post(
        f"/api/admin/emergency-alerts/{alert_id}/resolve",
        json={"reason": "Resolved leak"},
        cookies=_cookies(admin_s_tok, admin_d_tok),
    )

    # Normal member requests feeds
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1", role="member")
    
    # 1. Post feed: REMOVED post must NOT be visible
    resp1 = await client.get("/api/posts", cookies=_cookies(s_tok, d_tok))
    assert resp1.status_code == 200
    assert len(resp1.json()["data"]) == 0

    # 2. Emergency feed: RESOLVED alert MUST remain visible in history
    resp2 = await client.get("/api/emergency-alerts", cookies=_cookies(s_tok, d_tok))
    assert resp2.status_code == 200
    assert len(resp2.json()["data"]) == 1
    assert resp2.json()["data"][0]["status"] == "RESOLVED"

