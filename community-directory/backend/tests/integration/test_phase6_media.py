"""
Integration tests for Phase 6C: Media upload support.

Validates upload intents, MIME type constraints, file size limits, ownership checks,
and access authorization controls.
"""
import os
os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)
os.environ.setdefault("DEVICE_TOKEN_SECRET_KEY", "b" * 64)

from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient
from bson import ObjectId

from app.core.dependencies import get_db
from app.core.security import hash_session_token, hash_device_token
from app.main import create_app
from tests.integration.test_phase6_posts import _seed_active_member_with_device, _cookies


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_phase6_media"]
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


# ── TEST CASES ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_upload_intent_fails(client):
    resp = await client.post(
        "/api/media/upload-intent",
        json={"filename": "photo.jpg", "content_type": "image/jpeg", "size_bytes": 1000}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invalid_mime_type_fails(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    resp = await client.post(
        "/api/media/upload-intent",
        json={"filename": "doc.pdf", "content_type": "application/pdf", "size_bytes": 1000},
        cookies=_cookies(s_tok, d_tok)
    )
    assert resp.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_oversized_file_fails(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    
    # 1. Image > 5MB
    resp_img = await client.post(
        "/api/media/upload-intent",
        json={"filename": "photo.jpg", "content_type": "image/jpeg", "size_bytes": 6 * 1024 * 1024},
        cookies=_cookies(s_tok, d_tok)
    )
    assert resp_img.status_code == 422

    # 2. Video > 20MB
    resp_vid = await client.post(
        "/api/media/upload-intent",
        json={"filename": "video.mp4", "content_type": "video/mp4", "size_bytes": 21 * 1024 * 1024},
        cookies=_cookies(s_tok, d_tok)
    )
    assert resp_vid.status_code == 422


@pytest.mark.asyncio
async def test_valid_upload_intent_and_complete(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")
    
    # 1. Initiate intent
    resp_intent = await client.post(
        "/api/media/upload-intent",
        json={"filename": "photo.jpg", "content_type": "image/jpeg", "size_bytes": 1000},
        cookies=_cookies(s_tok, d_tok)
    )
    assert resp_intent.status_code == 201
    intent_data = resp_intent.json()["data"]
    media_id = intent_data["media_id"]
    assert "upload_url" in intent_data
    
    # Check pending in DB
    db_media = await mock_db.media_objects.find_one({"_id": ObjectId(media_id)})
    assert db_media["status"] == "PENDING"
    assert db_media["owner_member_id"] == "MEMBER1"

    # 2. Complete upload
    resp_complete = await client.post(
        "/api/media/complete",
        json={"media_id": media_id},
        cookies=_cookies(s_tok, d_tok)
    )
    assert resp_complete.status_code == 200
    assert resp_complete.json()["data"]["success"] is True

    # Check confirmed in DB
    db_media_confirmed = await mock_db.media_objects.find_one({"_id": ObjectId(media_id)})
    assert db_media_confirmed["status"] == "CONFIRMED"


@pytest.mark.asyncio
async def test_media_linked_to_post_access_control(client, mock_db):
    # Setup two users
    m1_s, m1_d = await _seed_active_member_with_device(mock_db, "MEMBER1")
    m2_s, m2_d = await _seed_active_member_with_device(mock_db, "MEMBER2")

    # Insert a confirmed media object owned by MEMBER1
    media_id = str((await mock_db.media_objects.insert_one({
        "owner_member_id": "MEMBER1",
        "storage_key": "MEMBER1/photo.jpg",
        "content_type": "image/jpeg",
        "size_bytes": 1000,
        "status": "CONFIRMED",
        "linked_post_id": None,
        "created_at": datetime.now(timezone.utc),
    })).inserted_id)

    # 1. MEMBER2 tries to access unlinked media -> 403 Forbidden
    resp_unlinked = await client.get(
        f"/api/media/{media_id}/access-url",
        cookies=_cookies(m2_s, m2_d)
    )
    assert resp_unlinked.status_code == 403

    # 2. Create post and link the media (successfully validated + linked in DB)
    post_resp = await client.post(
        "/api/posts",
        json={"message": "Look at this", "media_ids": [media_id]},
        cookies=_cookies(m1_s, m1_d)
    )
    assert post_resp.status_code == 201
    post_id = post_resp.json()["data"]["id"]
    
    # Verify linked in DB
    db_media = await mock_db.media_objects.find_one({"_id": ObjectId(media_id)})
    assert db_media["linked_post_id"] == post_id

    # 3. MEMBER2 can now fetch access-url because they have access to the active linked post
    resp_linked = await client.get(
        f"/api/media/{media_id}/access-url",
        cookies=_cookies(m2_s, m2_d)
    )
    assert resp_linked.status_code == 200
    assert "access_url" in resp_linked.json()["data"]


@pytest.mark.asyncio
async def test_moderated_post_media_access_denied(client, mock_db):
    # Setup admin, owner, and other member
    admin_s, admin_d = await _seed_active_member_with_device(mock_db, "ADMIN1", role="admin")
    m1_s, m1_d = await _seed_active_member_with_device(mock_db, "MEMBER1")
    m2_s, m2_d = await _seed_active_member_with_device(mock_db, "MEMBER2")

    # Seed media + post
    media_id = str((await mock_db.media_objects.insert_one({
        "owner_member_id": "MEMBER1",
        "storage_key": "MEMBER1/photo.jpg",
        "content_type": "image/jpeg",
        "size_bytes": 1000,
        "status": "CONFIRMED",
        "linked_post_id": None,
        "created_at": datetime.now(timezone.utc),
    })).inserted_id)

    post_resp = await client.post(
        "/api/posts",
        json={"message": "Look at this", "media_ids": [media_id]},
        cookies=_cookies(m1_s, m1_d)
    )
    post_id = post_resp.json()["data"]["id"]

    # Admin removes post (soft-delete)
    await client.post(
        f"/api/admin/posts/{post_id}/remove",
        json={"reason": "policy violation"},
        cookies=_cookies(admin_s, admin_d)
    )

    # 1. Normal member tries to access media -> 403 Forbidden
    resp_member = await client.get(
        f"/api/media/{media_id}/access-url",
        cookies=_cookies(m2_s, m2_d)
    )
    assert resp_member.status_code == 403

    # 2. Admin tries to access media -> 200 OK (admins bypass moderated media block for audit)
    resp_admin = await client.get(
        f"/api/media/{media_id}/access-url",
        cookies=_cookies(admin_s, admin_d)
    )
    assert resp_admin.status_code == 200


@pytest.mark.asyncio
async def test_maximum_three_media_files_limit(client, mock_db):
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER1")

    # Insert 4 confirmed media objects
    media_ids = []
    for i in range(4):
        mid = str((await mock_db.media_objects.insert_one({
            "owner_member_id": "MEMBER1",
            "storage_key": f"MEMBER1/photo{i}.jpg",
            "content_type": "image/jpeg",
            "size_bytes": 1000,
            "status": "CONFIRMED",
            "linked_post_id": None,
            "created_at": datetime.now(timezone.utc),
        })).inserted_id)
        media_ids.append(mid)

    # Post with 4 media items -> 400/422 ValueError (Pydantic or post creation validation)
    resp = await client.post(
        "/api/posts",
        json={"message": "too many images", "media_ids": media_ids},
        cookies=_cookies(s_tok, d_tok)
    )
    assert resp.status_code == 400 or resp.status_code == 422
