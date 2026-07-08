"""
Integration tests using an in-memory MongoDB mock (mongomock-motor).
These verify repository behavior and admin bootstrap logic without requiring
a live MongoDB server — useful for CI and sandboxed environments.

For full confidence before pilot, also run these same flows against a real
MongoDB Atlas M0 cluster (see docs/testing.md).
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.database import create_indexes
from app.domain.bootstrap_service import run_admin_bootstrap, BOOTSTRAP_STATE_KEY
from app.repositories.members_repo import MembersRepository
from app.repositories.sessions_repo import SessionsRepository
from app.repositories.devices_repo import DevicesRepository
from app.core.security import hash_session_token


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_community_directory"]
    yield db


@pytest.mark.asyncio
async def test_create_indexes_does_not_raise(mock_db):
    # Should complete without error even against a mock backend
    await create_indexes(mock_db)


@pytest.mark.asyncio
async def test_admin_bootstrap_creates_first_admin(mock_db, monkeypatch):
    from app.core import config as config_module
    config_module.get_settings.cache_clear()
    monkeypatch.setenv("ADMIN_BOOTSTRAP_EMAIL", "admin@example.org")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "correct-horse-battery-staple")

    await run_admin_bootstrap(mock_db)

    admin = await mock_db.members.find_one({"registered_email_normalized": "admin@example.org"})
    assert admin is not None
    assert admin["role"] == "admin"
    assert admin["status"] == "PENDING_ENROLLMENT"
    assert admin["member_id"].startswith("ADM-")

    state = await mock_db.system_state.find_one({"key": BOOTSTRAP_STATE_KEY})
    assert state["completed"] is True

    config_module.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_admin_bootstrap_is_idempotent(mock_db, monkeypatch):
    """Running bootstrap twice must not create a second admin or reset the first."""
    from app.core import config as config_module
    config_module.get_settings.cache_clear()
    monkeypatch.setenv("ADMIN_BOOTSTRAP_EMAIL", "admin2@example.org")
    monkeypatch.setenv("ADMIN_BOOTSTRAP_PASSWORD", "correct-horse-battery-staple")

    await run_admin_bootstrap(mock_db)
    count_after_first = await mock_db.members.count_documents({})

    await run_admin_bootstrap(mock_db)
    count_after_second = await mock_db.members.count_documents({})

    assert count_after_first == count_after_second == 1
    config_module.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_members_repository_enforces_active_only_directory_listing(mock_db):
    repo = MembersRepository(mock_db)

    await mock_db.members.insert_one(
        {"member_id": "A001", "name": "Active Member", "status": "ACTIVE"}
    )
    await mock_db.members.insert_one(
        {"member_id": "S002", "name": "Staged Member", "status": "STAGED"}
    )

    results = await repo.list_directory()
    member_ids = [m["member_id"] for m in results]

    assert "A001" in member_ids
    assert "S002" not in member_ids  # AT-001 style check: unapproved never listed


@pytest.mark.asyncio
async def test_session_repository_rejects_expired_session(mock_db):
    from datetime import datetime, timedelta, timezone

    repo = SessionsRepository(mock_db)
    token = "sometoken"
    token_hash = hash_session_token(token)

    # Insert an already-expired session directly
    await mock_db.sessions.insert_one(
        {
            "session_token_hash": token_hash,
            "member_id": "A001",
            "device_id": "dev1",
            "created_at": datetime.now(timezone.utc) - timedelta(hours=2),
            "expires_at": datetime.now(timezone.utc) - timedelta(hours=1),
            "revoked_at": None,
        }
    )

    found = await repo.find_active_session(token_hash)
    assert found is None  # Expired sessions must never validate


@pytest.mark.asyncio
async def test_device_revocation_invalidates_sessions(mock_db):
    """FR-DEV-008 / AT-009: revoking a device invalidates its sessions."""
    devices_repo = DevicesRepository(mock_db)
    sessions_repo = SessionsRepository(mock_db)

    device_id_str = await devices_repo.create_device(
        member_id="A001",
        device_cookie_hash="devicehash123",
        credential_id="cred123",
    )
    from bson import ObjectId
    device_object_id = ObjectId(device_id_str)

    await sessions_repo.create_session(
        member_id="A001", device_id=device_id_str, session_token_hash="sesshash123"
    )

    revoked_count = await devices_repo.revoke_all_for_member("A001")
    assert revoked_count == 1

    invalidated_count = await sessions_repo.revoke_all_for_device(device_id_str)
    assert invalidated_count == 1

    active_session = await sessions_repo.find_active_session("sesshash123")
    assert active_session is None
