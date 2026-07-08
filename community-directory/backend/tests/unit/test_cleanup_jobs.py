"""
Unit tests for Phase 7B: Background Cleanup Jobs.

Validates correct pruning logic for expired OTPs, expired sessions, revoked sessions,
orphan media files, and stale pending requests.
"""
from datetime import datetime, timedelta, timezone
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.jobs.cleanup import CleanupJobs


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_cleanup"]
    yield db


@pytest.mark.asyncio
async def test_cleanup_prunes_expired_otp_challenges(mock_db):
    now = datetime.now(timezone.utc)
    
    await mock_db["otp_challenges"].insert_many([
        {"member_id": "M1", "expires_at": now - timedelta(seconds=1), "created_at": now - timedelta(minutes=10)},
        {"member_id": "M2", "expires_at": now + timedelta(minutes=5), "created_at": now},
    ])
    
    jobs = CleanupJobs(mock_db)
    res = await jobs.run_cleanup()
    
    assert res["expired_otps"] == 1
    
    remaining = await mock_db["otp_challenges"].find({}).to_list(None)
    assert len(remaining) == 1
    assert remaining[0]["member_id"] == "M2"


@pytest.mark.asyncio
async def test_cleanup_prunes_expired_tickets(mock_db):
    now = datetime.now(timezone.utc)
    
    await mock_db["enrollment_tickets"].insert_many([
        {"member_id": "M1", "expires_at": now - timedelta(seconds=1)},
        {"member_id": "M2", "expires_at": now + timedelta(minutes=5)},
    ])
    
    jobs = CleanupJobs(mock_db)
    res = await jobs.run_cleanup()
    
    assert res["expired_tickets"] == 1
    
    remaining = await mock_db["enrollment_tickets"].find({}).to_list(None)
    assert len(remaining) == 1
    assert remaining[0]["member_id"] == "M2"


@pytest.mark.asyncio
async def test_cleanup_prunes_expired_sessions(mock_db):
    now = datetime.now(timezone.utc)
    
    await mock_db["sessions"].insert_many([
        {"member_id": "M1", "expires_at": now - timedelta(seconds=1), "revoked_at": None},
        {"member_id": "M2", "expires_at": now + timedelta(minutes=5), "revoked_at": None},
    ])
    
    jobs = CleanupJobs(mock_db)
    res = await jobs.run_cleanup()
    
    assert res["expired_sessions"] == 1
    
    remaining = await mock_db["sessions"].find({}).to_list(None)
    assert len(remaining) == 1
    assert remaining[0]["member_id"] == "M2"


@pytest.mark.asyncio
async def test_cleanup_prunes_revoked_sessions_outside_retention(mock_db):
    now = datetime.now(timezone.utc)
    
    await mock_db["sessions"].insert_many([
        {"member_id": "M1", "expires_at": now + timedelta(hours=1), "revoked_at": now - timedelta(days=31)},
        {"member_id": "M2", "expires_at": now + timedelta(hours=1), "revoked_at": now - timedelta(days=10)},
        {"member_id": "M3", "expires_at": now + timedelta(hours=1), "revoked_at": None},
    ])
    
    jobs = CleanupJobs(mock_db)
    res = await jobs.run_cleanup()
    
    assert res["revoked_sessions"] == 1
    
    remaining = await mock_db["sessions"].find({}).to_list(None)
    assert len(remaining) == 2
    ids = {r["member_id"] for r in remaining}
    assert ids == {"M2", "M3"}


@pytest.mark.asyncio
async def test_cleanup_prunes_orphan_media_only(mock_db):
    now = datetime.now(timezone.utc)
    
    await mock_db["media_objects"].insert_many([
        {"owner_member_id": "M1", "linked_post_id": None, "created_at": now - timedelta(hours=25)},
        {"owner_member_id": "M2", "linked_post_id": None, "created_at": now - timedelta(hours=5)},
        {"owner_member_id": "M3", "linked_post_id": "post123", "created_at": now - timedelta(hours=30)},
    ])
    
    jobs = CleanupJobs(mock_db)
    res = await jobs.run_cleanup()
    
    assert res["orphan_media"] == 1
    
    remaining = await mock_db["media_objects"].find({}).to_list(None)
    assert len(remaining) == 2
    ids = {r["owner_member_id"] for r in remaining}
    assert ids == {"M2", "M3"}


@pytest.mark.asyncio
async def test_cleanup_prunes_stale_device_requests(mock_db):
    now = datetime.now(timezone.utc)
    
    await mock_db["device_change_requests"].insert_many([
        {"member_id": "M1", "status": "PENDING", "requested_at": now - timedelta(days=31)},
        {"member_id": "M2", "status": "PENDING", "requested_at": now - timedelta(days=5)},
        {"member_id": "M3", "status": "APPROVED", "requested_at": now - timedelta(days=40)},
    ])
    
    jobs = CleanupJobs(mock_db)
    res = await jobs.run_cleanup()
    
    assert res["stale_device_requests"] == 1
    
    remaining = await mock_db["device_change_requests"].find({}).to_list(None)
    assert len(remaining) == 2
    ids = {r["member_id"] for r in remaining}
    assert ids == {"M2", "M3"}
