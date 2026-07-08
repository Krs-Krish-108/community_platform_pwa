"""
Integration tests for Phase 7A: Security Flag Aggregation.

Validates that security events aggregate correctly into admin flags when thresholds
are reached, prevents flag duplicate spam, and verifies admin resolution.
"""
import os
os.environ.setdefault("SESSION_SECRET_KEY", "a" * 64)
os.environ.setdefault("DEVICE_TOKEN_SECRET_KEY", "b" * 64)

from datetime import datetime, timezone, timedelta
from bson import ObjectId
import pytest
from httpx import AsyncClient, ASGITransport
from mongomock_motor import AsyncMongoMockClient

from app.core.dependencies import get_db
from app.core.security import hash_session_token, hash_device_token
from app.domain.security_service import SecurityService
from app.main import create_app
from tests.integration.test_phase6_posts import _seed_active_member_with_device, _cookies


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_phase7"]
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
async def test_threshold_detection_and_flag_creation(mock_db):
    service = SecurityService(mock_db)

    # Threshold for OTP_FAILED is 10 (as per settings in config.py)
    # Record 9 events -> no flag created
    for i in range(9):
        await service.record_event(
            event_type="OTP_FAILED",
            member_ref="MEMBER1",
            metadata={"attempt": i},
        )
        
    flag = await mock_db.security_flags.find_one({"target_ref": "MEMBER1", "rule_code": "RULE_OTP_FAILED"})
    assert flag is None

    # Record the 10th event -> triggers flag creation
    await service.record_event(
        event_type="OTP_FAILED",
        member_ref="MEMBER1",
        metadata={"attempt": 9},
    )

    flag = await mock_db.security_flags.find_one({"target_ref": "MEMBER1", "rule_code": "RULE_OTP_FAILED"})
    assert flag is not None
    assert flag["status"] == "OPEN"
    assert flag["severity"] == "HIGH"
    assert len(flag["evidence_event_ids"]) == 10


@pytest.mark.asyncio
async def test_no_duplicate_flag_spam(mock_db):
    service = SecurityService(mock_db)

    # Trigger initial flag
    for i in range(10):
        await service.record_event(
            event_type="OTP_FAILED",
            member_ref="MEMBER1",
        )

    flags_count_1 = await mock_db.security_flags.count_documents({"target_ref": "MEMBER1", "rule_code": "RULE_OTP_FAILED"})
    assert flags_count_1 == 1

    # Record 11th event -> no new flag, appends evidence ID to the existing one
    await service.record_event(
        event_type="OTP_FAILED",
        member_ref="MEMBER1",
    )

    flags_count_2 = await mock_db.security_flags.count_documents({"target_ref": "MEMBER1", "rule_code": "RULE_OTP_FAILED"})
    assert flags_count_2 == 1  # Still exactly one flag, no spam!

    flag = await mock_db.security_flags.find_one({"target_ref": "MEMBER1", "rule_code": "RULE_OTP_FAILED"})
    assert len(flag["evidence_event_ids"]) == 11


@pytest.mark.asyncio
async def test_admin_flag_resolution_and_audit(client, mock_db):
    # Seed an open flag in DB
    flag_id = str((await mock_db.security_flags.insert_one({
        "rule_code": "RULE_OTP_FAILED",
        "severity": "HIGH",
        "target_ref": "MEMBER1",
        "evidence_event_ids": ["evt1", "evt2"],
        "status": "OPEN",
        "admin_notes": None,
        "created_at": datetime.now(timezone.utc),
    })).inserted_id)

    # 1. Non-admin member tries to resolve flag -> 403 Forbidden
    s_tok, d_tok = await _seed_active_member_with_device(mock_db, "MEMBER2", role="member")
    resp_member = await client.post(
        f"/api/admin/security-flags/{flag_id}/resolve",
        json={"admin_notes": "Treated as safe"},
        cookies=_cookies(s_tok, d_tok),
    )
    assert resp_member.status_code == 403

    # 2. Admin resolves flag -> 200 OK
    admin_s_tok, admin_d_tok = await _seed_active_member_with_device(mock_db, "ADMIN1", role="admin")
    resp_admin = await client.post(
        f"/api/admin/security-flags/{flag_id}/resolve",
        json={"admin_notes": "Investigated and resolved"},
        cookies=_cookies(admin_s_tok, admin_d_tok),
    )
    assert resp_admin.status_code == 200
    assert resp_admin.json()["data"]["status"] == "RESOLVED"

    # Verify database state
    flag = await mock_db.security_flags.find_one({"_id": ObjectId(flag_id)})
    assert flag["status"] == "RESOLVED"
    assert flag["admin_notes"] == "Investigated and resolved"

    # Verify audit trail
    audit = await mock_db.audit_logs.find_one({"action": "SECURITY_FLAG_RESOLVED"})
    assert audit is not None
    assert audit["actor"] == "ADMIN1"
    assert audit["target"] == flag_id
    assert audit["reason"] == "Investigated and resolved"
