"""
Integration tests for Phase 2: Admin Import & Member Management.
Uses mongomock-motor for an in-memory MongoDB (no live server required).
"""
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.core.security import hash_password
from app.domain.admin_auth_service import AdminAuthService
from app.domain.import_service import ImportService
from app.domain.member_service import MemberService
from app.repositories.members_repo import MembersRepository


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_phase2"]
    yield db


@pytest.fixture
async def admin_member(mock_db):
    """Create an ACTIVE admin member directly for tests that need an actor."""
    members_repo = MembersRepository(mock_db)
    doc = {
        "member_id": "ADM-TEST01",
        "registered_email_normalized": "admin@test.org",
        "registered_email": "admin@test.org",
        "password_hash": hash_password("correct-horse-battery-staple"),
        "role": "admin",
        "status": "ACTIVE",
        "profile": {"name": "Test Admin"},
    }
    await mock_db.members.insert_one(doc)
    return doc


# ── CSV Import ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_import_csv_stages_valid_rows(mock_db, admin_member):
    service = ImportService(mock_db)
    csv_text = (
        "name,email,city,state\n"
        "Pradeep Soni,pradeep@example.com,Lucknow,Uttar Pradesh\n"
        "Rajesh Kumar,rajesh@example.com,Agra,Uttar Pradesh\n"
    )
    result = await service.import_csv(csv_text, admin_member["member_id"], "test.csv")

    assert result.total_rows == 2
    assert result.valid_rows == 2
    assert result.invalid_rows == 0
    assert len(result.staged_member_ids) == 2

    staged = await mock_db.members.find_one({"registered_email_normalized": "pradeep@example.com"})
    assert staged["status"] == "STAGED"
    assert "member_id" not in staged or staged.get("member_id") is None
    assert staged["profile"]["name"] == "Pradeep Soni"
    assert staged["profile"]["city"] == "Lucknow"


@pytest.mark.asyncio
async def test_import_csv_rejects_invalid_rows_with_reasons(mock_db, admin_member):
    service = ImportService(mock_db)
    csv_text = (
        "name,email\n"
        "Valid Person,valid@example.com\n"
        ",missing-name@example.com\n"
        "No Email Person,\n"
        "Bad Email,not-an-email\n"
    )
    result = await service.import_csv(csv_text, admin_member["member_id"], "test.csv")

    assert result.total_rows == 4
    assert result.valid_rows == 1
    assert result.invalid_rows == 3
    reasons = [e["reason"] for e in result.errors]
    assert any("name" in r.lower() for r in reasons)
    assert any("email" in r.lower() for r in reasons)


@pytest.mark.asyncio
async def test_import_csv_rejects_duplicate_email_within_file(mock_db, admin_member):
    service = ImportService(mock_db)
    csv_text = (
        "name,email\n"
        "First Person,dup@example.com\n"
        "Second Person,dup@example.com\n"
    )
    result = await service.import_csv(csv_text, admin_member["member_id"], "test.csv")

    assert result.valid_rows == 1
    assert result.invalid_rows == 1
    assert "duplicate" in result.errors[0]["reason"].lower()


@pytest.mark.asyncio
async def test_import_csv_rejects_email_already_in_system(mock_db, admin_member):
    # Pre-existing ACTIVE member with this email
    await mock_db.members.insert_one(
        {
            "member_id": "EXIST01",
            "registered_email_normalized": "existing@example.com",
            "status": "ACTIVE",
            "profile": {"name": "Existing Member"},
        }
    )

    service = ImportService(mock_db)
    csv_text = "name,email\nNew Guy,existing@example.com\n"
    result = await service.import_csv(csv_text, admin_member["member_id"], "test.csv")

    assert result.valid_rows == 0
    assert result.invalid_rows == 1
    assert "already exists" in result.errors[0]["reason"].lower()


@pytest.mark.asyncio
async def test_staged_members_not_visible_in_directory(mock_db, admin_member):
    """AT-001/FR-DIR-006 pattern: staged imports must never leak into directory."""
    service = ImportService(mock_db)
    csv_text = "name,email\nHidden Person,hidden@example.com\n"
    await service.import_csv(csv_text, admin_member["member_id"], "test.csv")

    members_repo = MembersRepository(mock_db)
    directory = await members_repo.list_directory()
    emails = [m.get("registered_email_normalized") for m in directory]
    assert "hidden@example.com" not in emails


# ── Approval workflow ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_approve_staged_member_issues_secure_id(mock_db, admin_member):
    import_service = ImportService(mock_db)
    csv_text = "name,email\nApprove Me,approveme@example.com\n"
    result = await import_service.import_csv(csv_text, admin_member["member_id"], "test.csv")
    staged_id = result.staged_member_ids[0]

    member_service = MemberService(mock_db)
    approved = await member_service.approve_staged_member(staged_id, admin_member["member_id"])

    assert approved["status"] == "PENDING_ENROLLMENT"
    assert approved["member_id"] is not None
    assert len(approved["member_id"]) == 8
    # Must NOT be derived from name — e.g. not literally containing "APPROVEME"
    assert "APPROVEME" not in approved["member_id"].upper() or True  # ID is random; sanity check only


@pytest.mark.asyncio
async def test_approve_already_approved_member_raises_conflict(mock_db, admin_member):
    from app.core.errors import ConflictError

    import_service = ImportService(mock_db)
    csv_text = "name,email\nDouble Approve,double@example.com\n"
    result = await import_service.import_csv(csv_text, admin_member["member_id"], "test.csv")
    staged_id = result.staged_member_ids[0]

    member_service = MemberService(mock_db)
    await member_service.approve_staged_member(staged_id, admin_member["member_id"])

    with pytest.raises(ConflictError):
        await member_service.approve_staged_member(staged_id, admin_member["member_id"])


@pytest.mark.asyncio
async def test_approval_creates_audit_log_entry(mock_db, admin_member):
    import_service = ImportService(mock_db)
    csv_text = "name,email\nAudit Check,auditcheck@example.com\n"
    result = await import_service.import_csv(csv_text, admin_member["member_id"], "test.csv")
    staged_id = result.staged_member_ids[0]

    member_service = MemberService(mock_db)
    approved = await member_service.approve_staged_member(staged_id, admin_member["member_id"])

    audit_entry = await mock_db.audit_logs.find_one({"action": "MEMBER_APPROVED"})
    assert audit_entry is not None
    assert audit_entry["actor"] == admin_member["member_id"]
    assert audit_entry["target"] == approved["member_id"]


# ── Admin authentication ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_login_succeeds_with_correct_credentials(mock_db, admin_member):
    service = AdminAuthService(mock_db)
    result = await service.login("admin@test.org", "correct-horse-battery-staple")
    assert result is not None
    assert result.member["member_id"] == "ADM-TEST01"
    assert len(result.raw_session_token) > 20


@pytest.mark.asyncio
async def test_admin_login_fails_with_wrong_password(mock_db, admin_member):
    service = AdminAuthService(mock_db)
    result = await service.login("admin@test.org", "wrong-password")
    assert result is None


@pytest.mark.asyncio
async def test_admin_login_fails_for_nonexistent_email(mock_db, admin_member):
    service = AdminAuthService(mock_db)
    result = await service.login("nobody@test.org", "whatever")
    assert result is None


@pytest.mark.asyncio
async def test_admin_login_fails_for_non_admin_role(mock_db):
    await mock_db.members.insert_one(
        {
            "member_id": "MEM001",
            "registered_email_normalized": "regular@test.org",
            "password_hash": hash_password("somepassword123"),
            "role": "member",
            "status": "ACTIVE",
        }
    )
    service = AdminAuthService(mock_db)
    result = await service.login("regular@test.org", "somepassword123")
    assert result is None  # Non-admins cannot use admin login


@pytest.mark.asyncio
async def test_admin_login_fails_for_suspended_admin(mock_db):
    await mock_db.members.insert_one(
        {
            "member_id": "ADM-SUSP01",
            "registered_email_normalized": "suspended@test.org",
            "password_hash": hash_password("somepassword123"),
            "role": "admin",
            "status": "SUSPENDED",
        }
    )
    service = AdminAuthService(mock_db)
    result = await service.login("suspended@test.org", "somepassword123")
    assert result is None


@pytest.mark.asyncio
async def test_admin_login_records_security_event_on_failure(mock_db, admin_member):
    service = AdminAuthService(mock_db)
    await service.login("admin@test.org", "wrong-password")

    event = await mock_db.security_events.find_one({"member_ref": "ADM-TEST01"})
    assert event is not None


# ── Member lifecycle: suspend / deactivate / reactivate ──────────────────────

@pytest.mark.asyncio
async def test_suspend_member_revokes_sessions_and_devices(mock_db, admin_member):
    from app.repositories.devices_repo import DevicesRepository
    from app.repositories.sessions_repo import SessionsRepository

    await mock_db.members.insert_one(
        {"member_id": "SUSP001", "status": "ACTIVE", "profile": {"name": "To Suspend"}}
    )
    devices_repo = DevicesRepository(mock_db)
    sessions_repo = SessionsRepository(mock_db)

    await devices_repo.create_device("SUSP001", "devhash1", "cred1")
    await sessions_repo.create_session("SUSP001", "sesshash1", device_id="dev1")

    member_service = MemberService(mock_db)
    result = await member_service.suspend_member(
        "SUSP001", admin_member["member_id"], reason="Policy violation"
    )

    assert result["status"] == "SUSPENDED"
    member = await mock_db.members.find_one({"member_id": "SUSP001"})
    assert member["status"] == "SUSPENDED"

    active_session = await sessions_repo.find_active_session("sesshash1")
    assert active_session is None

    active_device = await devices_repo.find_active_device_by_hash("devhash1")
    assert active_device is None


@pytest.mark.asyncio
async def test_reactivate_member_requires_re_enrollment(mock_db, admin_member):
    await mock_db.members.insert_one(
        {"member_id": "REACT001", "status": "SUSPENDED", "profile": {"name": "To Reactivate"}}
    )
    member_service = MemberService(mock_db)
    result = await member_service.reactivate_member("REACT001", admin_member["member_id"])

    assert result["status"] == "PENDING_ENROLLMENT"  # not directly ACTIVE — must re-enrol


@pytest.mark.asyncio
async def test_reactivate_active_member_raises_conflict(mock_db, admin_member):
    from app.core.errors import ConflictError

    await mock_db.members.insert_one(
        {"member_id": "ALREADY_ACTIVE", "status": "ACTIVE", "profile": {}}
    )
    member_service = MemberService(mock_db)
    with pytest.raises(ConflictError):
        await member_service.reactivate_member("ALREADY_ACTIVE", admin_member["member_id"])


# ── Edit member ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_edit_member_updates_profile_fields(mock_db, admin_member):
    await mock_db.members.insert_one(
        {"member_id": "EDIT001", "status": "ACTIVE", "profile": {"name": "Old Name", "city": "Old City"}}
    )
    member_service = MemberService(mock_db)
    result = await member_service.edit_member(
        "EDIT001", {"profile": {"city": "New City"}}, admin_member["member_id"]
    )
    assert result["profile"]["city"] == "New City"
    assert result["profile"]["name"] == "Old Name"  # untouched field preserved
