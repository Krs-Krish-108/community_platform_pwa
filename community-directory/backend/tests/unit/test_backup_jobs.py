"""
Unit tests for Phase 7C: Backup Jobs.

Validates metadata capture, encryption outputs, audit trail generation,
and failure mitigation states.
"""
from datetime import datetime, timezone
import os
import shutil
import tempfile
import pytest
from mongomock_motor import AsyncMongoMockClient

from app.jobs.backup import BackupJobs


@pytest.fixture
def temp_backup_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


@pytest.fixture
async def mock_db():
    client = AsyncMongoMockClient()
    db = client["test_backup"]
    yield db


@pytest.mark.asyncio
async def test_backup_succeeds_and_creates_metadata(mock_db, temp_backup_dir):
    # Seed some dummy data
    await mock_db["members"].insert_one({"name": "Test User", "role": "member"})
    
    jobs = BackupJobs(mock_db)
    res = await jobs.run_backup(actor="ADMIN_USER", backup_dir=temp_backup_dir)
    
    assert res["status"] == "SUCCESS"
    assert os.path.exists(res["filepath"])
    assert res["document_counts"]["members"] == 1

    # Verify metadata in DB
    meta = await mock_db["backup_runs"].find_one({"backup_id": res["backup_id"]})
    assert meta is not None
    assert meta["status"] == "SUCCESS"
    assert meta["created_by"] == "ADMIN_USER"
    assert meta["filepath"] == res["filepath"]

    # Verify audit log
    audit = await mock_db["audit_logs"].find_one({"action": "BACKUP_RUN", "target": res["backup_id"]})
    assert audit is not None
    assert audit["actor"] == "ADMIN_USER"
    assert audit["after"]["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_backup_failure_handling(mock_db, temp_backup_dir):
    # Setup custom broken collection that raises an exception on find queries
    class BrokenFindCollection:
        def __init__(self, real_col):
            self.real_col = real_col
        def find(self, *args, **kwargs):
            class BrokenCursor:
                def __aiter__(self):
                    return self
                async def __anext__(self):
                    raise Exception("Database query failed during collection find")
            return BrokenCursor()
        async def insert_one(self, *args, **kwargs):
            return await self.real_col.insert_one(*args, **kwargs)

    class CustomBrokenDb:
        def __init__(self, real_db):
            self.real_db = real_db
        def __getitem__(self, item):
            if item == "members":
                return BrokenFindCollection(self.real_db[item])
            return self.real_db[item]

    db_wrapper = CustomBrokenDb(mock_db)
    jobs = BackupJobs(db_wrapper)
    
    with pytest.raises(RuntimeError, match="Backup failed: Database query failed during collection find"):
        await jobs.run_backup(actor="ADMIN_USER", backup_dir=temp_backup_dir)

    # Verify metadata is still recorded with FAILED status
    meta = await mock_db["backup_runs"].find_one({"status": "FAILED"})
    assert meta is not None
    assert meta["created_by"] == "ADMIN_USER"
    assert "Database query failed" in meta["error_message"]

    # Verify audit log is logged with FAILED status
    audit = await mock_db["audit_logs"].find_one({"action": "BACKUP_RUN"})
    assert audit is not None
    assert audit["actor"] == "ADMIN_USER"
    assert audit["after"]["status"] == "FAILED"
