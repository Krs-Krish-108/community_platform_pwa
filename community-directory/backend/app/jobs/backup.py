"""
Backup jobs — encrypted database exports and metadata tracking.
Extracts all MongoDB collections, encrypts JSON dumps with Fernet, and writes
metadata and audit entries.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
import base64
import hashlib
import json
import os
from cryptography.fernet import Fernet
from bson import ObjectId

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def json_serial(obj: Any) -> str:
    """JSON serializer for datetimes and ObjectIds."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable by default JSON encoder")


class BackupJobs:
    def __init__(self, db):
        self.db = db
        self.settings = get_settings()

    def _get_fernet(self) -> Fernet:
        """Derive a 32-byte url-safe base64 key from session_secret_key."""
        key_bytes = hashlib.sha256(self.settings.session_secret_key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(key_bytes)
        return Fernet(fernet_key)

    async def run_backup(self, actor: str, backup_dir: str = "./backups") -> dict:
        """
        Extract all collections, encrypt the payload, save it locally,
        and log metadata + audit history. Raises RuntimeError if the backup fails.
        """
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        backup_id = f"backup_{timestamp}"
        
        logger.info("[Backup %s] Initiating encrypted database export...", backup_id)
        
        collections = [
            "members", "devices", "webauthn_credentials", "sessions",
            "otp_challenges", "device_change_requests", "posts", "media_objects",
            "security_events", "security_flags", "audit_logs", "import_runs"
        ]
        
        db_dump = {}
        counts = {}
        
        try:
            # 1. Extract documents
            for col_name in collections:
                cursor = self.db[col_name].find({})
                docs = [doc async for doc in cursor]
                db_dump[col_name] = docs
                counts[col_name] = len(docs)
                
            # 2. Serialize to JSON string
            serialized = json.dumps(db_dump, default=json_serial)
            
            # 3. Encrypt data
            fernet = self._get_fernet()
            encrypted_bytes = fernet.encrypt(serialized.encode("utf-8"))
            
            # 4. Save to destination file
            os.makedirs(backup_dir, exist_ok=True)
            filename = f"{backup_id}.enc"
            filepath = os.path.abspath(os.path.join(backup_dir, filename))
            
            with open(filepath, "wb") as f:
                f.write(encrypted_bytes)
                
            status = "SUCCESS"
            error_message = None
            logger.info("[Backup %s] Database encrypted and saved to %s", backup_id, filepath)
            
        except Exception as e:
            status = "FAILED"
            error_message = str(e)
            filepath = None
            logger.exception("[Backup %s] Database export failed", backup_id)
            
        # 5. Record backup metadata
        meta_doc = {
            "backup_id": backup_id,
            "status": status,
            "filepath": filepath,
            "counts": counts,
            "error_message": error_message,
            "created_at": now,
            "created_by": actor,
        }
        await self.db["backup_runs"].insert_one(meta_doc)
        
        # 6. Audit log logging
        from app.domain.audit_service import AuditService
        await AuditService(self.db).log(
            actor=actor,
            action="BACKUP_RUN",
            target=backup_id,
            before=None,
            after={"status": status, "filepath": filepath, "document_counts": counts},
            reason=error_message,
        )
        
        if status == "FAILED":
            raise RuntimeError(f"Backup failed: {error_message}")
            
        return {
            "backup_id": backup_id,
            "status": status,
            "filepath": filepath,
            "document_counts": counts,
        }
