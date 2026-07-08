"""
Cleanup jobs — background and manual data pruning utilities.
Prunes expired OTPs, expired sessions, revoked sessions beyond retention,
orphan media files, and stale pending device change requests.
"""
import uuid
from datetime import timedelta
from typing import Optional

from app.core.logging import get_logger
from app.core.security import utc_now

logger = get_logger(__name__)


class CleanupJobs:
    def __init__(self, db):
        self.db = db

    async def run_cleanup(self, job_id: Optional[str] = None) -> dict:
        """
        Execute pruning queries across all temporary collections.
        Returns a summary dictionary of deleted records.
        """
        jid = job_id or str(uuid.uuid4())
        logger.info("[Cleanup Job %s] Starting background cleanup run...", jid)
        
        now = utc_now()
        
        # 1. Expired OTP challenges (expired_at <= now)
        otp_res = await self.db["otp_challenges"].delete_many(
            {"expires_at": {"$lte": now}}
        )
        logger.info("[Cleanup Job %s] Pruned %d expired OTP challenges", jid, otp_res.deleted_count)

        # 2. Expired enrollment tickets (expired_at <= now)
        ticket_res = await self.db["enrollment_tickets"].delete_many(
            {"expires_at": {"$lte": now}}
        )
        logger.info("[Cleanup Job %s] Pruned %d expired enrollment tickets", jid, ticket_res.deleted_count)

        # 3. Expired sessions (expires_at <= now)
        session_res = await self.db["sessions"].delete_many(
            {"expires_at": {"$lte": now}}
        )
        logger.info("[Cleanup Job %s] Pruned %d expired sessions", jid, session_res.deleted_count)

        # 4. Revoked sessions older than 30 days retention
        retention_cutoff = now - timedelta(days=30)
        revoked_session_res = await self.db["sessions"].delete_many(
            {"revoked_at": {"$lte": retention_cutoff}}
        )
        logger.info(
            "[Cleanup Job %s] Pruned %d revoked sessions older than 30 days",
            jid,
            revoked_session_res.deleted_count,
        )

        # 5. Orphan media objects (unlinked, older than 24 hours)
        media_cutoff = now - timedelta(hours=24)
        media_res = await self.db["media_objects"].delete_many(
            {"linked_post_id": None, "created_at": {"$lte": media_cutoff}}
        )
        logger.info("[Cleanup Job %s] Pruned %d orphan media objects", jid, media_res.deleted_count)

        # 6. Stale pending device-change requests (pending, older than 30 days)
        req_cutoff = now - timedelta(days=30)
        req_res = await self.db["device_change_requests"].delete_many(
            {"status": "PENDING", "requested_at": {"$lte": req_cutoff}}
        )
        logger.info(
            "[Cleanup Job %s] Pruned %d stale pending device-change requests",
            jid,
            req_res.deleted_count,
        )

        logger.info("[Cleanup Job %s] Background cleanup run complete.", jid)
        
        return {
            "job_id": jid,
            "expired_otps": otp_res.deleted_count,
            "expired_tickets": ticket_res.deleted_count,
            "expired_sessions": session_res.deleted_count,
            "revoked_sessions": revoked_session_res.deleted_count,
            "orphan_media": media_res.deleted_count,
            "stale_device_requests": req_res.deleted_count,
        }
