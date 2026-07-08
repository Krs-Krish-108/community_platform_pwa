"""
Security service — records security events and aggregates them into admin-visible
security flags when thresholds are reached, preventing duplicate flag spam.
"""
from datetime import timedelta
from typing import Any, Dict, Optional

from app.core.config import get_settings
from app.core.security import utc_now
from app.repositories.security_repo import SecurityRepository, SecurityFlagsRepository


class SecurityService:
    def __init__(self, db):
        self.db = db
        self.events_repo = SecurityRepository(db)
        self.flags_repo = SecurityFlagsRepository(db)
        self.settings = get_settings()

    async def record_event(
        self,
        event_type: str,
        member_ref: Optional[str] = None,
        source_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Record a security event and evaluate threshold rules to aggregate them
        into an open security flag if a violation persists.
        """
        # 1. Save raw event
        event_id = await self.events_repo.record_event(
            event_type=event_type,
            member_ref=member_ref,
            source_hash=source_hash,
            metadata=metadata,
        )

        # 2. Get threshold based on configuration settings
        threshold = 5  # default fall-back threshold
        if event_type == "OTP_FAILED":
            threshold = self.settings.security_flag_otp_fail_threshold
        elif event_type == "DEVICE_TOKEN_INVALID":
            threshold = self.settings.security_flag_device_invalid_threshold
        elif event_type == "IDENTITY_MISMATCH":
            threshold = self.settings.security_flag_identity_mismatch_threshold
        elif event_type == "UNAUTHORIZED_POST_ATTEMPT":
            threshold = 3
        elif event_type == "MEDIA_REJECTED":
            threshold = 5

        # 3. Retrieve recent matching events in a sliding 1-hour window
        since = utc_now() - timedelta(hours=1)
        query: Dict[str, Any] = {
            "event_type": event_type,
            "created_at": {"$gte": since}
        }
        
        # Enforce scope checks on target key (either member ID or IP hash identifier)
        if member_ref:
            query["member_ref"] = member_ref
            target_ref = member_ref
        elif source_hash:
            query["source_hash"] = source_hash
            target_ref = source_hash
        else:
            target_ref = "unknown"

        cursor = self.events_repo.collection.find(query).sort("created_at", -1)
        recent_events = [doc async for doc in cursor]
        recent_count = len(recent_events)

        # 4. Trigger security flag creation/update if threshold is exceeded
        if recent_count >= threshold:
            rule_code = f"RULE_{event_type}"
            open_flag = await self.flags_repo.find_open_for_target(target_ref, rule_code)
            event_ids = [str(e["_id"]) for e in recent_events]

            if not open_flag:
                # Create a new open flag
                severity = "MEDIUM"
                if event_type in ("OTP_FAILED", "DEVICE_TOKEN_INVALID"):
                    severity = "HIGH"
                    
                await self.flags_repo.create_flag(
                    rule_code=rule_code,
                    severity=severity,
                    target_ref=target_ref,
                    evidence_event_ids=event_ids,
                )
            else:
                # Update existing open flag evidence list to avoid duplicate flag spam
                existing_ids = set(open_flag.get("evidence_event_ids", []))
                new_ids = [eid for eid in event_ids if eid not in existing_ids]
                if new_ids:
                    await self.flags_repo.collection.update_one(
                        {"_id": open_flag["_id"]},
                        {"$push": {"evidence_event_ids": {"$each": new_ids}}}
                    )

        return event_id
