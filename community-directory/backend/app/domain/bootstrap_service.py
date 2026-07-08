"""
Admin bootstrap service.

Creates the FIRST administrator account from environment variables, exactly once.
After bootstrap completes, the system_state collection records completion and
this process will never run again — even if the env vars are still present.

FR-ADM-001, FR-ADM-003: bootstrap only via env vars; no reset on restart.
"""
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import hash_password, utc_now
from app.domain.audit_service import AuditService

logger = get_logger(__name__)

BOOTSTRAP_STATE_KEY = "admin_bootstrap_completed"


async def run_admin_bootstrap(db) -> None:
    """
    Called once during app startup (see main.py lifespan).
    Idempotent: does nothing if bootstrap already completed or if members exist.
    """
    settings = get_settings()

    system_state = db.system_state
    existing_flag = await system_state.find_one({"key": BOOTSTRAP_STATE_KEY})

    if existing_flag and existing_flag.get("completed"):
        logger.info("Admin bootstrap already completed. Skipping.")
        return

    if not settings.admin_bootstrap_email or not settings.admin_bootstrap_password:
        logger.warning(
            "ADMIN_BOOTSTRAP_EMAIL / ADMIN_BOOTSTRAP_PASSWORD not set. "
            "No administrator will be created. Set these env vars and restart "
            "if this is the first deployment."
        )
        return

    if len(settings.admin_bootstrap_password) < 12:
        logger.error(
            "ADMIN_BOOTSTRAP_PASSWORD is too short (min 12 characters). "
            "Bootstrap aborted for safety."
        )
        return

    members = db.members
    email_normalized = settings.admin_bootstrap_email.strip().lower()

    already_exists = await members.find_one(
        {"registered_email_normalized": email_normalized}
    )
    if already_exists:
        logger.info("A member with the bootstrap admin email already exists. Skipping creation.")
        await system_state.update_one(
            {"key": BOOTSTRAP_STATE_KEY},
            {"$set": {"completed": True, "completed_at": utc_now()}},
            upsert=True,
        )
        return

    # Generate a secure random Member ID for the bootstrap admin
    import secrets
    member_id = "ADM-" + secrets.token_hex(4).upper()

    admin_doc = {
        "member_id": member_id,
        "registered_email_normalized": email_normalized,
        "registered_email": settings.admin_bootstrap_email,
        "password_hash": hash_password(settings.admin_bootstrap_password),
        "role": "admin",
        "status": "PENDING_ENROLLMENT",
        "profile": {"name": "System Administrator"},
        "visibility_settings": {},
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    await members.insert_one(admin_doc)

    audit = AuditService(db)
    await audit.log(
        actor="system",
        action="ADMIN_BOOTSTRAP_CREATED",
        target=member_id,
        after={"role": "admin", "status": "PENDING_ENROLLMENT"},
        reason="First administrator created from bootstrap environment variables.",
    )

    await system_state.update_one(
        {"key": BOOTSTRAP_STATE_KEY},
        {"$set": {"completed": True, "completed_at": utc_now(), "admin_member_id": member_id}},
        upsert=True,
    )

    logger.info(
        "Bootstrap administrator created with Member ID %s. "
        "Complete enrolment (OTP + passkey) via the standard enrolment flow to activate.",
        member_id,
    )
