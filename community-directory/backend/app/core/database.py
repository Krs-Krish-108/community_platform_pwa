"""
MongoDB connection lifecycle management using Motor (async driver).

The database instance is created once at app startup and stored in app.state.db.
All repositories receive this instance via the get_db() dependency.
"""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class Database:
    client: AsyncIOMotorClient = None
    db: AsyncIOMotorDatabase = None


_database = Database()


async def connect_to_mongo() -> AsyncIOMotorDatabase:
    """Establish MongoDB connection. Called once during app startup."""
    settings = get_settings()
    logger.info("Connecting to MongoDB at %s ...", _redact_uri(settings.mongodb_uri))

    _database.client = AsyncIOMotorClient(
        settings.mongodb_uri,
        serverSelectionTimeoutMS=5000,
        tz_aware=True,  # ensures retrieved datetimes are UTC-aware, matching utc_now()
    )
    _database.db = _database.client[settings.database_name]

    # Verify connectivity
    await _database.client.admin.command("ping")
    logger.info("MongoDB connection established. Database: %s", settings.database_name)

    return _database.db


async def close_mongo_connection() -> None:
    """Close MongoDB connection. Called during app shutdown."""
    if _database.client:
        _database.client.close()
        logger.info("MongoDB connection closed.")


async def ping_database() -> bool:
    """Health check helper — returns True if DB responds."""
    try:
        if _database.client is None:
            return False
        await _database.client.admin.command("ping")
        return True
    except Exception as exc:
        logger.error("Database ping failed: %s", exc)
        return False


def _redact_uri(uri: str) -> str:
    """Hide credentials in the connection string before logging."""
    if "@" in uri:
        scheme, rest = uri.split("://", 1)
        _, host_part = rest.split("@", 1)
        return f"{scheme}://***:***@{host_part}"
    return uri


async def create_indexes(db: AsyncIOMotorDatabase) -> None:
    """
    Create all required indexes. Idempotent — safe to call on every startup.
    Indexes are sourced from the Backend Blueprint §5.2.
    """
    logger.info("Ensuring database indexes...")

    # members
    await db.members.create_index("member_id", unique=True, sparse=True)
    await db.members.create_index("registered_email_normalized", unique=True, sparse=True)
    await db.members.create_index("status")

    # devices
    await db.devices.create_index("device_cookie_hash", unique=True, sparse=True)
    await db.devices.create_index("member_id")
    await db.devices.create_index("status")

    # webauthn_credentials
    await db.webauthn_credentials.create_index("credential_id", unique=True)
    await db.webauthn_credentials.create_index("member_id")

    # sessions
    await db.sessions.create_index("session_token_hash", unique=True)
    await db.sessions.create_index("expires_at", expireAfterSeconds=0)
    await db.sessions.create_index("member_id")

    # otp_challenges
    await db.otp_challenges.create_index("expires_at", expireAfterSeconds=0)
    await db.otp_challenges.create_index("member_id")

    # enrollment_tickets
    await db.enrollment_tickets.create_index("token_hash", unique=True)
    await db.enrollment_tickets.create_index("expires_at", expireAfterSeconds=0)
    await db.enrollment_tickets.create_index("member_id")

    # webauthn_challenges
    await db.webauthn_challenges.create_index("expires_at", expireAfterSeconds=0)
    await db.webauthn_challenges.create_index([("subject_type", 1), ("subject_id", 1), ("purpose", 1)])

    # device_change_requests
    await db.device_change_requests.create_index("member_id")
    await db.device_change_requests.create_index("status")

    # posts
    await db.posts.create_index([("type", 1), ("created_at", -1)])
    await db.posts.create_index([("author_member_id", 1), ("created_at", -1)])
    await db.posts.create_index("status")

    # media_objects
    await db.media_objects.create_index("owner_member_id")
    await db.media_objects.create_index("created_at")
    await db.media_objects.create_index("linked_post_id")

    # security_events
    await db.security_events.create_index([("created_at", -1)])
    await db.security_events.create_index("event_type")

    # security_flags
    await db.security_flags.create_index([("status", 1), ("severity", 1)])
    await db.security_flags.create_index([("created_at", -1)])

    # audit_logs
    await db.audit_logs.create_index([("actor", 1), ("created_at", -1)])
    await db.audit_logs.create_index("target")
    await db.audit_logs.create_index([("created_at", -1)])

    # import_runs
    await db.import_runs.create_index([("created_at", -1)])
    await db.import_runs.create_index("status")

    # system (bootstrap tracking)
    await db.system_state.create_index("key", unique=True)

    logger.info("Database indexes ready.")
