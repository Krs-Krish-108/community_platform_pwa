"""
Security helpers: token generation, hashing, cookie construction.

Rules:
- Raw token values are NEVER stored or logged.
- Only HMAC-SHA256 hashes of tokens are stored in the database.
- Cookie values are opaque random bytes — browser JS cannot read them (HttpOnly).
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from app.core.config import get_settings

settings = get_settings()

# ── Token generation ──────────────────────────────────────────────────────────

def generate_opaque_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random token string."""
    return secrets.token_urlsafe(nbytes)


def generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP of the given length."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_token(token: str, key: str) -> str:
    """
    HMAC-SHA256 hash of a token using the given key.
    Used to store session/device tokens safely without storing the raw value.
    """
    return hmac.new(
        key.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_session_token(token: str) -> str:
    return hash_token(token, settings.session_secret_key)


def hash_device_token(token: str) -> str:
    return hash_token(token, settings.device_token_secret_key)


def hash_enrollment_ticket(token: str) -> str:
    """
    Enrollment tickets are hashed with the session key — they carry
    equivalent sensitivity (proof of a just-completed OTP verification)
    and share the session's short-lived, single-use lifecycle.
    """
    return hash_token(token, settings.session_secret_key)


def hash_otp(otp: str) -> str:
    """One-way hash for OTP storage. Uses SHA-256 (no key needed — OTPs are short-lived)."""
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def verify_otp_hash(otp: str, stored_hash: str) -> bool:
    """Constant-time comparison to verify an OTP against its stored hash."""
    return hmac.compare_digest(hash_otp(otp), stored_hash)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt (for admin accounts only)."""
    from passlib.context import CryptContext
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    from passlib.context import CryptContext
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    return _pwd_context.verify(plain, hashed)


# ── Cookie construction ───────────────────────────────────────────────────────

def make_session_cookie_params(token: str, expire_hours: int) -> dict:
    """
    Return kwargs for response.set_cookie() for the session cookie.
    HttpOnly + Secure + SameSite=Strict prevents JS access and CSRF.
    """
    expires = datetime.now(timezone.utc) + timedelta(hours=expire_hours)
    return dict(
        key="__Host-cd_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        expires=expires,
        domain=None,   # __Host- prefix requires no Domain attribute
    )


def make_device_cookie_params(token: str, expire_days: int) -> dict:
    """
    Return kwargs for response.set_cookie() for the trusted-device cookie.
    Long-lived but fully revocable via server-side device record.
    """
    expires = datetime.now(timezone.utc) + timedelta(days=expire_days)
    return dict(
        key="__Host-cd_device",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        expires=expires,
        domain=None,
    )


def clear_session_cookie_params() -> dict:
    return dict(
        key="__Host-cd_session",
        value="",
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=0,
    )


def clear_device_cookie_params() -> dict:
    return dict(
        key="__Host-cd_device",
        value="",
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
        max_age=0,
    )


# ── Expiry helpers ────────────────────────────────────────────────────────────

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime) -> datetime:
    """
    Normalize a datetime retrieved from MongoDB to be timezone-aware (UTC).
    BSON dates carry no timezone; depending on driver/mock configuration,
    retrieved datetimes may come back naive. MongoDB always stores UTC,
    so a naive datetime is always interpreted as UTC here.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def otp_expiry() -> datetime:
    return utc_now() + timedelta(minutes=settings.otp_expire_minutes)


def session_expiry() -> datetime:
    return utc_now() + timedelta(hours=settings.session_expire_hours)


def device_cookie_expiry() -> datetime:
    return utc_now() + timedelta(days=settings.device_cookie_expire_days)
