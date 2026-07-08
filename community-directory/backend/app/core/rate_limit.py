"""
Rate limiting.

MVP implementation uses in-memory storage (sufficient for single-instance pilot).
The interface is designed so the storage backend can be swapped to Redis without
changing any route or service code — just replace InMemoryRateLimitStore.

Usage:
    limiter = RateLimiter(key="identify", max_calls=5, window_seconds=900)
    await limiter.check(request)   # raises RateLimitExceeded if over limit
"""
import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from fastapi import Request

from app.core.errors import RateLimitExceeded
from app.core.logging import get_logger

logger = get_logger(__name__)


# ── Storage interface ─────────────────────────────────────────────────────────

class InMemoryRateLimitStore:
    """
    Thread-safe in-memory rate limit store.
    Stores call timestamps per (key, identifier) pair.
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        # {bucket_key: [timestamp, ...]}
        self._store: Dict[str, List[float]] = defaultdict(list)

    async def record_and_check(
        self, bucket: str, window_seconds: int, max_calls: int
    ) -> bool:
        """
        Record a call for `bucket`. Return True if within limit, False if exceeded.
        Automatically evicts timestamps older than the window.
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            timestamps = self._store[bucket]
            # Evict old entries
            self._store[bucket] = [t for t in timestamps if t > cutoff]
            if len(self._store[bucket]) >= max_calls:
                return False
            self._store[bucket].append(now)
            return True

    async def reset(self, bucket: str) -> None:
        async with self._lock:
            self._store.pop(bucket, None)


# Singleton store — shared across all limiters in the process
_store = InMemoryRateLimitStore()


# ── Rate limiter ──────────────────────────────────────────────────────────────

@dataclass
class RateLimiter:
    """
    Callable rate limiter. Use as a FastAPI dependency or call directly.

    Args:
        key:             Policy name (e.g. "identify", "otp_verify").
        max_calls:       Maximum allowed calls within the window.
        window_seconds:  Sliding window duration in seconds.
    """
    key: str
    max_calls: int
    window_seconds: int

    def _get_identifier(self, request: Request) -> str:
        """
        Build a per-request identifier from the client IP.
        X-Forwarded-For is read only when the deployment is known to set it correctly.
        """
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first (client) IP from the chain
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def check(self, request: Request) -> None:
        """
        Check the rate limit for this request. Raises RateLimitExceeded if over limit.
        Call this at the start of any rate-limited route handler.
        """
        identifier = self._get_identifier(request)
        bucket = f"{self.key}:{identifier}"

        allowed = await _store.record_and_check(
            bucket=bucket,
            window_seconds=self.window_seconds,
            max_calls=self.max_calls,
        )

        if not allowed:
            logger.warning(
                "Rate limit exceeded: policy=%s identifier=%s",
                self.key,
                identifier,
            )
            raise RateLimitExceeded()

    async def reset(self, request: Request) -> None:
        identifier = self._get_identifier(request)
        bucket = f"{self.key}:{identifier}"
        await _store.reset(bucket)


# ── Pre-configured limiters (used across routes) ──────────────────────────────

from app.core.config import get_settings as _get_settings

def _s() -> "Settings":  # lazy to avoid circular import
    return _get_settings()


def identify_limiter() -> RateLimiter:
    s = _s()
    return RateLimiter("identify", s.rate_limit_identify_per_15min, 15 * 60)


def otp_resend_limiter() -> RateLimiter:
    s = _s()
    return RateLimiter("otp_resend", s.rate_limit_otp_resend_per_hour, 3600)


def post_limiter() -> RateLimiter:
    s = _s()
    return RateLimiter("post_create", s.rate_limit_post_per_hour, 3600)


def admin_login_limiter() -> RateLimiter:
    # Reuses the identify policy — same enumeration/brute-force risk profile
    s = _s()
    return RateLimiter("admin_login", s.rate_limit_identify_per_15min, 15 * 60)


def otp_verify_limiter() -> RateLimiter:
    # IP-level guard distinct from the per-challenge attempt counter —
    # protects against an attacker rotating member_id/otp guesses rapidly.
    s = _s()
    return RateLimiter("otp_verify", s.rate_limit_identify_per_15min, 15 * 60)
