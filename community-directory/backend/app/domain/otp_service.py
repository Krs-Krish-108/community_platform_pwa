"""
OTP service — challenge lifecycle: issue, verify, attempt limits, resend
cooldown, daily cap. Purpose-agnostic (works for ENROLLMENT and
DEVICE_CHANGE) since the rules are identical either way.

FR-AUTH-005: expiry configurable within 5-10 min window, max 5 attempts.
FR-AUTH-006: resend cooldown 30-60s, daily request cap.
FR-AUTH-007: OTP stored only as one-way hash, invalidated after use/expiry.
FR-AUTH-008: failed identity checks, invalid OTP attempts, resend abuse recorded.
"""
from app.core.config import get_settings
from app.core.errors import OTPExpired, OTPMaxAttempts, OTPError, RateLimitExceeded
from app.core.logging import get_logger
from app.core.security import generate_otp, hash_otp, verify_otp_hash, utc_now, ensure_aware
from app.repositories.otp_repo import OTPRepository
from app.domain.security_service import SecurityService

logger = get_logger(__name__)


class OTPService:
    def __init__(self, db):
        self.db = db
        self.otp_repo = OTPRepository(db)
        self.security_service = SecurityService(db)
        self.settings = get_settings()

    async def issue_challenge(self, member_id: str, purpose: str) -> str:
        """
        Create a new OTP challenge, enforcing daily cap and resend cooldown.
        Returns the RAW otp (caller is responsible for emailing it — never
        logging or storing it in plaintext beyond this return value).
        """
        count_today = await self.otp_repo.count_today(member_id, purpose)
        if count_today >= self.settings.otp_daily_cap:
            await self.security_service.record_event(
                event_type="OTP_RESEND_ABUSE",
                member_ref=member_id,
                metadata={"reason": "daily_cap_exceeded", "purpose": purpose},
            )
            raise RateLimitExceeded(
                detail="Daily verification code limit reached. Please try again tomorrow "
                "or contact an administrator."
            )

        last = await self.otp_repo.find_last_challenge_any_state(member_id, purpose)
        if last:
            elapsed_seconds = (utc_now() - ensure_aware(last["created_at"])).total_seconds()
            if elapsed_seconds < self.settings.otp_resend_cooldown_seconds:
                await self.security_service.record_event(
                    event_type="OTP_RESEND_ABUSE",
                    member_ref=member_id,
                    metadata={"reason": "cooldown_active", "purpose": purpose},
                )
                raise RateLimitExceeded(
                    detail="Please wait before requesting another code."
                )

        otp = generate_otp(6)
        otp_hash = hash_otp(otp)
        await self.otp_repo.create_challenge(member_id, purpose, otp_hash)

        logger.info("OTP challenge issued for member_id=%s purpose=%s", member_id, purpose)
        return otp

    async def verify_challenge(self, member_id: str, purpose: str, submitted_otp: str) -> None:
        """
        Verify a submitted OTP against the active challenge.
        Raises OTPExpired / OTPMaxAttempts / OTPError on failure.
        On success, marks the challenge consumed (single-use).
        """
        challenge = await self.otp_repo.find_active_challenge(member_id, purpose)
        if not challenge:
            await self.security_service.record_event(
                event_type="OTP_FAILED",
                member_ref=member_id,
                metadata={"reason": "no_active_challenge", "purpose": purpose},
            )
            raise OTPExpired()

        attempts = challenge.get("attempts", 0)
        if attempts >= self.settings.otp_max_attempts:
            await self.otp_repo.expire_challenge(challenge["_id"])
            raise OTPMaxAttempts()

        if not verify_otp_hash(submitted_otp, challenge["otp_hash"]):
            new_attempts = await self.otp_repo.increment_attempts(challenge["_id"])
            await self.security_service.record_event(
                event_type="OTP_FAILED",
                member_ref=member_id,
                metadata={"reason": "wrong_code", "purpose": purpose, "attempts": new_attempts},
            )
            if new_attempts >= self.settings.otp_max_attempts:
                await self.otp_repo.expire_challenge(challenge["_id"])
                raise OTPMaxAttempts()
            raise OTPError()

        await self.otp_repo.consume_challenge(challenge["_id"])
        logger.info("OTP verified successfully for member_id=%s purpose=%s", member_id, purpose)
