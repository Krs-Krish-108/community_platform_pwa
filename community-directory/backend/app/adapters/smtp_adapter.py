"""
SMTP adapter — sends OTP emails via an SMTP-compatible provider (Resend, etc.).

Security rule (SEC-005): OTP values are NEVER logged in production. In
development mode only, the OTP is also printed to the console so local
testing doesn't require a real inbox — this path is clearly gated and
cannot fire when APP_MODE=production.
"""
import aiosmtplib
from email.message import EmailMessage

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class SMTPAdapter:
    def __init__(self):
        self.settings = get_settings()

    def _build_otp_message(self, to_email: str, otp: str) -> EmailMessage:
        message = EmailMessage()
        message["From"] = f"{self.settings.otp_from_name} <{self.settings.otp_from_email}>"
        message["To"] = to_email
        message["Subject"] = "Your verification code"
        message.set_content(
            f"Your Community Directory verification code is: {otp}\n\n"
            f"This code expires in {self.settings.otp_expire_minutes} minutes. "
            f"If you did not request this code, you can safely ignore this email."
        )
        return message

    async def send_otp_email(self, to_email: str, otp: str) -> None:
        if self.settings.is_development:
            # Development convenience ONLY — never reachable in production
            # (is_development is False whenever APP_MODE=production).
            logger.info(
                "[DEV ONLY] OTP email to %s — code: %s (would be sent via SMTP in production)",
                to_email, otp,
            )
            return

        message = self._build_otp_message(to_email, otp)
        try:
            await aiosmtplib.send(
                message,
                hostname=self.settings.smtp_host,
                port=self.settings.smtp_port,
                username=self.settings.smtp_username,
                password=self.settings.smtp_password,
                start_tls=True,
            )
            logger.info("OTP email dispatched to %s", to_email)
        except Exception as exc:
            # Never log the OTP value itself, even on failure.
            logger.error("Failed to send OTP email to %s: %s", to_email, exc)
            raise
