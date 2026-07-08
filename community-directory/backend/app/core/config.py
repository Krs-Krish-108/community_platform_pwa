"""
Typed application settings loaded from environment variables.
Startup fails loudly if any mandatory secret is missing in production.
"""
from functools import lru_cache
from typing import List, Literal
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Runtime ──────────────────────────────────────────────
    app_mode: Literal["development", "production"] = "development"
    log_level: str = "INFO"
    app_version: str = "1.0.0"

    # ── Origins ──────────────────────────────────────────────
    app_origin: str = "http://localhost:5173"
    api_origin: str = "http://localhost:8000"
    cors_allowed_origins: str = "http://localhost:5173"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    # ── Database ─────────────────────────────────────────────
    mongodb_uri: str = "mongodb://localhost:27017"
    database_name: str = "community_directory"

    # ── Session Security ─────────────────────────────────────
    session_secret_key: str = "CHANGE_ME_generate_a_64_byte_hex_secret"
    device_token_secret_key: str = "CHANGE_ME_generate_another_64_byte_hex_secret"
    session_expire_hours: int = 24
    device_cookie_expire_days: int = 90

    # ── WebAuthn ─────────────────────────────────────────────
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "Community Directory"
    webauthn_origins: str = "http://localhost:5173"

    @property
    def webauthn_origins_list(self) -> List[str]:
        return [o.strip() for o in self.webauthn_origins.split(",") if o.strip()]

    # ── OTP ──────────────────────────────────────────────────
    otp_expire_minutes: int = 10
    otp_max_attempts: int = 5
    otp_resend_cooldown_seconds: int = 60
    otp_daily_cap: int = 10

    # ── Email ────────────────────────────────────────────────
    smtp_host: str = "smtp.resend.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    otp_from_email: str = "noreply@example.com"
    otp_from_name: str = "Community Directory"

    # ── Object Storage ───────────────────────────────────────
    object_storage_endpoint: str = ""
    object_storage_bucket: str = "community-media"
    object_storage_access_key: str = ""
    object_storage_secret_key: str = ""
    object_storage_public_base_url: str = ""

    # ── Media Limits ─────────────────────────────────────────
    media_max_image_mb: int = 5
    media_max_video_mb: int = 20
    media_signed_url_expire_seconds: int = 3600

    # ── Rate Limits ──────────────────────────────────────────
    rate_limit_identify_per_15min: int = 5
    rate_limit_otp_resend_per_hour: int = 5
    rate_limit_post_per_hour: int = 20

    # ── Admin Bootstrap ──────────────────────────────────────
    admin_bootstrap_email: str = ""
    admin_bootstrap_password: str = ""

    # ── Security Thresholds ───────────────────────────────────
    security_flag_otp_fail_threshold: int = 10
    security_flag_device_invalid_threshold: int = 5
    security_flag_identity_mismatch_threshold: int = 10

    # ── Polling Intervals ────────────────────────────────────
    inbox_poll_interval_ms: int = 45000
    emergency_poll_interval_ms: int = 15000

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        """In production, fail loudly if any mandatory secret is still the default."""
        if self.app_mode != "production":
            return self

        weak_defaults = {"CHANGE_ME", "change_me", ""}
        checks = {
            "SESSION_SECRET_KEY": self.session_secret_key,
            "DEVICE_TOKEN_SECRET_KEY": self.device_token_secret_key,
            "ADMIN_BOOTSTRAP_EMAIL": self.admin_bootstrap_email,
        }
        for name, value in checks.items():
            if any(value.upper().startswith(d.upper()) for d in weak_defaults):
                raise ValueError(
                    f"[STARTUP ERROR] {name} must be set to a real secret in production. "
                    "Server will not start with default or empty values."
                )

        if len(self.session_secret_key) < 32:
            raise ValueError(
                "SESSION_SECRET_KEY must be at least 32 characters. "
                "Generate with: python -c \"import secrets; print(secrets.token_hex(64))\""
            )

        return self

    @property
    def is_production(self) -> bool:
        return self.app_mode == "production"

    @property
    def is_development(self) -> bool:
        return self.app_mode == "development"


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance. Called once at startup."""
    return Settings()
