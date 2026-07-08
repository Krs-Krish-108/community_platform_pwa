"""
Unit tests for CORS configuration and Cookie security settings.
"""
from app.core.config import Settings
from app.core.security import make_session_cookie_params, make_device_cookie_params


def test_cors_origins_parsing():
    # Single origin
    settings = Settings(cors_allowed_origins="http://localhost:3000")
    assert settings.cors_origins_list == ["http://localhost:3000"]

    # Multiple origins with spaces and trailing commas
    settings = Settings(cors_allowed_origins=" http://localhost:3000, http://192.168.1.100:3000 , ")
    assert settings.cors_origins_list == ["http://localhost:3000", "http://192.168.1.100:3000"]


def test_cookie_security_properties():
    # Session cookie properties
    session_params = make_session_cookie_params("test_token", expire_hours=24)
    assert session_params["key"] == "__Host-cd_session"
    assert session_params["httponly"] is True
    assert session_params["secure"] is True
    assert session_params["samesite"] == "strict"
    assert session_params["path"] == "/"
    assert session_params["domain"] is None

    # Device cookie properties
    device_params = make_device_cookie_params("test_token", expire_days=90)
    assert device_params["key"] == "__Host-cd_device"
    assert device_params["httponly"] is True
    assert device_params["secure"] is True
    assert device_params["samesite"] == "strict"
    assert device_params["path"] == "/"
    assert device_params["domain"] is None
