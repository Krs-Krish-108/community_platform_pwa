"""
Unit tests for app.core.security — token generation, hashing, OTP verification.
No database or network required.
"""
import pytest

from app.core.security import (
    generate_opaque_token,
    generate_otp,
    hash_token,
    hash_otp,
    verify_otp_hash,
    hash_password,
    verify_password,
)


def test_generate_opaque_token_is_url_safe_and_unique():
    t1 = generate_opaque_token()
    t2 = generate_opaque_token()
    assert t1 != t2
    assert len(t1) > 20


def test_generate_otp_length_and_numeric():
    otp = generate_otp(6)
    assert len(otp) == 6
    assert otp.isdigit()


def test_hash_token_deterministic_with_same_key():
    token = "sometoken123"
    key = "supersecretkey"
    h1 = hash_token(token, key)
    h2 = hash_token(token, key)
    assert h1 == h2


def test_hash_token_differs_with_different_key():
    token = "sometoken123"
    h1 = hash_token(token, "key1")
    h2 = hash_token(token, "key2")
    assert h1 != h2


def test_otp_hash_verification_succeeds_for_correct_otp():
    otp = "123456"
    stored_hash = hash_otp(otp)
    assert verify_otp_hash(otp, stored_hash) is True


def test_otp_hash_verification_fails_for_wrong_otp():
    stored_hash = hash_otp("123456")
    assert verify_otp_hash("999999", stored_hash) is False


def test_password_hash_and_verify_roundtrip():
    password = "correct-horse-battery-staple"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong-password", hashed) is False
