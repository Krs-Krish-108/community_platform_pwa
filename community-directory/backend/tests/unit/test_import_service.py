"""
Unit tests for app.domain.import_service — CSV parsing and validation.
Pure logic tests, no database required.
"""
from app.domain.import_service import parse_csv, _validate_row, _normalize_email


def test_parse_csv_basic():
    csv_text = "name,email\nJohn Doe,john@example.com\nJane Roe,jane@example.com\n"
    rows = parse_csv(csv_text)
    assert len(rows) == 2
    assert rows[0]["name"] == "John Doe"
    assert rows[0]["email"] == "john@example.com"


def test_parse_csv_normalizes_header_case_and_spaces():
    csv_text = "Name,Email Address\nJohn,john@example.com\n"
    rows = parse_csv(csv_text)
    assert "name" in rows[0]
    # "Email Address" -> "email_address" (not "email"), demonstrating normalization
    assert "email_address" in rows[0]


def test_parse_csv_skips_blank_rows():
    csv_text = "name,email\nJohn,john@example.com\n,,\nJane,jane@example.com\n"
    rows = parse_csv(csv_text)
    assert len(rows) == 2


def test_validate_row_requires_name():
    row = {"name": "", "email": "john@example.com"}
    error = _validate_row(row, 1)
    assert error is not None
    assert "name" in error.lower()


def test_validate_row_requires_email():
    row = {"name": "John", "email": ""}
    error = _validate_row(row, 1)
    assert error is not None
    assert "email" in error.lower()


def test_validate_row_rejects_malformed_email():
    row = {"name": "John", "email": "not-an-email"}
    error = _validate_row(row, 1)
    assert error is not None
    assert "invalid email" in error.lower()


def test_validate_row_accepts_valid_row():
    row = {"name": "John Doe", "email": "john@example.com"}
    error = _validate_row(row, 1)
    assert error is None


def test_normalize_email_lowercases_and_strips():
    assert _normalize_email("  John@EXAMPLE.com  ") == "john@example.com"
