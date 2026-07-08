"""
Unit tests for app.domain.privacy_service — the privacy projection matrix.
Pure logic, no database required.
"""
from app.domain.privacy_service import (
    project_directory_card,
    project_profile_for_member,
    project_profile_for_admin,
    project_profile,
)


SAMPLE_MEMBER = {
    "member_id": "TARGET01",
    "registered_email": "target@example.com",
    "status": "ACTIVE",
    "role": "member",
    "profile": {
        "name": "Target Person",
        "city": "Lucknow",
        "state": "Uttar Pradesh",
        "occupation": "Engineer",
        "organisation": "ACME Corp",
        "education_sector": "Engineering",
        "about": "A community member.",
        "phone": "+91-9999999999",
        "blood_group": "O+",
        "sub_caste": "Brahmin Swarnkar",
        "dob": "1990-01-01",
        "pincode": "226001",
        "marital_status": "Single",
        "gender": "Male",
    },
    "visibility_settings": {},  # nothing opted in by default
}


def test_directory_card_contains_only_summary_fields():
    card = project_directory_card(SAMPLE_MEMBER)
    assert card["member_id"] == "TARGET01"
    assert card["name"] == "Target Person"
    assert card["city"] == "Lucknow"
    # Sensitive fields must NEVER appear at card level
    assert "phone" not in card
    assert "blood_group" not in card
    assert "dob" not in card
    assert "pincode" not in card
    assert "sub_caste" not in card


def test_other_member_view_hides_sensitive_fields_by_default():
    profile = project_profile_for_member(SAMPLE_MEMBER, viewer_is_self=False)
    # Basic fields visible
    assert profile["name"] == "Target Person"
    assert profile["occupation"] == "Engineer"
    # Sensitive fields hidden — no visibility_settings opt-in present
    assert "phone" not in profile
    assert "email" not in profile
    assert "blood_group" not in profile
    assert "sub_caste" not in profile
    assert "dob" not in profile
    # Always self-only, regardless of visibility settings
    assert "pincode" not in profile
    assert "marital_status" not in profile
    assert "gender" not in profile


def test_other_member_view_respects_opted_in_visibility():
    member = dict(SAMPLE_MEMBER)
    member["visibility_settings"] = {
        "show_contact": True,
        "show_blood_group": True,
        "show_dob": True,
    }
    profile = project_profile_for_member(member, viewer_is_self=False)
    assert profile["phone"] == "+91-9999999999"
    assert profile["email"] == "target@example.com"
    assert profile["blood_group"] == "O+"
    assert profile["dob"] == "1990-01-01"
    # Still hidden: sub_caste was not opted in
    assert "sub_caste" not in profile
    # Still hidden: family/pincode/gender are self-only, never via visibility settings
    assert "pincode" not in profile
    assert "gender" not in profile


def test_self_view_shows_everything_regardless_of_visibility_settings():
    profile = project_profile_for_member(SAMPLE_MEMBER, viewer_is_self=True)
    assert profile["phone"] == "+91-9999999999"
    assert profile["blood_group"] == "O+"
    assert profile["sub_caste"] == "Brahmin Swarnkar"
    assert profile["dob"] == "1990-01-01"
    assert profile["pincode"] == "226001"
    assert profile["marital_status"] == "Single"
    assert profile["gender"] == "Male"


def test_admin_view_includes_full_profile_and_status_but_no_secrets():
    admin_view = project_profile_for_admin(SAMPLE_MEMBER)
    assert admin_view["status"] == "ACTIVE"
    assert admin_view["registered_email"] == "target@example.com"
    assert admin_view["profile"]["blood_group"] == "O+"
    assert admin_view["profile"]["sub_caste"] == "Brahmin Swarnkar"
    # Admin profile view never includes device/session/OTP/credential secrets
    assert "password_hash" not in admin_view
    assert "session_token_hash" not in admin_view
    assert "device_cookie_hash" not in admin_view


def test_project_profile_routes_by_role_admin():
    result = project_profile(SAMPLE_MEMBER, viewer_member_id="ADM01", viewer_role="admin")
    assert "registered_email" in result  # admin-shape response


def test_project_profile_routes_by_role_member_other():
    result = project_profile(SAMPLE_MEMBER, viewer_member_id="OTHER01", viewer_role="member")
    assert "phone" not in result  # not opted in, not self


def test_project_profile_routes_by_role_member_self():
    result = project_profile(SAMPLE_MEMBER, viewer_member_id="TARGET01", viewer_role="member")
    assert result["phone"] == "+91-9999999999"  # self always sees own contact
