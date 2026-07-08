"""
Privacy projection service.

Implements the Privacy Projection Matrix (SRS §8.2 / PRD §7):

    Data category                          | Member viewing another | Admin
    ----------------------------------------|-------------------------|-------
    Directory card                          | Name, photo/initials,   | All approved
                                             | city/state, summary     | card fields
    Contact details                         | Only if target permits  | Full access
    Education and profession                | Permitted profile fields| Full record
    Blood group                             | Only if policy enables  | Visible
    DOB, pincode, family, spouse, caste      | Hidden by default       | Admin-only
    Device/security/OTP/audit records       | Never visible           | Admin only

Rule (Backend Blueprint §7.3): do not write one giant serializer reused
everywhere. Explicit projection functions per viewer/purpose.
"""
from typing import Any, Dict, Optional


def _profile(member: Dict[str, Any]) -> Dict[str, Any]:
    return member.get("profile", {}) or {}


def _visibility(member: Dict[str, Any]) -> Dict[str, Any]:
    return member.get("visibility_settings", {}) or {}


def project_directory_card(member: Dict[str, Any]) -> Dict[str, Any]:
    """
    Card-level fields shown in the paginated directory list.
    Same for every verified member viewer — no per-target visibility needed
    at card level (only name, location, and profession summary).
    """
    profile = _profile(member)
    return {
        "member_id": member.get("member_id"),
        "name": profile.get("name"),
        "city": profile.get("city"),
        "state": profile.get("state"),
        "occupation": profile.get("occupation"),
        "organisation": profile.get("organisation"),
        "updated_at": member.get("updated_at"),
    }


def project_profile_for_member(
    member: Dict[str, Any], viewer_is_self: bool
) -> Dict[str, Any]:
    """
    Full profile view as seen by another verified member (or by the member
    themself, in which case sensitive self-only fields are also included).
    """
    profile = _profile(member)
    visibility = _visibility(member)

    result: Dict[str, Any] = {
        "member_id": member.get("member_id"),
        "name": profile.get("name"),
        "city": profile.get("city"),
        "state": profile.get("state"),
        "occupation": profile.get("occupation"),
        "organisation": profile.get("organisation"),
        "education_sector": profile.get("education_sector"),
        "about": profile.get("about"),
    }

    # Contact details: only if target member's visibility settings permit,
    # or the viewer is looking at their own profile.
    if viewer_is_self or visibility.get("show_contact"):
        result["phone"] = profile.get("phone")
        result["email"] = member.get("registered_email")

    # Blood group: opt-in field.
    if viewer_is_self or visibility.get("show_blood_group"):
        result["blood_group"] = profile.get("blood_group")

    # Sub-caste: admin-only by default per policy; requires explicit consent.
    if viewer_is_self or visibility.get("show_sub_caste"):
        result["sub_caste"] = profile.get("sub_caste")

    # DOB: hidden by default.
    if viewer_is_self or visibility.get("show_dob"):
        result["dob"] = profile.get("dob")

    # Self-only sensitive fields — never shown to other members regardless
    # of visibility settings (family, pincode, marital status, gender).
    if viewer_is_self:
        result["pincode"] = profile.get("pincode")
        result["marital_status"] = profile.get("marital_status")
        result["gender"] = profile.get("gender")

    return result


def project_profile_for_admin(member: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full administrative view. Includes every profile field and visibility
    settings, but NEVER device/session/OTP/credential secrets — those live
    in separate collections the admin views through dedicated endpoints
    (device-change-requests, security-flags, audit-logs), not the profile API.
    """
    profile = dict(_profile(member))
    return {
        "member_id": member.get("member_id"),
        "registered_email": member.get("registered_email"),
        "status": member.get("status"),
        "role": member.get("role"),
        "profile": profile,
        "visibility_settings": _visibility(member),
        "created_at": member.get("created_at"),
        "updated_at": member.get("updated_at"),
    }


def project_profile(
    member: Dict[str, Any],
    viewer_member_id: str,
    viewer_role: str,
) -> Dict[str, Any]:
    """
    Single entry point routes to the correct projection based on viewer role
    and whether the viewer is looking at their own record.
    """
    if viewer_role == "admin":
        return project_profile_for_admin(member)

    viewer_is_self = viewer_member_id == member.get("member_id")
    return project_profile_for_member(member, viewer_is_self)
