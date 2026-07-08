# Phase 3 — Protected Directory

## What was built

Three routes, all gated by the **full** access decision model
(`require_active_member`): valid session → active member → active device →
role → privacy projection. No route here accepts a session alone.

| Endpoint | Method | Description |
|---|---|---|
| `/api/members` | GET | Paginated, searchable, filterable directory (card-level fields only) |
| `/api/members/filters` | GET | Distinct values per filter category, for populating filter chips |
| `/api/members/{member_id}` | GET | Privacy-projected profile |

### Search & filters (FR-DIR-002/003)
- Free-text `q` searches name, city, state, organisation, occupation, about — case-insensitive, regex-escaped (no injection via special characters)
- Structured filters: `state`, `blood_group`, `occupation`, `education_sector`, `sub_caste`
- Filters and search combine with AND logic

### Pagination (FR-DIR-004)
- `page` / `page_size` query params, `page_size` hard-capped at 100 at the route schema level (422 if exceeded — not silently truncated)
- No endpoint ever returns an unrestricted raw dump

### Privacy projection (FR-DIR-005, SRS §8.2 matrix)

Three explicit projection functions — no single "god serializer":

| Viewer | What they see |
|---|---|
| **Directory card** (anyone) | Name, city, state, occupation, organisation — nothing else |
| **Another member** | Card fields + about/education, **plus** contact/blood-group/sub-caste/DOB only if the *target* member's `visibility_settings` opts in |
| **Self** | Everything, including pincode, marital status, gender — always, regardless of their own visibility settings (those settings control what *others* see) |
| **Admin** | Full profile + status + role — but never device/session/OTP/credential secrets, which live behind separate admin endpoints |

Sensitive fields (DOB, pincode, family, sub-caste) are **hidden by default** — a member must explicitly opt in via visibility settings before another member can see them.

## Important design note

Phase 3 builds the directory API against the **full** identity gate now,
even though OTP (Phase 4) and WebAuthn (Phase 5) don't exist yet. This
matches the Backend Blueprint's build order: establish the protected data
layer first, then layer identity on top. Tests simulate what Phases 4-5
will produce — an active session tied to an active device — by inserting
those records directly, so the authorization and privacy logic is fully
proven before the real enrolment flow is wired in.

## Tests — 33 new, 80 total, all passing

| Property | Test |
|---|---|
| No cookies → 401 | `test_directory_denied_without_any_cookies` |
| Session without device cookie → 403 DEVICE_NOT_APPROVED | `test_directory_denied_with_session_but_no_device_cookie` |
| Garbage session token → 401 SESSION_EXPIRED | `test_directory_denied_with_invalid_session_token` |
| Suspended member → 403 ACCOUNT_SUSPENDED | `test_directory_denied_for_suspended_member` |
| Revoked device → 403 DEVICE_NOT_APPROVED | `test_directory_denied_for_revoked_device` |
| Valid session+device → 200 with correct data | `test_directory_accessible_with_full_valid_auth` |
| STAGED/PENDING members never appear | `test_directory_excludes_staged_and_pending_members` |
| Card never leaks blood group/DOB/phone | `test_directory_card_never_contains_sensitive_fields` |
| Search text filters correctly | `test_directory_search_filters_by_text` |
| State filter works | `test_directory_filter_by_state` |
| page_size > 100 rejected (422) | `test_directory_page_size_rejected_above_hard_limit` |
| Filter options return distinct values | `test_directory_filters_endpoint_returns_distinct_values` |
| Other-member view hides unconsented sensitive fields | `test_profile_view_by_other_member_hides_sensitive_fields` |
| Self view shows own sensitive fields | `test_profile_self_view_shows_own_sensitive_fields` |
| Admin view sees full record | `test_profile_admin_view_sees_full_record` |
| Nonexistent / STAGED / PENDING member_id → 404 | 2 tests |
| Regex special characters in search are escaped | `test_search_text_is_regex_escaped` |

## A bug caught during this phase

The device/member ownership check inside `require_active_member` (written in
Phase 1, before the devices repository shape was finalized) compared a
Mongo `ObjectId` string against a `member_id` string — two different ID
spaces that could never match, followed by a second, differently-shaped
comparison meant to catch the real case. It happened to produce the right
answer by accident (the always-false first clause made the whole `and`
false whenever the real match succeeded), but it was fragile and confusing.
Simplified to a single direct comparison: `device["member_id"] ==
member["member_id"]`, which is what the repository actually stores.

## Try it locally

Once Phase 4/5 are built, real members will reach this point through
OTP + passkey enrolment. For now, you can exercise these routes exactly
the way the test suite does — insert an ACTIVE member, an ACTIVE device,
and a valid session directly, then call the API with the raw session/device
tokens as cookies.

## What's next — Phase 4

OTP + Sessions: registered-email identity verification, hashed OTP
challenges with expiry/attempt limits, and opaque server-side session
issuance — the real front door members will walk through before Phase 5
adds the passkey/device layer this phase's tests currently simulate.
