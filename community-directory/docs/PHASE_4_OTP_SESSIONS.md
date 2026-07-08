# Phase 4 — OTP + Sessions

## What was built

The real front door members will use to prove control of their registered
email — before Phase 5 adds the passkey/device layer.

| Endpoint | Method | Description |
|---|---|---|
| `/api/auth/identify` | POST | Member ID + email → generic response, may trigger OTP internally |
| `/api/auth/otp/verify` | POST | OTP code → enrollment ticket OR pending-approval status |

### One flow, two purposes

Both first-time enrolment and existing-member device changes share the
same identify + OTP mechanism, distinguished by the member's **current
status** at the moment of identification:

| Member status | Purpose | What happens on OTP success |
|---|---|---|
| `PENDING_ENROLLMENT` | `ENROLLMENT` | Issues a short-lived **enrollment ticket** — consumed by Phase 5's passkey registration |
| `ACTIVE` | `DEVICE_CHANGE` | Creates a `PENDING` device-change request — reviewed by the admin routes already built in Phase 2 |
| `STAGED`, `SUSPENDED`, `DEACTIVATED`, or no match | — | Generic response, **no OTP sent**, security event recorded |

### The non-negotiable rule this phase enforces

**OTP alone never creates a session or grants access.** This is tested
directly: after a successful enrollment OTP verification, the member's
status remains `PENDING_ENROLLMENT` and no session document is created.
The enrollment ticket is only a proof-of-OTP receipt for Phase 5 to
consume during passkey registration — it cannot be used to reach the
directory, post, or view profiles by itself.

Similarly, a device-change OTP verification creates a `PENDING` admin
request — it does not touch sessions or devices. The member's access
stays exactly as it was until an admin approves the change (Phase 2 routes)
and the member completes new passkey registration (Phase 5).

### OTP abuse controls (FR-AUTH-005/006/008)

- **Expiry**: configurable window (default 10 minutes)
- **Attempts**: max 5 wrong guesses per challenge, then it expires outright
- **Resend cooldown**: configurable (default 60s) — rapid resends are rate-limited
- **Daily cap**: configurable (default 10/day) — prevents email-bombing a target
- **Storage**: OTP is SHA-256 hashed; the raw value exists only in memory long enough to email it
- **Every failure is a security event**: wrong code, no active challenge, resend abuse, daily cap — all logged with safe metadata, never the OTP itself

### Generic responses (FR-AUTH-003)

`/api/auth/identify` returns the **exact same message** whether the
Member ID/email match a real record or not — verified with a direct
byte-for-byte comparison test between a real member and a fabricated one.

## A real bug caught and fixed here

Writing the resend-cooldown test surfaced a genuine bug: comparing
`utc_now()` (timezone-aware) against a datetime retrieved from MongoDB
(naive — BSON dates carry no timezone info) raised `TypeError: can't
subtract offset-naive and offset-aware datetimes`.

This wasn't a mock-only artifact — it would have failed identically
against a real MongoDB Atlas cluster unless the Motor client is
explicitly configured `tz_aware=True`. Fixed two ways for defense in depth:
1. `AsyncIOMotorClient(..., tz_aware=True)` in `core/database.py`
2. A new `ensure_aware()` helper in `core/security.py` that normalizes
   any retrieved datetime before arithmetic, so the code is safe even
   if a client/driver configuration ever changes.

## Tests — 30 new, 110 total, all passing

| Property | Test |
|---|---|
| Unknown member → silent, no OTP, security event logged | `test_identify_with_no_matching_record_completes_silently` |
| STAGED/SUSPENDED members never receive OTP | 2 tests |
| PENDING_ENROLLMENT → ENROLLMENT purpose OTP | `test_identify_for_pending_enrollment_member_sends_otp` |
| ACTIVE → DEVICE_CHANGE purpose OTP | `test_identify_for_active_member_sends_device_change_otp` |
| Right Member ID + wrong email → no OTP leaked | `test_identify_email_mismatch_for_real_member_does_not_send_otp` |
| 5 wrong OTPs → challenge expires (AT-003) | `test_verify_challenge_expires_after_max_attempts` |
| Resend cooldown enforced | `test_resend_within_cooldown_is_rate_limited` |
| Daily cap enforced | `test_daily_cap_enforced` |
| OTP success does NOT activate member or create session | `test_successful_enrollment_otp_does_not_activate_member_or_create_session` |
| Enrollment ticket stored only as hash | `test_enrollment_ticket_is_stored_only_as_hash` |
| Device-change OTP creates exactly one pending request (no duplicates) | `test_device_change_request_is_not_duplicated_on_repeat_verification` |
| Device-change OTP does not grant access | `test_device_change_does_not_grant_directory_access` |
| `/identify` returns byte-identical message for real vs fake member (AT-002) | `test_identify_endpoint_returns_same_message_for_real_member` |
| Full HTTP enrollment flow: identify → verify → ticket | `test_otp_verify_endpoint_full_enrollment_flow` |
| Full HTTP device-change flow: identify → verify → pending | `test_otp_verify_endpoint_device_change_flow` |

## What's next — Phase 5

Trusted Devices: WebAuthn/passkey registration (consuming the enrollment
ticket this phase issues) and login, the trusted-device cookie, and the
member-side device-change request creation this phase's admin approval
routes have been waiting for since Phase 2.
