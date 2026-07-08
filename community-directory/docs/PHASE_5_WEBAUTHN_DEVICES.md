# Phase 5 — Trusted Devices (WebAuthn/Passkeys)

## What was built

The passkey layer that turns Phase 4's enrollment tickets and Phase 3's
directory access gate into a real, working member experience — no more
IMEI, no more browser-generated IDs, no more localStorage.

| Endpoint | Method | Description |
|---|---|---|
| `/api/webauthn/register/options` | POST | Enrollment ticket → passkey creation options |
| `/api/webauthn/register/verify` | POST | Attestation → device + credential + **first session** |
| `/api/webauthn/login/options` | POST | Device cookie → passkey assertion options |
| `/api/webauthn/login/verify` | POST | Assertion → **new session** (routine daily login) |
| `/api/auth/me` | GET | Session validity + device-approval status |
| `/api/auth/logout` | POST | Ends session; device trust untouched |
| `/api/devices/current` | GET | Current device info |
| `/api/devices/change-request` | POST | Self-service "I'm getting a new phone" request |
| `/api/devices/current` | DELETE | Self-service device removal (lost/sold phone) |

### Registration flow

1. Member completes OTP (Phase 4) → receives an enrollment ticket
2. `register/options`: ticket validated, WebAuthn challenge generated and stored server-side, options returned to the browser
3. Browser prompts biometric/PIN, creates a passkey, returns an attestation
4. `register/verify`: attestation cryptographically verified → **only then**:
   - Device created with status `ACTIVE`
   - Credential's public key + signature counter stored
   - Member activated (`PENDING_ENROLLMENT` → `ACTIVE`)
   - First session issued, both session and device cookies set
   - If this followed an approved device-change request, that request is marked `COMPLETED`

### Login flow (routine, no OTP)

Uses the **trusted-device cookie** to identify which passkey to challenge —
the member never re-types their Member ID for daily access. If the device
cookie is missing or revoked, the member is routed back to the OTP/device-change
flow (Phase 4) instead.

### The device-change loop, closed

Phase 2 built admin approval. Phase 4 built the OTP trigger and pending
request creation. This phase closes the loop: `auth_service.verify_otp`
now checks whether a prior request was already `APPROVED` — if so, it
skips creating another pending request and issues a fresh enrollment
ticket directly, so the member can register their replacement passkey
immediately. Verified with `test_finish_registration_after_device_change_approval_marks_request_completed`.

## How the crypto boundary was tested

Generating a genuinely valid, signed WebAuthn attestation/assertion
requires either a real hardware security key or a browser's virtual
authenticator (Chrome DevTools Protocol) — neither is available in this
sandboxed backend environment. This matches the Backend Blueprint's own
test-layer design (§12.1): full ceremony E2E testing belongs to
Playwright + a virtual authenticator in Phase 8's hardening pass, not
backend unit tests.

Two testing strategies were used instead, cleanly separated at the
crypto boundary:

1. **Option generation is tested for real, no mocking** — `generate_registration_options`/`generate_authentication_options` are pure server-side construction with no authenticator involved. Verified: correct RP ID, correct user identity, sufficient challenge entropy, correct `allowCredentials` scoping.

2. **Verification is mocked at exactly one call** (`verify_registration_response` / `verify_authentication_response`) — this is `py_webauthn`'s own audited cryptography, not something this project should be re-certifying. Every piece of orchestration *around* that call is fully tested for real: ticket validity and single-use consumption, challenge single-use consumption, device/credential creation, member activation, session issuance, sign-count persistence, and status gating.

This is standard practice for testing code that wraps a well-established
crypto library — the same reason nobody re-tests bcrypt's hashing
correctness, only that their code calls it correctly.

## Properties proven by tests (27 new, 137 total)

| Property | Test |
|---|---|
| Valid ticket → correct WebAuthn options | `test_begin_registration_with_valid_ticket_returns_options` |
| Expired/invalid ticket rejected | 2 tests |
| Successful registration creates device+credential+session, activates member | `test_finish_registration_creates_device_credential_and_session` |
| Ticket AND challenge consumed exactly once | `test_finish_registration_consumes_ticket_and_challenge` |
| **Reused ticket rejected** (can't register two devices from one OTP) | `test_finish_registration_rejects_reused_ticket` |
| **Crypto failure does NOT consume the ticket** — member can retry | `test_finish_registration_does_not_consume_ticket_on_crypto_failure` |
| **Crypto failure does NOT activate the member** | same test |
| Post-device-change-approval registration closes the request | `test_finish_registration_after_device_change_approval_marks_request_completed` |
| No device cookie → login blocked | `test_begin_login_with_invalid_device_token_raises` |
| Successful login updates sign counter, issues session | `test_finish_login_updates_sign_count_and_creates_session` |
| **Suspended member blocked even with a valid, correctly-signed passkey** | `test_finish_login_blocks_suspended_member_despite_valid_passkey` |
| Revoked device blocked before any crypto check | `test_finish_login_with_revoked_device_raises` |
| Crypto failure at login creates NO session | `test_finish_login_does_not_create_session_on_crypto_failure` |
| Full HTTP registration flow sets both cookies correctly | `test_register_verify_endpoint_sets_cookies_and_activates_member` |
| Full HTTP login flow sets session cookie | `test_login_verify_endpoint_issues_session_cookie` |
| `/me` distinguishes "no session" from "session but device not approved" | 2 tests |
| Logout revokes session, device cookie untouched | `test_auth_logout_revokes_session` |
| Self-service device removal revokes device + all its sessions + clears both cookies | `test_devices_delete_current_clears_cookies_and_revokes` |

## What's next — Phase 6

Shared Communication: Inbox posts and Emergency alerts, stored centrally
and derived from the verified session (never a typed Member ID) —
replacing the legacy prototype's `localStorage`-only messaging with a
real, moderatable, auditable feed every verified member shares.
