# Phase 2 — Admin Import & Member Management

## What was built

### Admin authentication (interim, Phases 2-4)
Administrators log in with email + password until WebAuthn/passkeys are
extended to admin accounts in Phase 5. This is a deliberate bridging
mechanism — regular members **never** use password login; they always go
through OTP + passkey (Phase 4-5).

| Endpoint | Method | Description |
|---|---|---|
| `/api/admin/auth/login` | POST | Email + password → session cookie |
| `/api/admin/auth/logout` | POST | Revoke current admin session |
| `/api/admin/auth/me` | GET | Current admin identity |

### CSV Import
| Endpoint | Method | Description |
|---|---|---|
| `/api/admin/imports/members` | POST | Upload CSV → validate → stage |
| `/api/admin/imports` | GET | List past import runs |

**Validation rules:**
- Required: `name`, `email`
- Email format validated, normalized (lowercase, trimmed)
- Duplicate emails rejected — both within the same file and against existing records
- Every row outcome (staged or rejected + reason) is preserved in `import_runs`
- Valid rows enter `STAGED` status — **never visible in the directory**

### Member Approval & Lifecycle
| Endpoint | Method | Description |
|---|---|---|
| `/api/admin/members/staged` | GET | List STAGED records awaiting approval |
| `/api/admin/members/staged/{id}/approve` | POST | Issue secure Member ID → `PENDING_ENROLLMENT` |
| `/api/admin/members/pending-enrollment` | GET | List approved members awaiting enrolment |
| `/api/admin/members/{member_id}` | PATCH | Edit profile fields |
| `/api/admin/members/{member_id}/suspend` | POST | Suspend — revokes all sessions & devices |
| `/api/admin/members/{member_id}/deactivate` | POST | Deactivate — revokes all sessions & devices |
| `/api/admin/members/{member_id}/reactivate` | POST | Reactivate → `PENDING_ENROLLMENT` (must re-enrol) |
| `/api/admin/members/export` | GET | Export all ACTIVE members (audited) |

**Secure Member ID generation (FR-IMP-005):**
- 8 characters, random alphabet excluding ambiguous characters (0/O, 1/I)
- Generated via `secrets.choice()` — cryptographically secure
- Verified unique against existing records before assignment
- **Never derived from name, email, or timestamp** — this was the #1 flaw in the legacy prototype's `makeId(name+timestamp)`

### Device Change Requests (admin approval side)
| Endpoint | Method | Description |
|---|---|---|
| `/api/admin/device-change-requests` | GET | List pending requests |
| `/api/admin/device-change-requests/{id}/approve` | POST | Approve → revoke old device/sessions |
| `/api/admin/device-change-requests/{id}/reject` | POST | Reject with reason |

*(Full request creation happens in Phase 5 when WebAuthn is wired for members. The admin approval side is ready now.)*

### Security & Audit
| Endpoint | Method | Description |
|---|---|---|
| `/api/admin/security-flags` | GET | List open security flags |
| `/api/admin/security-flags/{id}/resolve` | POST | Resolve with admin notes |
| `/api/admin/audit-logs` | GET | View audit trail (filterable by actor) |

## Security properties verified by tests

| Property | Test |
|---|---|
| Staged imports never leak into directory | `test_staged_members_not_visible_in_directory` |
| Member ID is random, not derived from name/timestamp | `test_generate_candidate_id_is_not_deterministic` |
| Duplicate emails rejected (in-file and cross-record) | `test_import_csv_rejects_duplicate_email_within_file`, `test_import_csv_rejects_email_already_in_system` |
| Double-approval blocked | `test_approve_already_approved_member_raises_conflict` |
| Every approval is audited | `test_approval_creates_audit_log_entry` |
| Admin login rejects wrong password / non-admins / suspended accounts | `test_admin_login_fails_*` (4 tests) |
| Failed admin login recorded as security event | `test_admin_login_records_security_event_on_failure` |
| Suspension immediately revokes sessions + devices | `test_suspend_member_revokes_sessions_and_devices` |
| Reactivation forces re-enrolment (no session/device restore) | `test_reactivate_member_requires_re_enrollment` |

**31 new tests, all passing.** Combined with Phase 1: **47 tests total.**

## Try it locally

```bash
cd backend
cp .env.example .env
# Edit .env: set ADMIN_BOOTSTRAP_EMAIL, ADMIN_BOOTSTRAP_PASSWORD, SESSION_SECRET_KEY, etc.
pip install -r requirements.txt
uvicorn app.main:app --reload
```

On first startup, the bootstrap admin is created automatically from your `.env` values.

```bash
# 1. Log in as the bootstrap admin
curl -c cookies.txt -X POST http://localhost:8000/api/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourdomain.com","password":"your-bootstrap-password"}'

# 2. Upload a CSV of members
curl -b cookies.txt -X POST http://localhost:8000/api/admin/imports/members \
  -F "file=@members.csv"

# 3. Review staged records
curl -b cookies.txt http://localhost:8000/api/admin/members/staged

# 4. Approve one
curl -b cookies.txt -X POST http://localhost:8000/api/admin/members/staged/{staged_id}/approve
```

## What's next — Phase 3

Protected Directory: session-gated search/filter/profile APIs with privacy
projections, replacing the legacy prototype's public Google Sheet fetch.
