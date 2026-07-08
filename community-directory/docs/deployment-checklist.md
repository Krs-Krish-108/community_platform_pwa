# Production Pilot Deployment Hardening Checklist

This checklist defines the security properties, configuration parameters, and verification audits required before launching the Verified Community Directory PWA pilot in a staging or production environment.

---

## 1. Environment & Cryptographic Secrets

- [ ] **App Mode Configuration**: Enforce `APP_MODE=production`. This activates loud startup validation and disables OpenAPI documentation routes (`/api/docs`, `/api/redoc`).
- [ ] **Unique High-Entropy Keys**:
  - `SESSION_SECRET_KEY` must be a cryptographically secure random value (at least 32 characters, recommended 64-byte hex).
  - `DEVICE_TOKEN_SECRET_KEY` must be set and distinct from the session secret key.
  - *Verification command*: `python -c "import secrets; print(secrets.token_hex(64))"`
- [ ] **Object Storage Access**:
  - Confirm cloud storage bucket (e.g. Cloudflare R2 / AWS S3) is active.
  - Enforce `OBJECT_STORAGE_ACCESS_KEY` and `OBJECT_STORAGE_SECRET_KEY` env variables are set (upload-intent URLs will fail if empty in production).

---

## 2. Production Startup Validation

The backend uses Pydantic settings validators to automatically crash the server on start if weak defaults are present in production:
- [ ] Ensure `SESSION_SECRET_KEY` does not contain defaults like `"CHANGE_ME"`.
- [ ] Ensure `DEVICE_TOKEN_SECRET_KEY` does not contain defaults like `"CHANGE_ME"`.
- [ ] Ensure `ADMIN_BOOTSTRAP_EMAIL` is set to the real email of the system bootstrap admin.
- [ ] Ensure the database has connection parameters set.

---

## 3. Security Headers Checklist

The backend injects standard security headers to protect browsers from clickjacking, MIME sniffing, and cross-site scripting:
- [ ] `X-Frame-Options: DENY` (prevents UI clickjacking).
- [ ] `X-Content-Type-Options: nosniff` (forces browser to respect content-type headers).
- [ ] `X-XSS-Protection: 1; mode=block` (activates browser XSS filters).
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` (masks referrer metadata).
- [ ] `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (enforced automatically in production to guarantee HTTPS).

---

## 4. Rate-limiting Guards

Ensure rate limits are configured to block automated scraping and credential attacks:
- [ ] `RATE_LIMIT_IDENTIFY_PER_15MIN`: Limit OTP requests per IP (default: 5 requests per 15 minutes).
- [ ] `RATE_LIMIT_OTP_RESEND_PER_HOUR`: Limit OTP verify codes per IP (default: 5 requests per hour).
- [ ] `RATE_LIMIT_POST_PER_HOUR`: Limit Inbox/Emergency creations to prevent spam (default: 20 per hour).

---

## 5. Database Indexes

The database initialization layer automatically checks and ensures these critical performance and uniqueness indexes exist in MongoDB:
- [ ] `members` -> `{ member_id: 1 }` (Unique)
- [ ] `members` -> `{ registered_email: 1 }` (Unique)
- [ ] `devices` -> `{ member_id: 1, status: 1 }`
- [ ] `sessions` -> `{ session_token_hash: 1 }` (Unique)
- [ ] `otp_challenges` -> `{ member_id: 1, purpose: 1, expires_at: 1 }`
- [ ] `posts` -> `{ type: 1, status: 1, created_at: -1 }` (Accelerates feed searches)

---

## 6. Backup & Retention Schedule

The system implements automated backup metadata and encryption routines:
- [ ] **Daily Encrypted Export**: Runs at night using `BackupJobs.run_backup()`. Serializes all collections, encrypts the output via AES-256 (Fernet) with a key derived from the session secret, and logs uploader details.
- [ ] **Weekly Offsite Archive**: Syncs `.enc` backups to secure cloud vaults.
- [ ] **Manual Backup Protocol**: Trigger `BackupJobs` immediately before initiating bulk imports (`/api/admin/imports/members`), running database migrations, or deploying code updates.

---

## 7. PWA Offline & Caching Constraints

To prevent leak of private data on shared devices:
- [ ] **App Shell Caching**: Configure the PWA service worker (`sw.js`) to cache **only static resources** (HTML index, stylesheet, frontend bundle, manifest.json, icons).
- [ ] **Private API Bypass**: Never cache endpoints under `/api/*` in the service worker.
- [ ] **Cache-Control Headers**: The backend automatically serves all directory, post, and session calls with:
  ```http
  Cache-Control: no-store, no-cache, must-revalidate, max-age=0
  ```
  Ensure local proxies or CDN layers (e.g. Cloudflare, Nginx) do not override these headers for API routes.
