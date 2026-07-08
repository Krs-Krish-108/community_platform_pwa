# Verified Community Directory PWA

A secure, private, administrator-controlled community platform where only approved members
can discover verified profiles, share Inbox updates, raise Emergency alerts, and access
the system from an approved device.

## Architecture

```
frontend/    → React + TypeScript + Vite PWA (mobile-first)
backend/     → Python FastAPI (modular monolith)
legacy-ui-reference/  → Original prototype (UI reference only — NOT production)
docs/        → Architecture and API documentation
```

## Tech Stack

| Layer        | Choice                            |
|--------------|-----------------------------------|
| Frontend     | React 18 + TypeScript + Vite      |
| PWA          | vite-plugin-pwa + Workbox         |
| Backend API  | Python FastAPI                    |
| Database     | MongoDB Atlas (Motor async driver)|
| Auth         | Opaque server-side sessions + WebAuthn/Passkeys |
| OTP          | Email via SMTP (Resend/Gmail)     |
| Media        | Cloudflare R2 (S3-compatible)     |
| Deployment   | Docker + Render/Cloud Run (backend), Vercel/Netlify (frontend) |

## Build Phases

| Phase | Focus                        | Status  |
|-------|------------------------------|---------|
| 0     | Legacy freeze                | ✅ Done  |
| 1     | Backend foundation           | ✅ Done  |
| 2     | Admin import & member mgmt   | ✅ Done  |
| 3     | Protected directory          | ✅ Done  |
| 4     | OTP + sessions               | ✅ Done  |
| 5     | Trusted devices (WebAuthn)   | ✅ Done  |
| 6     | Shared Inbox + Emergency     | 🔜 Next  |
| 7     | Security operations          | ⏳       |
| 8     | PWA hardening + pilot        | ⏳       |

## Quick Start

### Backend

```bash
cd backend
cp .env.example .env        # fill in your secrets
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Docker (full stack)

```bash
docker-compose up --build
```

## Security Rules (Non-Negotiable)

- No public Google Sheet CSV endpoint in any production code
- No real member data in frontend source, fallback arrays, or service-worker cache
- No browser-generated Member IDs
- No typed Member ID as proof of identity
- No localStorage-based shared Inbox or Emergency persistence
- No OTP-only activation for a new device
- No frontend-only authorization or role checks
- No admin action without an audit log entry

## Folder Structure

```
community-directory/
├── backend/
│   ├── app/
│   │   ├── api/          ← HTTP route handlers (thin)
│   │   ├── core/         ← Config, security helpers, dependencies, errors
│   │   ├── domain/       ← Business services (OTP, WebAuthn, members, posts…)
│   │   ├── repositories/ ← Database access layer
│   │   ├── schemas/      ← Pydantic request/response models
│   │   ├── jobs/         ← Background tasks (cleanup, imports)
│   │   ├── adapters/     ← SMTP, object storage wrappers
│   │   └── main.py
│   ├── tests/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── pages/        ← Route-level screen components
│   │   ├── components/   ← Reusable UI pieces
│   │   ├── services/     ← API client modules
│   │   ├── hooks/        ← Custom React hooks
│   │   └── pwa/          ← Service worker + manifest helpers
│   ├── public/
│   └── package.json
├── legacy-ui-reference/  ← Original prototype (READ ONLY — UI reference)
├── docs/
├── docker-compose.yml
└── README.md
```
