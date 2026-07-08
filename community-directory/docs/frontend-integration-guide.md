# Frontend Integration Guide

This guide explains how to integrate the React frontend application with the secure FastAPI backend. It covers CORS configurations, cookie security rules, local development troubleshooting, and verification checks.

---

## 1. CORS Configuration

The backend implements standard Cross-Origin Resource Sharing (CORS) middleware to allow the frontend web application to make requests across ports and domains.

### Environment Configuration
* **Environment Variable**: `CORS_ALLOWED_ORIGINS`
* **Default Value**: `http://localhost:5173`
* **Syntax**: A comma-separated list of origins. For example:
  ```env
  CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000,https://app.communitydirectory.org
  ```

### Backend CORS Settings
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,  # Essential for HttpOnly cookies transport
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-ID"],
)
```

---

## 2. Cookie Transport & Security

To prevent Cross-Site Scripting (XSS) and Session Hijacking, the backend does not return raw session/device tokens in response bodies. Instead, it relies on cookies.

### Cookie Schemas
1. **`__Host-cd_session`**:
   * Opaque session token.
   * Properties: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, `Domain=None`.
   * Lifetime: 24 hours.
2. **`__Host-cd_device`**:
   * Trusted device signature.
   * Properties: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, `Domain=None`.
   * Lifetime: 90 days.

### Client-Side Integration Requirements
Because the cookies are flagged as `HttpOnly`, browser JavaScript cannot read them (`document.cookie` is empty).
* **Credentials Flag**: The frontend must send credentials with every request (e.g. `credentials: 'include'` in Fetch, or `withCredentials: true` in Axios).
* **Storage Guard**: Do not attempt to store session tokens or device keys in `localStorage`, `sessionStorage`, or custom JavaScript memory stores.

---

## 3. Local Development Guidelines

### Secure Origin Restrictions
The `__Host-` cookie prefix enforces a strict security policy where the browser **only** accepts and saves the cookies if the connection is a **Secure Origin**.
* **Localhost Bypass**: Modern browsers (Chrome, Firefox, Safari) treat `http://localhost` as a secure origin. If the React frontend runs on `http://localhost:5173` and requests the backend at `http://localhost:8000`, the cookies **will work** without SSL.
* **IP / Custom Domain Blocking**: If you access the frontend using an IP address (e.g., `http://192.168.1.5:5173`) or a local custom domain (e.g., `http://my-dev-site.local`), the browser **will reject the backend cookies** because the connection is not running over HTTPS.

### Workarounds for IP / Custom Domain Testing
If you need to test the app on mobile devices or custom domains locally, you must run local development over HTTPS:
1. **Using local-ssl-proxy**:
   Run a secure proxy in front of your dev servers:
   ```bash
   npx local-ssl-proxy --source 8001 --target 8000
   ```
   Now make frontend API requests to `https://192.168.1.5:8001`.
2. **Using mkcert**:
   Install local certificates to configure HTTPS directly in your Vite/React config and FastAPI runner.

---

## 4. Endpoint Verification Instructions

You can verify that your connection, routing, and CORS headers are correctly established by checking these endpoints.

### 4.1. Health Check (`GET /api/health`)
Verifies that the backend server is running and connected to MongoDB.
* **Command**:
  ```bash
  curl -i http://localhost:8000/api/health
  ```
* **Expected Headers**:
  ```http
  HTTP/1.1 200 OK
  content-type: application/json
  access-control-allow-origin: http://localhost:5173
  access-control-allow-credentials: true
  ```
* **Expected Response Body**:
  ```json
  {
    "status": "ok",
    "version": "1.0.0"
  }
  ```

### 4.2. Auth Identity Status (`GET /api/auth/me`)
Verifies the current session state and device approval status.
* **Command (Unauthenticated)**:
  ```bash
  curl -i http://localhost:8000/api/auth/me
  ```
* **Expected Response (401 Unauthorized)**:
  ```json
  {
    "error": {
      "code": "AUTHENTICATION_REQUIRED",
      "message": "Please sign in to continue.",
      "request_id": "req-b286c0ab-1ef2-4876-92bb-9be4d3fa54e2"
    }
  }
  ```
* **Command (Authenticated)**:
  Make a request using your frontend client where the browser automatically appends the `__Host-cd_session` cookie.
* **Expected Response (200 OK)**:
  ```json
  {
    "data": {
      "member_id": "MEMBER1",
      "status": "ACTIVE",
      "role": "member",
      "device_approved": true
    },
    "meta": {
      "request_id": "req-9b7e3f2d-8e4c-4b5a-a1b2-c3d4e5f6a7b8"
    }
  }
  ```
  If `device_approved` is `false`, the frontend knows the session is valid but the current device cookie is missing or awaiting admin approval.
