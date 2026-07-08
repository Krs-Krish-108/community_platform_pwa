# Playwright E2E Testing Setup & Plan

This document outlines the setup instructions and step-by-step test plan for End-to-End (E2E) browser automation using Playwright. It includes instructions for simulating WebAuthn (passkey) credentials in headless tests.

---

## 1. Installation & Environment Setup

Playwright tests can be run either via Node.js (recommended for frontend-heavy codebases) or Python (integrates directly with our Pytest suite).

### Option A: Node.js (TypeScript) Setup
Initialize Playwright in the frontend directory:
```bash
npm init playwright@latest
```
Choose TypeScript, set the tests folder to `tests/e2e`, and add browsers (Chromium is required for WebAuthn CDP extensions).

### Option B: Python (Pytest) Setup
Install Playwright python bindings in the backend environment:
```bash
pip install pytest-playwright
playwright install chromium
```

---

## 2. Automating WebAuthn with Playwright (Virtual Authenticators)

Since automated tests cannot interact with physical USB keys or OS-level biometrics (Windows Hello/Touch ID), Chromium provides a **Chrome DevTools Protocol (CDP)** API to create virtual authenticators.

### How it Works (JavaScript/TypeScript Example)
```typescript
import { test, expect } from '@playwright/test';

test('WebAuthn Passkey Registration Flow', async ({ page }) => {
  // 1. Establish CDP session with Chromium
  const cdpSession = await page.context().newCDPSession(page);

  // 2. Enable WebAuthn emulation
  await cdpSession.send('WebAuthn.enable');

  // 3. Add a virtual device supporting resident keys and user verification
  const result = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });

  // Now, navigator.credentials.create() and navigator.credentials.get()
  // will succeed automatically using the virtual authenticator!
});
```

---

## 3. E2E Test Plan Details

Each scenario is modeled against target DOM elements. Note that selectors (like `#member-id-input`) are mapped to the standard layout schemas.

### 3.1. Member Enrollment & OTP Verify
1. **Action**: Navigate to `/register`. Input Member ID (`#member-id-input`) and Email (`#email-input`). Click `#submit-identify`.
2. **Assertion**: Verify that a generic success message is displayed on screen.
3. **Action (API-linked)**: Retrieve the latest OTP hash from the database. Enter the OTP code into `#otp-input` and click `#submit-otp`.
4. **Assertion**: Verify that the browser receives an enrollment ticket (`tkt_...`) and transitions to the passkey setup view.

### 3.2. WebAuthn Passkey Enrolment
1. **Action**: Start registration. The virtual authenticator intercept handles the OS request.
2. **Assertion**: Verify that the backend responds with a success status (`ACTIVE`) and sets the `__Host-cd_session` and `__Host-cd_device` cookies.
3. **Assertion**: Verify that the app redirects to `/directory`.

### 3.3. Daily Login Recovery (Device Change or Re-verification)
1. **Action**: Perform enrollment with an existing Member ID.
2. **Assertion**: Verify that the OTP verification response returns a status `PENDING_APPROVAL`.
3. **Action**: Sign in as administrator and approve the device request.
4. **Action**: Re-login on the member browser. The virtual authenticator handles credential assertions.
5. **Assertion**: Verify that the member is successfully logged in.

### 3.4. Directory Access & Privacy Projections
1. **Action**: Search for a member name in the directory search bar `#directory-search`.
2. **Assertion**: Verify that member cards are displayed.
3. **Action**: Click a card to view profile details.
4. **Assertion**: Verify that privacy-protected fields (like phone numbers) are masked/hidden unless the target member configures them as visible.

### 3.5. Inbox Post & Emergency Alert Creation
1. **Action**: Navigate to `#inbox-tab`. Write text in `#post-input` and click `#post-submit`.
2. **Assertion**: Verify that the post appears at the top of the feed `#inbox-feed`.
3. **Action**: Navigate to `#emergency-tab`. Write text in `#emergency-input` and click `#emergency-submit`.
4. **Assertion**: Verify that the alert appears with `#priority-urgent` at the top of the emergency feed.

### 3.6. Admin Moderation
1. **Action**: Sign in as an admin via `/admin/login`. Navigate to the moderation panel.
2. **Action**: Find the created inbox post and click `#remove-post-btn`. Input a moderation reason.
3. **Assertion**: Verify that the post status changes.
4. **Action**: Switch back to the member browser view and refresh the feed.
5. **Assertion**: Verify that the removed post is no longer visible to members.

### 3.7. Logout
1. **Action**: Click `#logout-btn`.
2. **Assertion**: Verify that the browser redirects to `/login` and the session cookie `__Host-cd_session` is cleared.
