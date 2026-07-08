# PHASE 0 — LEGACY FREEZE

**Status: FROZEN — do not extend or deploy this code**

This folder contains the original single-file Community Directory prototype, preserved
as a **UI reference only**.

## What this is

The original `index.html` is a working visual demo. It is NOT suitable for production
because:

| Problem | Risk |
|---|---|
| Fetches `SHEET_ID` Google Sheet CSV directly from the browser | Sheet URL is publicly discoverable |
| Real member names, emails, phone numbers in `FALLBACK` array | PII in frontend source code |
| `makeId(name + timestamp)` — client-generated Member IDs | IDs are reproducible and guessable |
| Member ID typed in composer = author identity | Anyone can post as any visible ID |
| `localStorage` stores Inbox and Emergency messages | Messages are per-device, not shared, not auditable |
| Public Google Form "Add Members" button | Unverified submissions bypass admin approval |
| Public Google Drive thumbnail URLs | Private photos become publicly accessible |
| No authentication, sessions, or device trust | Anyone who opens the URL can access all member data |

## What to take from this UI

- Visual design language (WhatsApp-style green, card layout, bottom-sheet profile)
- Screen inventory: Directory list, Profile sheet, Inbox panel, Emergency panel
- Filter chip behaviour and search UX
- Field layout in profile sheet (about, work, education, family, blood group)

## What NOT to carry forward

- The `SHEET_ID` or `FALLBACK` data array (contains real PII)
- The `FORM_URL` Google Form link in frontend code
- The `makeId()` function or any client-side ID generation
- The composer's `idInput` field — author identity must come from session
- `localStorage` message persistence
- Any direct Google Drive or Google Sheets URL in frontend production code

## Screens to rebuild (Phase 3+)

1. **Login / Enrolment** — new screen (not in prototype)
2. **Directory List** — rebuild from `index.html` visual reference
3. **Profile Sheet** — rebuild with backend privacy projection
4. **Inbox Panel** — rebuild with central database feed
5. **Emergency Panel** — rebuild with central database + admin resolution
6. **Admin Dashboard** — new screen (not in prototype)
7. **Device Enrolment** — new screen (WebAuthn passkey flow)
