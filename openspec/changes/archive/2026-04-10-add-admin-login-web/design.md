## Context

Currently all API endpoints require `X-API-Key` and the dashboard does `prompt("Enter API key:")` on load. This completely blocks access for anyone without the key — even to read-only data. The owner wants the dashboard to be publicly readable while keeping scan triggering admin-only.

The existing `WEB_API_KEY` env var is already the shared secret. We reuse it as the admin password to avoid adding new config. There is only one admin user.

## Goals / Non-Goals

**Goals:**
- Public read-only access to nodes, stats, countries — no credentials required
- Admin login via a username/password form; on success the API key is stored in `sessionStorage` and sent on write requests
- "Start Scan" button visible only when admin is logged in
- Login/logout control in the header
- Keep `POST /api/v1/scans` protected server-side (API key required)

**Non-Goals:**
- Multi-user accounts or roles
- Persistent login across browser sessions (sessionStorage expires on tab close — intentional)
- Rate-limiting or brute-force protection on login
- HTTPS enforcement (out of scope — handled by reverse proxy)

## Decisions

**D1 — Admin credentials validated client-side against the API key**
The login form sends username + password to the frontend only; the frontend compares the password against the known API key by making a test request (`GET /api/v1/scans/ping` or simply trying `POST /api/v1/scans` with a dummy dry-run). Alternative: add a dedicated `POST /api/v1/auth/login` endpoint. Rejected for now — adds server complexity for a single-user case.

Actually, simpler: the login form stores the entered password as the API key in `sessionStorage`. The first authenticated request will 401 if wrong — the frontend handles this by showing "Invalid credentials" and clearing the session. No dedicated login endpoint needed.

**D2 — sessionStorage, not localStorage**
`sessionStorage` is tab-scoped and clears on tab close. Suitable for an admin tool. `localStorage` would persist indefinitely, which is less appropriate for a credential.

**D3 — Read endpoints made public at the FastAPI level**
Remove `Depends(require_api_key)` from `GET /nodes`, `GET /stats`, `GET /nodes/countries`. The security boundary is: anyone can read, only key-holders can write. This is a deliberate design choice — the data is already public (sourced from Shodan).

**D4 — Login form inline in the header, not a separate page**
Keeps the single-file dashboard architecture. A modal/inline form in the header is sufficient for a single admin.

**D5 — Username field is cosmetic (always "admin")**
The actual credential is the password (= WEB_API_KEY). The username field improves perceived security UX but is not validated server-side.

## Risks / Trade-offs

- [Risk] API key exposed in sessionStorage is readable by JS on the same origin → Acceptable; same-origin JS already has full access to the page
- [Risk] Making read endpoints public means anyone with the URL can see node data → By design; data is sourced from Shodan and not sensitive
- [Trade-off] No brute-force protection → Low risk for an internal tool; add rate limiting later if needed

## Migration Plan

1. Deploy updated `nodes.py`, `stats.py`, `scans.py` (read endpoints become public)
2. Deploy updated `index.html` (remove prompt, add login form)
3. Existing API key clients sending `X-API-Key` on read endpoints will still work (the header is simply ignored)
4. Rollback: revert both files; read endpoints require key again and popup returns

## Open Questions

None.
