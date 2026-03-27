## Why

The current dashboard prompts for an API key via a browser `prompt()` on every page load, which is poor UX and blocks access to read-only data for users without the key. The goal is to allow anyone to browse node data without authentication, while restricting destructive/operational actions (Start Scan) to an authenticated admin.

## What Changes

- **BREAKING**: Remove the `prompt("Enter API key:")` popup — the dashboard no longer requires a key to load
- Add a login form (username + password) that grants admin status when submitted successfully
- Admin session stored in `sessionStorage` so it survives page refresh but not tab close
- "Start Scan" button hidden from unauthenticated visitors; visible only when logged in as admin
- Add a login/logout button in the header
- All read-only endpoints (`/api/v1/nodes`, `/api/v1/stats`, `/api/v1/nodes/countries`) accessible without `X-API-Key` from the browser
- Scan trigger endpoint (`POST /api/v1/scans`) remains protected by API key — the frontend sends it only when admin is logged in

## Capabilities

### New Capabilities
- `web-admin-session`: Browser-side admin session management (login form, sessionStorage token, logout)

### Modified Capabilities
- `web-dashboard`: Dashboard is now publicly readable; "Start Scan" button is conditionally shown based on admin session state
- `web-api`: `/api/v1/nodes`, `/api/v1/stats`, `/api/v1/nodes/countries` no longer require `X-API-Key` (public read); `POST /api/v1/scans` and `GET /api/v1/scans/{id}` remain protected

## Impact

- `src/web/auth.py`: Split into `require_api_key` (write operations) and optional auth for read endpoints
- `src/web/routers/nodes.py`, `stats.py`: Remove `require_api_key` dependency from GET endpoints
- `src/web/routers/scans.py`: Keep `require_api_key` on POST and GET by job_id
- `src/web/static/index.html`: Remove `prompt()`, add login form UI, conditional scan button visibility, sessionStorage-based session
- No new backend dependencies; no schema changes
