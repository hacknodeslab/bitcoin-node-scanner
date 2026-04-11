## Context

The web interface uses a login form and a scan trigger button that submit POST requests. Currently these endpoints only validate the `X-API-Key` header but have no CSRF protection. A malicious page could forge cross-site requests using the victim's stored session key.

The app is a FastAPI SPA. The frontend stores the API key in `sessionStorage` and sends it as a header. Since `sessionStorage` is not accessible cross-origin, the main attack vector is via form submissions or fetch from a third-party page.

## Goals / Non-Goals

**Goals:**
- Protect all state-changing POST endpoints from CSRF attacks
- Token-based approach compatible with the existing header-based auth
- Minimal friction for the existing SPA flow

**Non-Goals:**
- Full session management (the app is stateless by design)
- SameSite cookie-based auth (would require rearchitecting auth)
- Protecting GET endpoints (they are read-only)

## Decisions

**Double Submit Cookie pattern**
The server sets a CSRF token as a `Set-Cookie` (HttpOnly=False, SameSite=Strict) on page load. The frontend reads it via JavaScript and sends it back as a custom header (`X-CSRF-Token`). The server validates that both values match.

- Chosen over synchronizer token (requires server-side session state)
- Chosen over `SameSite=Strict` cookies alone (the app uses header-based auth, not cookies)

**Token generation**: `secrets.token_hex(32)` — cryptographically secure, sufficient entropy.

**Token lifetime**: Per-session (regenerated on each page load). No expiry needed given the SPA model.

## Risks / Trade-offs

- [Cookie blocked by browser settings] → Acceptable: users with cookies disabled cannot use the login form anyway
- [Token leak via XSS] → Mitigated by existing CSP; CSRF token is not a substitute for XSS protection
- [SameSite=Strict breaks cross-origin embeds] → Non-issue, this tool is not designed to be embedded

## Migration Plan

1. Add `/api/v1/csrf-token` endpoint that sets the cookie and returns the token in the response body
2. Add CSRF validation dependency used by POST endpoints
3. Update frontend to fetch token on load and include it in POST requests
4. No rollback concern — purely additive server-side validation
