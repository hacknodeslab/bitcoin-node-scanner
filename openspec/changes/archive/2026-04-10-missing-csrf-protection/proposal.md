## Why

The login form and scan trigger form lack CSRF protection, making them vulnerable to cross-site request forgery attacks where a malicious site could trigger authenticated actions on behalf of a logged-in user.

## What Changes

- Introduce a CSRF token mechanism for state-changing requests (POST)
- Generate and validate CSRF tokens server-side on the FastAPI backend
- Include the token in the login form and scan trigger form on the frontend
- Reject requests missing or containing an invalid CSRF token

## Capabilities

### New Capabilities

- `csrf-protection`: Server-side CSRF token generation and validation for POST endpoints

### Modified Capabilities

- `admin-login-web`: Login form now requires and submits a CSRF token with each request

## Impact

- `src/web/main.py`: Add session middleware and CSRF token endpoint
- `src/web/auth.py`: Add CSRF validation dependency
- `src/web/routers/scans.py`: Protect POST /scans with CSRF validation
- `src/web/static/index.html`: Fetch and include CSRF token in form submissions
