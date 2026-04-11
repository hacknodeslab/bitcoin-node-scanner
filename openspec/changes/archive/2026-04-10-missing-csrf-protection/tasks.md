## 1. Backend — CSRF token endpoint

- [x] 1.1 Add `GET /api/v1/csrf-token` endpoint in a new `src/web/routers/csrf.py` that generates a token with `secrets.token_hex(32)`, sets it as a `SameSite=Strict` cookie, and returns it in the response body
- [x] 1.2 Register the csrf router in `src/web/main.py`

## 2. Backend — CSRF validation dependency

- [x] 2.1 Add `require_csrf_token` dependency in `src/web/auth.py` that reads the `csrftoken` cookie and `X-CSRF-Token` header, compares them with `secrets.compare_digest`, and raises HTTP 403 on mismatch or absence
- [x] 2.2 Apply `require_csrf_token` as a dependency on `POST /api/v1/scans` in `src/web/routers/scans.py`

## 3. Frontend — fetch and send CSRF token

- [x] 3.1 In `src/web/static/index.html`, add a `fetchCsrfToken()` function that calls `GET /api/v1/csrf-token` on page load and stores the token in a module-level variable
- [x] 3.2 Update `triggerScan()` (and any other POST fetch calls) to include the `X-CSRF-Token` header using the stored token
