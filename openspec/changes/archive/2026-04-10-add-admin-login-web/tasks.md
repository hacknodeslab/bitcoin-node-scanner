## 1. API — Make Read Endpoints Public

- [x] 1.1 Remove `dependencies=[Depends(require_api_key)]` from `GET /api/v1/nodes`, `GET /api/v1/nodes/countries`, and `GET /api/v1/nodes/{id}/geo` in `src/web/routers/nodes.py`
- [x] 1.2 Remove `dependencies=[Depends(require_api_key)]` from `GET /api/v1/stats` in `src/web/routers/stats.py`
- [x] 1.3 Keep `require_api_key` on `POST /api/v1/scans` and `GET /api/v1/scans/{job_id}` in `src/web/routers/scans.py` (no change needed there)

## 2. Frontend — Remove API Key Prompt

- [x] 2.1 Remove the `const API_KEY = prompt("Enter API key:") || ""` line from `index.html`
- [x] 2.2 Change `const headers = { "X-API-Key": API_KEY }` to read from `sessionStorage` at call time: use an empty object `{}` for read requests and `{ "X-API-Key": adminKey }` for write requests

## 3. Frontend — Admin Session (sessionStorage)

- [x] 3.1 On page load, check `sessionStorage.getItem("adminKey")` — if present, enter admin mode (show scan button, show logout)
- [x] 3.2 Login form submit: store the entered password in `sessionStorage` as `adminKey`, then make a test request (`GET /api/v1/scans/ping` returning 404 is fine — a 401 means wrong key); on 401 clear sessionStorage and show error; on any other response enter admin mode

## 4. Frontend — Login Form UI

- [x] 4.1 Add a login form to the header with username (display only) and password fields, and a "Login" button; hidden when admin is logged in
- [x] 4.2 Add an "Admin ▾" label and "Logout" button to the header; hidden when not logged in
- [x] 4.3 Add CSS for the login form and logout button to match the existing dark theme

## 5. Frontend — Conditional Scan Button

- [x] 5.1 Move the "Start Scan" button and scan status span inside a `<div id="scan-controls">` that is hidden by default (`display:none`)
- [x] 5.2 Show `scan-controls` when admin logs in; hide it when admin logs out

## 6. Tests

- [x] 6.1 Update `tests/test_web_api.py`: read endpoints (`GET /nodes`, `GET /stats`, `GET /nodes/countries`) should return 200 without `X-API-Key` header
- [x] 6.2 Verify scan endpoints still return 401 without API key (existing tests already cover this — confirm they still pass)
