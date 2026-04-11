## MODIFIED Requirements

### Requirement: Login form submits CSRF token
The login form SHALL fetch a CSRF token from `GET /api/v1/csrf-token` on page load and include it as the `X-CSRF-Token` header in all subsequent POST requests.

#### Scenario: CSRF token fetched on page load
- **WHEN** the page loads
- **THEN** the frontend calls `GET /api/v1/csrf-token` and stores the returned token in memory

#### Scenario: CSRF token included in scan trigger
- **WHEN** the user triggers a scan via the admin panel
- **THEN** the POST request to `/api/v1/scans` includes the `X-CSRF-Token` header with the stored token
