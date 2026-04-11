## ADDED Requirements

### Requirement: CSRF token endpoint
The system SHALL expose a `GET /api/v1/csrf-token` endpoint that generates a cryptographically secure token, sets it as a `SameSite=Strict` cookie named `csrftoken`, and returns it in the JSON response body.

#### Scenario: Token issued on request
- **WHEN** a client sends `GET /api/v1/csrf-token`
- **THEN** the server responds with `{"csrfToken": "<token>"}` and sets `Set-Cookie: csrftoken=<token>; SameSite=Strict; Path=/`

### Requirement: CSRF validation on POST endpoints
The system SHALL validate the `X-CSRF-Token` request header against the `csrftoken` cookie value on all state-changing POST endpoints. Requests where the values are absent or do not match SHALL be rejected with HTTP 403.

#### Scenario: Valid CSRF token accepted
- **WHEN** a POST request includes a matching `X-CSRF-Token` header and `csrftoken` cookie
- **THEN** the server processes the request normally

#### Scenario: Missing CSRF token rejected
- **WHEN** a POST request is missing the `X-CSRF-Token` header or the `csrftoken` cookie
- **THEN** the server responds with HTTP 403 and `{"detail": "CSRF token missing or invalid"}`

#### Scenario: Mismatched CSRF token rejected
- **WHEN** a POST request includes an `X-CSRF-Token` header that does not match the `csrftoken` cookie
- **THEN** the server responds with HTTP 403 and `{"detail": "CSRF token missing or invalid"}`
