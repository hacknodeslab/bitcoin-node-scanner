## ADDED Requirements

### Requirement: Vulnerabilities list endpoint
The system SHALL expose `GET /api/v1/vulnerabilities` returning cached CVE entries for Bitcoin from the database, triggering a fresh NVD fetch if the cache is stale or empty.

#### Scenario: Return cached vulnerabilities
- **WHEN** `GET /api/v1/vulnerabilities` is called with a valid API key and the cache is fresh
- **THEN** the response SHALL return HTTP 200 with JSON: `{"total": <int>, "items": [{"cve_id", "published", "last_modified", "severity", "cvss_score", "description", "affected_versions", "fetched_at"}]}`

#### Scenario: Trigger fetch on empty cache
- **WHEN** `GET /api/v1/vulnerabilities` is called and the cache is empty
- **THEN** the server SHALL synchronously fetch from NVD, populate the cache, and return the results with HTTP 200

#### Scenario: NVD upstream unavailable and cache empty
- **WHEN** the NVD API is unreachable and no cached data exists
- **THEN** the server SHALL return HTTP 503 with `{"detail": "NVD API unavailable and no cached data"}`

#### Scenario: Authentication required
- **WHEN** `GET /api/v1/vulnerabilities` is called without a valid `X-API-Key`
- **THEN** the server SHALL return HTTP 401 Unauthorized
