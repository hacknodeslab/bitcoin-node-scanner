## ADDED Requirements

### Requirement: API server starts and serves requests
The system SHALL provide a FastAPI HTTP server runnable via `uvicorn src.web.main:app` that listens on a configurable host and port.

#### Scenario: Server starts with valid configuration
- **WHEN** `WEB_API_KEY` environment variable is set and the server is started
- **THEN** the server SHALL bind to the configured host/port and respond to HTTP requests

#### Scenario: Server refuses to start without API key
- **WHEN** `WEB_API_KEY` environment variable is not set
- **THEN** the server SHALL raise a configuration error and exit with a non-zero status code

### Requirement: API key authentication on all endpoints
The system SHALL require a valid `X-API-Key` header on all non-documentation endpoints.

#### Scenario: Request with valid API key is accepted
- **WHEN** a request includes `X-API-Key: <correct-key>` header
- **THEN** the server SHALL process the request and return the expected response

#### Scenario: Request with missing or invalid API key is rejected
- **WHEN** a request is made without `X-API-Key` or with an incorrect key
- **THEN** the server SHALL return HTTP 401 Unauthorized

### Requirement: Node list endpoint
The system SHALL expose `GET /api/v1/nodes` returning a paginated list of scanned nodes from the database.

#### Scenario: List nodes with default pagination
- **WHEN** `GET /api/v1/nodes` is called with a valid API key
- **THEN** the response SHALL return up to 100 nodes as JSON with fields: `ip`, `port`, `version`, `risk_level`, `country`, `last_seen`

#### Scenario: Filter nodes by risk level
- **WHEN** `GET /api/v1/nodes?risk_level=CRITICAL` is called
- **THEN** the response SHALL return only nodes with `risk_level == "CRITICAL"`

### Requirement: Statistics endpoint
The system SHALL expose `GET /api/v1/stats` returning aggregate scan statistics.

#### Scenario: Stats returns summary counts
- **WHEN** `GET /api/v1/stats` is called with a valid API key
- **THEN** the response SHALL return JSON with: `total_nodes`, `by_risk_level` (object), `by_country` (top 10), `vulnerable_versions_count`, `last_scan_at`

### Requirement: Trigger scan endpoint
The system SHALL expose `POST /api/v1/scans` to initiate a new background scan.

#### Scenario: Scan triggered successfully
- **WHEN** `POST /api/v1/scans` is called and no other scan is running
- **THEN** the server SHALL create a scan job record and return HTTP 202 Accepted with `{"job_id": "<uuid>", "status": "pending"}`

#### Scenario: Concurrent scan is rejected
- **WHEN** `POST /api/v1/scans` is called while a scan is already running
- **THEN** the server SHALL return HTTP 409 Conflict with an explanatory message

### Requirement: Scan job status endpoint
The system SHALL expose `GET /api/v1/scans/{job_id}` to retrieve scan job status.

#### Scenario: Get status of existing job
- **WHEN** `GET /api/v1/scans/{job_id}` is called with a valid job ID
- **THEN** the response SHALL return JSON with: `job_id`, `status` (pending/running/completed/failed), `started_at`, `finished_at`, `result_summary`

#### Scenario: Get status of non-existent job
- **WHEN** `GET /api/v1/scans/{job_id}` is called with an unknown job ID
- **THEN** the server SHALL return HTTP 404 Not Found

### Requirement: sort_by and sort_dir params on node list
`GET /api/v1/nodes` SHALL accept optional `sort_by` (string) and `sort_dir` (`asc`|`desc`) query parameters. Allowed `sort_by` values: `ip`, `port`, `version`, `risk_level`, `country_name`, `geo_country_name`, `last_seen`. Default: `sort_by=last_seen`, `sort_dir=desc`.

#### Scenario: Default sort preserved when params absent
- **WHEN** `sort_by` and `sort_dir` are not provided
- **THEN** results are ordered by `last_seen DESC` (existing behavior unchanged)

#### Scenario: Custom sort applied when params present
- **WHEN** `?sort_by=risk_level&sort_dir=asc` is provided
- **THEN** results are ordered by `risk_level ASC`

### Requirement: country param on node list
`GET /api/v1/nodes` SHALL accept an optional `country` query parameter. When present, results SHALL be filtered to nodes where `country_name` matches (case-insensitive).

#### Scenario: country param filters results
- **WHEN** `?country=France` is provided
- **THEN** only nodes with `country_name = 'France'` (case-insensitive) are returned

### Requirement: GET /api/v1/nodes/countries endpoint
A new endpoint `GET /api/v1/nodes/countries` SHALL return a JSON array of distinct non-null `country_name` strings, sorted alphabetically, limited to 100 entries.

#### Scenario: Returns alphabetical country list
- **WHEN** request is made with valid API key
- **THEN** response is 200 with a JSON array of strings, alphabetically sorted

#### Scenario: Requires API key
- **WHEN** no `X-API-Key` header is provided
- **THEN** response is 401
